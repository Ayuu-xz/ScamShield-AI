"""Real-world dataset ingestion, cleaning, domain-diversity audit, and leakage-free splitting."""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import zipfile
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit

import duckdb
import httpx
import tldextract
from sklearn.model_selection import StratifiedGroupKFold, train_test_split

BACKEND_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BACKEND_DIR / "data"
RAW_DIR = DATA_DIR / "raw"
PROCESSED_DIR = DATA_DIR / "processed"

UCI_SMS_URL = "https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip"
MENDELEY_LEGITPHISH_API = "https://data.mendeley.com/public-api/datasets/hx4m73v2sf"
MENDELEY_10191_API = "https://data.mendeley.com/public-api/datasets/vmg875v4xs"
MENDELEY_5971_API = "https://data.mendeley.com/public-api/datasets/f45bkkt8pr"
PHISHTANK_CSV_URL = "https://data.phishtank.com/data/online-valid.csv"
URLHAUS_RECENT_URL = "https://urlhaus.abuse.ch/downloads/csv_recent/"

RANDOM_SEED = 42
DATASET_VERSION = "3.0.0"

# Offline Public Suffix List extractor (zero network calls)
_TLD_EXTRACT = tldextract.TLDExtract(suffix_list_urls=())

URL_LABEL_MAP: dict[str, str] = {
    "0": "Phishing",
    "phish": "Phishing",
    "phishing": "Phishing",
    "malicious": "Phishing",
    "bad": "Phishing",
    "-1": "Phishing",
    "1": "Legitimate",
    "benign": "Legitimate",
    "legitimate": "Legitimate",
    "good": "Legitimate",
}

MESSAGE_LABEL_MAP: dict[str, str] = {
    "ham": "Legitimate",
    "legitimate": "Legitimate",
    "spam": "Spam",
    "smishing": "Phishing",
    "phishing": "Phishing",
    "scam": "Scam",
}

_URL_IN_TEXT_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"'{}\\|^`\[\]]+", re.IGNORECASE)
_NUM_RE = re.compile(r"\b\d+(?:[.,]\d+)?\b")


class SchemaValidationError(ValueError):
    """Raised when an input dataset file is missing required columns or format."""


@dataclass
class CleaningStats:
    source_rows: int
    dropped_missing: int
    dropped_invalid_label: int
    exact_duplicates_removed: int
    normalized_duplicates_removed: int
    conflicting_label_groups: int
    conflicting_rows_removed: int
    cleaned_rows: int
    class_distribution_before: dict[str, int]
    class_distribution_after: dict[str, int]


def extract_registrable_domain(raw_url: str) -> str:
    """Extract registrable domain (eTLD+1) offline using tldextract."""
    candidate = raw_url.strip() if "://" in raw_url else f"http://{raw_url.strip()}"
    try:
        host = (urlsplit(candidate).hostname or "").lower()
    except ValueError:
        host = ""
    if not host:
        return raw_url.strip().lower()[:64]
    ext = _TLD_EXTRACT(host)
    return ext.top_domain_under_public_suffix or host


def _normalize_url_key(raw_url: str) -> str:
    cleaned = " ".join(raw_url.strip().split())
    candidate = cleaned if "://" in cleaned else f"http://{cleaned}"
    try:
        parts = urlsplit(candidate)
        scheme = parts.scheme.lower()
        host = (parts.hostname or "").lower()
        path = parts.path.rstrip("/")
        query = parts.query
        return f"{scheme}://{host}{path}?{query}" if query else f"{scheme}://{host}{path}"
    except ValueError:
        return cleaned.lower()


def _normalize_message_key(raw_text: str) -> str:
    return " ".join(raw_text.strip().lower().split())


def _message_leakage_group(raw_text: str) -> str:
    norm = _normalize_message_key(raw_text)
    norm = _URL_IN_TEXT_RE.sub("__url__", norm)
    norm = _NUM_RE.sub("__num__", norm)
    return hashlib.sha1(norm.encode("utf-8")).hexdigest()[:16]


def clean_records(
    rows: Iterable[tuple[str, str]],
    *,
    label_map: dict[str, str],
    is_url: bool,
) -> tuple[list[tuple[str, str, str]], CleaningStats]:
    """Validate, normalize, deduplicate, and remove conflicting labels."""
    source_rows = 0
    dropped_missing = 0
    dropped_invalid_label = 0
    before_dist: Counter[str] = Counter()

    exact_seen: set[tuple[str, str]] = set()
    exact_dups = 0
    norm_groups: dict[str, list[tuple[str, str]]] = {}

    for raw_text, raw_label in rows:
        source_rows += 1
        text = " ".join(str(raw_text or "").split())
        if not text:
            dropped_missing += 1
            continue

        mapped = label_map.get(str(raw_label or "").strip().lower())
        if mapped is None:
            dropped_invalid_label += 1
            continue

        before_dist[mapped] += 1

        if (text, mapped) in exact_seen:
            exact_dups += 1
            continue
        exact_seen.add((text, mapped))

        norm_key = _normalize_url_key(text) if is_url else _normalize_message_key(text)
        norm_groups.setdefault(norm_key, []).append((text, mapped))

    cleaned: list[tuple[str, str, str]] = []
    norm_dups = 0
    conflict_groups = 0
    conflict_rows = 0
    after_dist: Counter[str] = Counter()

    for _norm_key, items in norm_groups.items():
        labels_in_group = {lbl for _, lbl in items}
        if len(labels_in_group) > 1:
            conflict_groups += 1
            conflict_rows += len(items)
            continue

        canonical_text, canonical_label = items[0]
        norm_dups += len(items) - 1
        group_id = (
            extract_registrable_domain(canonical_text)
            if is_url
            else _message_leakage_group(canonical_text)
        )
        cleaned.append((canonical_text, canonical_label, group_id))
        after_dist[canonical_label] += 1

    stats = CleaningStats(
        source_rows=source_rows,
        dropped_missing=dropped_missing,
        dropped_invalid_label=dropped_invalid_label,
        exact_duplicates_removed=exact_dups,
        normalized_duplicates_removed=norm_dups,
        conflicting_label_groups=conflict_groups,
        conflicting_rows_removed=conflict_rows,
        cleaned_rows=len(cleaned),
        class_distribution_before=dict(sorted(before_dist.items())),
        class_distribution_after=dict(sorted(after_dist.items())),
    )
    return cleaned, stats


def clean_sourced_records(
    rows: Iterable[tuple[str, str, str]],
    *,
    label_map: dict[str, str],
    is_url: bool,
) -> tuple[list[tuple[str, str, str, str]], CleaningStats]:
    """Clean (text, label, source) rows preserving first-seen provenance."""
    source_rows = 0
    dropped_missing = 0
    dropped_invalid_label = 0
    before_dist: Counter[str] = Counter()
    exact_seen: set[tuple[str, str]] = set()
    exact_dups = 0
    norm_groups: dict[str, list[tuple[str, str, str]]] = {}

    for raw_text, raw_label, src in rows:
        source_rows += 1
        text = " ".join(str(raw_text or "").split())
        if not text:
            dropped_missing += 1
            continue
        mapped = label_map.get(str(raw_label or "").strip().lower())
        if mapped is None:
            dropped_invalid_label += 1
            continue
        before_dist[mapped] += 1
        if (text, mapped) in exact_seen:
            exact_dups += 1
            continue
        exact_seen.add((text, mapped))
        norm_key = _normalize_url_key(text) if is_url else _normalize_message_key(text)
        norm_groups.setdefault(norm_key, []).append((text, mapped, src))

    cleaned: list[tuple[str, str, str, str]] = []
    norm_dups = 0
    conflict_groups = 0
    conflict_rows = 0
    after_dist: Counter[str] = Counter()

    for _norm_key, items in norm_groups.items():
        if len({lbl for _, lbl, _ in items}) > 1:
            conflict_groups += 1
            conflict_rows += len(items)
            continue
        canonical_text, canonical_label, canonical_src = items[0]
        norm_dups += len(items) - 1
        group_id = (
            extract_registrable_domain(canonical_text)
            if is_url
            else _message_leakage_group(canonical_text)
        )
        cleaned.append((canonical_text, canonical_label, group_id, canonical_src))
        after_dist[canonical_label] += 1

    stats = CleaningStats(
        source_rows=source_rows,
        dropped_missing=dropped_missing,
        dropped_invalid_label=dropped_invalid_label,
        exact_duplicates_removed=exact_dups,
        normalized_duplicates_removed=norm_dups,
        conflicting_label_groups=conflict_groups,
        conflicting_rows_removed=conflict_rows,
        cleaned_rows=len(cleaned),
        class_distribution_before=dict(sorted(before_dist.items())),
        class_distribution_after=dict(sorted(after_dist.items())),
    )
    return cleaned, stats


def stratified_grouped_split(
    records: list[tuple[str, str, str]],
    *,
    random_seed: int = RANDOM_SEED,
) -> tuple[list[tuple[str, str]], list[tuple[str, str]], list[tuple[str, str]]]:
    """Split (text, label, group) into leakage-free ~70/15/15 train/val/test sets."""
    texts = [r[0] for r in records]
    labels = [r[1] for r in records]
    groups = [r[2] for r in records]

    if len(set(groups)) >= 10:
        sgkf = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=random_seed)
        train_idx, holdout_idx = next(sgkf.split(texts, labels, groups))
        train = [(texts[i], labels[i]) for i in train_idx]

        h_texts = [texts[i] for i in holdout_idx]
        h_labels = [labels[i] for i in holdout_idx]
        h_groups = [groups[i] for i in holdout_idx]
        if len(set(h_groups)) >= 4:
            sgkf2 = StratifiedGroupKFold(n_splits=2, shuffle=True, random_state=random_seed)
            val_sub, test_sub = next(sgkf2.split(h_texts, h_labels, h_groups))
            val = [(h_texts[i], h_labels[i]) for i in val_sub]
            test = [(h_texts[i], h_labels[i]) for i in test_sub]
            return train, val, test

    X_train, X_temp, y_train, y_temp = train_test_split(
        texts, labels, test_size=0.30, random_state=random_seed, stratify=labels
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, random_state=random_seed, stratify=y_temp
    )
    return list(zip(X_train, y_train)), list(zip(X_val, y_val)), list(zip(X_test, y_test))


def _stratified_grouped_split_sourced(
    records: list[tuple[str, str, str, str]],
    *,
    random_seed: int = RANDOM_SEED,
) -> tuple[
    list[tuple[str, str, str]],
    list[tuple[str, str, str]],
    list[tuple[str, str, str]],
]:
    """Split (text, label, group, source) preserving source provenance."""
    texts = [r[0] for r in records]
    labels = [r[1] for r in records]
    groups = [r[2] for r in records]
    sources = [r[3] for r in records]

    sgkf = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=random_seed)
    train_idx, holdout_idx = next(sgkf.split(texts, labels, groups))
    train = [(texts[i], labels[i], sources[i]) for i in train_idx]

    h_texts = [texts[i] for i in holdout_idx]
    h_labels = [labels[i] for i in holdout_idx]
    h_groups = [groups[i] for i in holdout_idx]
    h_sources = [sources[i] for i in holdout_idx]
    sgkf2 = StratifiedGroupKFold(n_splits=2, shuffle=True, random_state=random_seed)
    val_sub, test_sub = next(sgkf2.split(h_texts, h_labels, h_groups))
    val = [(h_texts[i], h_labels[i], h_sources[i]) for i in val_sub]
    test = [(h_texts[i], h_labels[i], h_sources[i]) for i in test_sub]
    return train, val, test


def ensure_phreshphish_csvs() -> tuple[Path, Path]:
    """Stream (url, label, date, lang) columns from PhreshPhish Parquet shards via DuckDB."""
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    train_csv = RAW_DIR / "phreshphish_train.csv"
    test_csv = RAW_DIR / "phreshphish_test.csv"
    if train_csv.exists() and test_csv.exists():
        return train_csv, test_csv

    con = duckdb.connect()
    con.execute("INSTALL httpfs; LOAD httpfs;")
    if not train_csv.exists():
        train_urls = [
            f"https://huggingface.co/datasets/phreshphish/phreshphish/resolve/refs%2Fconvert%2Fparquet/default/train/{i:04d}.parquet"
            for i in range(20)
        ]
        con.execute(
            "COPY (SELECT url, label, CAST(date AS VARCHAR) AS date, lang FROM read_parquet(?)) TO ? (HEADER, DELIMITER ',')",
            [train_urls, str(train_csv)],
        )
    if not test_csv.exists():
        test_urls = [
            f"https://huggingface.co/datasets/phreshphish/phreshphish/resolve/refs%2Fconvert%2Fparquet/default/test/{i:04d}.parquet"
            for i in range(10)
        ]
        con.execute(
            "COPY (SELECT url, label, CAST(date AS VARCHAR) AS date, lang FROM read_parquet(?)) TO ? (HEADER, DELIMITER ',')",
            [test_urls, str(test_csv)],
        )
    return train_csv, test_csv


def _compute_domain_diversity(records: list[tuple[str, str, str, str]]) -> dict:
    """Compute registrable domain, TLD, path, and query-string diversity metrics."""
    dom_counter: Counter[str] = Counter()
    legit_dom_counter: Counter[str] = Counter()
    tld_counter: Counter[str] = Counter()
    with_query = 0
    with_deep_path = 0

    for url, lbl, dom, _src in records:
        dom_counter[dom] += 1
        if lbl == "Legitimate":
            legit_dom_counter[dom] += 1
        ext = _TLD_EXTRACT(dom)
        tld = ext.suffix or "unknown"
        tld_counter[tld] += 1
        try:
            parts = urlsplit(url if "://" in url else f"http://{url}")
            if parts.query:
                with_query += 1
            if parts.path and parts.path.count("/") >= 2:
                with_deep_path += 1
        except ValueError:
            pass

    total = max(1, len(records))
    legit_total = max(1, sum(legit_dom_counter.values()))
    wiki_so = legit_dom_counter.get("wikipedia.org", 0) + legit_dom_counter.get("stackoverflow.com", 0)
    return {
        "total_urls": len(records),
        "unique_registrable_domains": len(dom_counter),
        "unique_legitimate_domains": len(legit_dom_counter),
        "unique_tlds": len(tld_counter),
        "urls_with_query_strings": with_query,
        "urls_with_multi_segment_paths": with_deep_path,
        "wikipedia_stackoverflow_share_of_legitimate": round(wiki_so / legit_total, 4),
        "top_15_legitimate_domains": legit_dom_counter.most_common(15),
        "top_15_tlds": tld_counter.most_common(15),
    }


def _load_csv_column_pairs(path: Path, text_col: str, label_col: str, source_name: str):
    with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        fields = set(reader.fieldnames or [])
        if text_col not in fields or label_col not in fields:
            raise SchemaValidationError(f"{path.name} missing {text_col} or {label_col}")
        for row in reader:
            yield row.get(text_col, ""), row.get(label_col, ""), source_name


def _build_synthetic_defensive_urls() -> list[tuple[str, str]]:
    legit_domains = [
        "example.com", "docs.python.org", "developer.mozilla.org", "github.com",
        "en.wikipedia.org", "stackoverflow.com", "react.dev", "fastapi.tiangolo.com",
    ]
    legit_paths = ["", "/about", "/docs", "/search?q=python", "/help?utm_source=newsletter"]
    phish_brands = ["paypa1", "micros0ft", "g00gle", "app1e", "amaz0n"]
    phish_tlds = ["com", "xyz", "tk", "top"]
    phish_paths = ["/login/verify", "/kyc-update", "/download/invoice.exe"]
    rows: list[tuple[str, str]] = []
    for d in legit_domains:
        for p in legit_paths:
            rows.append((f"https://{d}{p}", "Legitimate"))
    for b in phish_brands:
        for t in phish_tlds:
            for p in phish_paths:
                rows.append((f"http://{b}-secure-login.{t}{p}", "Phishing"))
    return rows


def _build_synthetic_hinglish_scam_messages() -> list[tuple[str, str]]:
    return [
        ("Aapka Bank khata band ho jayega, turant KYC update kare: http://bit.ly/verify-now", "Phishing"),
        ("Aapne lottery mein Rs 50,000 jeete hai! Claim karne ke liye Rs 499 processing fee bheje.", "Scam"),
        ("Ghar baithe kamaye $5,000 daily! Registration fee $25 bhej kar apna slot book kare.", "Scam"),
        ("Congratulations! You won a cash prize of $10,000. Pay registration fee $25 to claim.", "Scam"),
        ("Work from home and earn $5,000 per day! Pay $15 joining fee to start today.", "Scam"),
        ("Urgent: share your OTP to receive cashback of Rs 50,000 in your account.", "Scam"),
        ("Kal subah 9 baje meeting hai, time pe aa jana.", "Legitimate"),
        ("Hi team, our weekly standup is moved to 3 PM in Room B.", "Legitimate"),
    ]


def _write_csv(path: Path, header: list[str], rows: Iterable[tuple]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(rows)


def prepare_all_datasets() -> dict:
    """Acquire, clean, deduplicate, split by registrable domain/template, and write reports."""
    phresh_train_csv, phresh_test_csv = ensure_phreshphish_csvs()

    # 1. URLs: LegitPhish + PhreshPhish (train) + PhishTank (verified=yes)
    lp_rows = list(_load_csv_column_pairs(RAW_DIR / "legitphish_urls.csv", "URL", "ClassLabel", "legitphish"))
    pp_train_rows = list(_load_csv_column_pairs(phresh_train_csv, "url", "label", "phreshphish_train"))
    pt_rows = []
    with (RAW_DIR / "phishtank_online_valid.csv").open("r", encoding="utf-8", errors="replace", newline="") as f:
        for row in csv.DictReader(f):
            if str(row.get("verified", "")).strip().lower() == "yes":
                pt_rows.append((row.get("url", ""), "phishing", "phishtank"))

    url_cleaned, url_stats = clean_sourced_records(
        lp_rows + pp_train_rows + pt_rows,
        label_map=URL_LABEL_MAP,
        is_url=True,
    )
    url_train, url_val, url_test = _stratified_grouped_split_sourced(url_cleaned)

    train_val_domains = {
        extract_registrable_domain(u) for u, _, _ in url_train + url_val
    }

    # Time-separated PhreshPhish test set filtered to strictly unseen registrable domains
    pp_test_raw = list(_load_csv_column_pairs(phresh_test_csv, "url", "label", "phreshphish_test"))
    pp_test_cleaned, pp_test_stats = clean_sourced_records(
        pp_test_raw, label_map=URL_LABEL_MAP, is_url=True
    )
    pp_test_unseen = [
        (u, lbl, src)
        for u, lbl, dom, src in pp_test_cleaned
        if dom not in train_val_domains
    ]

    url_out = PROCESSED_DIR / "urls"
    _write_csv(url_out / "train.csv", ["url", "label", "source"], url_train)
    _write_csv(url_out / "val.csv", ["url", "label", "source"], url_val)
    _write_csv(url_out / "test.csv", ["url", "label", "source"], url_test)
    _write_csv(url_out / "test_phreshphish_unseen.csv", ["url", "label", "source"], pp_test_unseen)

    syn_url_cleaned, _ = clean_records(_build_synthetic_defensive_urls(), label_map=URL_LABEL_MAP, is_url=True)
    _write_csv(url_out / "benchmark_synthetic.csv", ["url", "label"], [(u, l) for u, l, _ in syn_url_cleaned])

    # Domain diversity before (LegitPhish only) vs after (Combined URLs)
    lp_only_cleaned, _ = clean_sourced_records(lp_rows, label_map=URL_LABEL_MAP, is_url=True)
    domain_diversity_report = {
        "before_legitphish_only": _compute_domain_diversity(lp_only_cleaned),
        "after_combined_real_world": _compute_domain_diversity(url_cleaned),
    }

    # 2. Messages: Real-world UCI SMS + Mendeley 10191 + Mishra & Soni 5971
    uci_rows = []
    for line in (RAW_DIR / "SMSSpamCollection").read_text(encoding="utf-8", errors="replace").splitlines():
        if "\t" in line:
            lbl, txt = line.split("\t", 1)
            uci_rows.append((txt, lbl, "uci_sms"))
    m10191_rows = list(_load_csv_column_pairs(RAW_DIR / "mendeley_10191.csv", "TEXT", "LABEL", "mendeley_10191"))
    m5971_rows = list(_load_csv_column_pairs(RAW_DIR / "mendeley_5971.csv", "TEXT", "LABEL", "mendeley_5971"))

    msg_cleaned, msg_stats = clean_sourced_records(
        uci_rows + m10191_rows + m5971_rows,
        label_map=MESSAGE_LABEL_MAP,
        is_url=False,
    )
    msg_train, msg_val, msg_test = _stratified_grouped_split_sourced(msg_cleaned)

    # Keep synthetic Hinglish/Scam strictly separate from real-world test!
    syn_msg = _build_synthetic_hinglish_scam_messages()
    msg_out = PROCESSED_DIR / "messages"
    _write_csv(msg_out / "train.csv", ["text", "label", "source"], msg_train)
    _write_csv(msg_out / "val.csv", ["text", "label", "source"], msg_val)
    _write_csv(msg_out / "test.csv", ["text", "label", "source"], msg_test)
    _write_csv(
        msg_out / "benchmark_synthetic_hinglish.csv",
        ["text", "label", "source"],
        [(t, l, "synthetic_hinglish_scam") for t, l in syn_msg],
    )

    quality_report = {
        "dataset_version": DATASET_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "url_quality": url_stats.__dict__,
        "phreshphish_time_holdout_quality": pp_test_stats.__dict__,
        "message_quality": msg_stats.__dict__,
    }

    label_distribution_report = {
        "url_splits": {
            "train": dict(Counter(l for _, l, _ in url_train)),
            "val": dict(Counter(l for _, l, _ in url_val)),
            "test_unseen_domains": dict(Counter(l for _, l, _ in url_test)),
            "test_phreshphish_time_unseen": dict(Counter(l for _, l, _ in pp_test_unseen)),
        },
        "message_splits_real_world_only": {
            "train": dict(Counter(l for _, l, _ in msg_train)),
            "val": dict(Counter(l for _, l, _ in msg_val)),
            "test": dict(Counter(l for _, l, _ in msg_test)),
        },
    }

    manifest = {
        "dataset_version": DATASET_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "random_seed": RANDOM_SEED,
        "url_sources": [
            {"name": "LegitPhish", "url": "https://data.mendeley.com/datasets/hx4m73v2sf/2", "license": "CC BY 4.0", "status": "integrated"},
            {"name": "PhreshPhish (train 20 shards + test 10 shards)", "url": "https://huggingface.co/datasets/phreshphish/phreshphish", "license": "CC BY 4.0", "status": "integrated"},
            {"name": "PhishTank online-valid", "url": "https://phishtank.org/", "license": "PhishTank Terms (verified=yes)", "status": "integrated"},
            {"name": "URLhaus csv_recent", "url": URLHAUS_RECENT_URL, "status": "skipped_http_410_and_malware_not_phishing_policy"},
        ],
        "message_sources": [
            {"name": "UCI SMS Spam Collection", "url": "https://archive.ics.uci.edu/dataset/228/sms+spam+collection", "license": "CC BY 4.0", "status": "integrated"},
            {"name": "Mendeley Balanced Spam & Smishing (10,191)", "url": "https://data.mendeley.com/datasets/vmg875v4xs/1", "license": "CC BY 4.0", "status": "integrated"},
            {"name": "Mishra & Soni SMS Phishing (5,971)", "url": "https://data.mendeley.com/datasets/f45bkkt8pr", "license": "CC BY 4.0", "status": "integrated"},
            {"name": "Synthetic Hinglish & Scam", "status": "kept_strictly_separate_for_supplementary_eval"},
        ],
    }

    PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
    (PROCESSED_DIR / "dataset_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    (PROCESSED_DIR / "dataset_quality_report.json").write_text(json.dumps(quality_report, indent=2), encoding="utf-8")
    (PROCESSED_DIR / "label_distribution_report.json").write_text(json.dumps(label_distribution_report, indent=2), encoding="utf-8")
    (PROCESSED_DIR / "domain_diversity_report.json").write_text(json.dumps(domain_diversity_report, indent=2), encoding="utf-8")

    md = (
        "# ScamShield AI — Dataset Source & Provenance Report (v3.0.0)\n\n"
        f"- **Generated**: {manifest['generated_at']}\n"
        f"- **URLs (Cleaned Real-World)**: {url_stats.cleaned_rows} (Train: {len(url_train)}, Val: {len(url_val)}, Test Unseen Domains: {len(url_test)})\n"
        f"- **PhreshPhish Time-Separated Unseen-Domain Test**: {len(pp_test_unseen)} rows\n"
        f"- **Messages (Cleaned Real-World)**: {msg_stats.cleaned_rows} (Train: {len(msg_train)}, Val: {len(msg_val)}, Test: {len(msg_test)})\n"
        f"- **Domain Diversity**: Unique legitimate domains increased from {domain_diversity_report['before_legitphish_only']['unique_legitimate_domains']} to {domain_diversity_report['after_combined_real_world']['unique_legitimate_domains']}.\n"
    )
    (PROCESSED_DIR / "dataset_source_report.md").write_text(md, encoding="utf-8")

    print(json.dumps({"manifest": manifest, "label_distribution": label_distribution_report, "domain_diversity": domain_diversity_report}, indent=2))
    return manifest


if __name__ == "__main__":
    prepare_all_datasets()
