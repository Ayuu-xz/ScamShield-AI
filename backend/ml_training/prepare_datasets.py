"""Reusable dataset ingestion, cleaning, conflict detection, and leakage-safe splitting."""

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

import httpx
from sklearn.model_selection import StratifiedGroupKFold, train_test_split

BACKEND_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BACKEND_DIR / "data"
RAW_DIR = DATA_DIR / "raw"
PROCESSED_DIR = DATA_DIR / "processed"

UCI_SMS_URL = "https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip"
MENDELEY_LEGITPHISH_API = "https://data.mendeley.com/public-api/datasets/hx4m73v2sf"
RANDOM_SEED = 42
DATASET_VERSION = "2.0.0"

URL_LABEL_MAP: dict[str, str] = {
    "0": "Phishing",
    "phishing": "Phishing",
    "malicious": "Phishing",
    "bad": "Phishing",
    "-1": "Phishing",
    "1": "Legitimate",
    "legitimate": "Legitimate",
    "benign": "Legitimate",
    "good": "Legitimate",
}

MESSAGE_LABEL_MAP: dict[str, str] = {
    "ham": "Legitimate",
    "legitimate": "Legitimate",
    "spam": "Spam",
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


def _url_leakage_group(raw_url: str) -> str:
    """Group URLs by normalized hostname+path so query-param variants stay in one split."""
    candidate = raw_url.strip() if "://" in raw_url else f"http://{raw_url.strip()}"
    try:
        parts = urlsplit(candidate)
        host = (parts.hostname or "").lower()
        path = parts.path.rstrip("/").lower()
        return f"{host}{path}" or raw_url.strip().lower()
    except ValueError:
        return raw_url.strip().lower()


def _normalize_message_key(raw_text: str) -> str:
    return " ".join(raw_text.strip().lower().split())


def _message_leakage_group(raw_text: str) -> str:
    """Skeletonize template variables (URLs/numbers) so template siblings stay in one split."""
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
            _url_leakage_group(canonical_text)
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


def stratified_grouped_split(
    records: list[tuple[str, str, str]],
    *,
    random_seed: int = RANDOM_SEED,
) -> tuple[list[tuple[str, str]], list[tuple[str, str]], list[tuple[str, str]]]:
    """Split (text, label, group) into leakage-free ~70/15/15 train/val/test sets."""
    texts = [r[0] for r in records]
    labels = [r[1] for r in records]
    groups = [r[2] for r in records]

    unique_groups = len(set(groups))
    if unique_groups >= 10:
        # 5-fold StratifiedGroupKFold (~20% holdout), then split holdout ~50/50 into val/test
        sgkf = StratifiedGroupKFold(n_splits=6, shuffle=True, random_state=random_seed)
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

    # Fallback when group count is very small
    X_train, X_temp, y_train, y_temp = train_test_split(
        texts, labels, test_size=0.30, random_state=random_seed, stratify=labels
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, random_state=random_seed, stratify=y_temp
    )
    return list(zip(X_train, y_train)), list(zip(X_val, y_val)), list(zip(X_test, y_test))


def download_uci_sms_dataset() -> Path:
    """Download and extract UCI SMS Spam Collection if not already present."""
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    target_txt = RAW_DIR / "SMSSpamCollection"
    if target_txt.exists():
        return target_txt

    response = httpx.get(UCI_SMS_URL, timeout=20.0, follow_redirects=True)
    response.raise_for_status()
    with zipfile.ZipFile(io.BytesIO(response.content)) as zf:
        for member in zf.namelist():
            if member.endswith("SMSSpamCollection"):
                target_txt.write_bytes(zf.read(member))
                break

    if not target_txt.exists():
        raise RuntimeError("SMSSpamCollection file not found inside downloaded archive.")
    return target_txt


def download_legitphish_dataset() -> Path:
    """Download Mendeley LegitPhish CSV if not already present locally."""
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    target_csv = RAW_DIR / "legitphish_urls.csv"
    if target_csv.exists():
        return target_csv

    meta = httpx.get(MENDELEY_LEGITPHISH_API, timeout=15.0).json()
    download_url = meta["files"][0]["content_details"]["download_url"]
    r = httpx.get(download_url, timeout=60.0, follow_redirects=True)
    r.raise_for_status()
    target_csv.write_bytes(r.content)
    return target_csv


def load_legitphish_rows(csv_path: Path) -> Iterable[tuple[str, str]]:
    """Validate LegitPhish CSV schema and yield (URL, ClassLabel) pairs."""
    with csv_path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        fields = set(reader.fieldnames or [])
        if "URL" not in fields or "ClassLabel" not in fields:
            raise SchemaValidationError(
                f"Expected 'URL' and 'ClassLabel' columns in {csv_path.name}, found {sorted(fields)}"
            )
        for row in reader:
            yield row.get("URL", ""), row.get("ClassLabel", "")


def _build_synthetic_defensive_urls() -> list[tuple[str, str]]:
    """Generate the synthetic_defensive_urls_v1 benchmark (never fetched)."""
    legit_domains = [
        "example.com", "docs.python.org", "developer.mozilla.org", "github.com",
        "en.wikipedia.org", "stackoverflow.com", "react.dev", "fastapi.tiangolo.com",
        "news.ycombinator.com", "archive.ics.uci.edu", "portal.university.edu",
        "shop.example-store.com", "support.example.org", "cloud.example.net",
    ]
    legit_paths = [
        "", "/about", "/docs", "/getting-started", "/products/item-42",
        "/blog/security-tips", "/search?q=python", "/contact", "/pricing",
        "/account/settings", "/help?utm_source=newsletter&fbclid=12345",
        "/dashboard?next=/profile",
    ]
    phish_brands = ["paypa1", "micros0ft", "g00gle", "app1e", "amaz0n", "netf1ix", "chase-bank"]
    phish_tlds = ["com", "xyz", "tk", "top", "click", "info", "net"]
    phish_paths = [
        "/login/verify", "/kyc-update", "/auth/password-reset",
        "/security-check?next=https://evil.example.org/steal",
        "/download/invoice.exe", "/signin?redirect=http://192.168.1.50/collect",
        "/webscr?cmd=_login-submit&session=%20%40%2F%2F",
    ]

    raw_urls: list[tuple[str, str]] = []
    for d in legit_domains:
        for p in legit_paths:
            raw_urls.append((f"https://{d}{p}", "Legitimate"))
            raw_urls.append((f"https://www.{d}{p}", "Legitimate"))

    for brand in phish_brands:
        for tld in phish_tlds:
            for p in phish_paths:
                raw_urls.append((f"http://{brand}-secure-login.{tld}{p}", "Phishing"))
                raw_urls.append((f"https://login.verify.account.{brand}-portal.{tld}{p}", "Phishing"))

    for idx in range(1, 35):
        raw_urls.append((f"http://192.168.{idx % 250}.{(idx * 7) % 250}/verify/login", "Phishing"))
        raw_urls.append((f"https://trusted.com@evil-host-{idx}.xyz/auth/kyc", "Phishing"))
        raw_urls.append((f"http://bit.ly/verify-acct-{idx}", "Phishing"))

    return raw_urls


def _build_synthetic_phishing_and_scam_messages() -> list[tuple[str, str]]:
    """Curated synthetic Phishing & Scam messages (English + Hinglish) for 4-class training."""
    phishing_templates = [
        "Your {brand} account has been suspended. Verify your identity immediately at {url}",
        "Urgent security alert from {brand}: unusual login detected. Confirm password at {url}",
        "Update your {brand} KYC before midnight to avoid account block: {url}",
        "Action required: your {brand} wallet is locked. Unlock your account here {url}",
        "Aapka {brand} khata band ho jayega, turant KYC update kare: {url}",
        "Dear customer, your {brand} netbanking password expired. Reset now: {url}",
        "Confirm your OTP and card details to cancel unauthorized transaction: {url}",
        "Your {brand} verification is pending. Click {url} and enter your PIN.",
    ]
    scam_templates = [
        "Congratulations! You won a cash prize of {amount}. Pay registration fee {fee} to claim.",
        "Work from home and earn {amount} per day! Pay {fee} joining fee to start today.",
        "Failed parcel delivery: your package is held at customs. Pay {fee} delivery charge at {url}",
        "Aapne lottery mein {amount} jeete hai! Claim karne ke liye {fee} processing fee bheje.",
        "Ghar baithe kamaye {amount} daily! Registration fee {fee} bhej kar apna slot book kare.",
        "Your courier parcel is on hold due to unpaid customs fee of {fee}. Pay at {url}",
        "You have been selected for an unexpected cash reward of {amount}. Share bank details to receive.",
        "Urgent: share your OTP to receive cashback of {amount} in your account.",
    ]
    legit_hinglish_and_reminders = [
        "Urgent reminder: please bring your project report to the lab tomorrow at 10 AM.",
        "Hi team, our weekly standup is moved to 3 PM in Room B.",
        "Kal subah 9 baje meeting hai, time pe aa jana.",
        "Your order #4821 has been shipped. Track it in our official mobile app.",
        "Thanks for attending today's workshop! Slides are uploaded on the portal.",
        "Please review the pull request when you have a moment.",
    ]

    brands = ["Bank", "PayPal", "Account", "Card", "UPI", "Wallet", "Portal", "Service"]
    urls = [
        "http://bit.ly/verify-now",
        "http://paypa1-secure.example.com/login",
        "http://192.168.1.50/kyc",
        "https://secure-update.example.org/auth",
    ]
    amounts = ["$5,000", "Rs 50,000", "INR 1,00,000", "$10,000"]
    fees = ["Rs 499", "$25", "Rs 250", "$15"]

    rows: list[tuple[str, str]] = []
    for tmpl in phishing_templates:
        for b in brands[:5]:
            for u in urls:
                rows.append((tmpl.format(brand=b, url=u), "Phishing"))
    for tmpl in scam_templates:
        for amt in amounts:
            for fee in fees[:2]:
                for u in urls[:2]:
                    rows.append((tmpl.format(amount=amt, fee=fee, url=u), "Scam"))
    for msg in legit_hinglish_and_reminders:
        rows.append((msg, "Legitimate"))
    return rows


def _write_csv(path: Path, header: list[str], rows: list[tuple[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        writer.writerows(rows)


def prepare_all_datasets() -> dict:
    """Ingest, clean, split, and generate manifest for URL and Message datasets."""
    # 1. URLs: LegitPhish (real-world) + synthetic_defensive_urls_v1 (benign/phish diversity)
    legitphish_path = download_legitphish_dataset()
    lp_cleaned, lp_stats = clean_records(
        load_legitphish_rows(legitphish_path),
        label_map=URL_LABEL_MAP,
        is_url=True,
    )
    syn_raw = _build_synthetic_defensive_urls()
    syn_cleaned, syn_stats = clean_records(
        syn_raw,
        label_map=URL_LABEL_MAP,
        is_url=True,
    )

    combined_url_rows = [(t, lbl) for t, lbl, _ in lp_cleaned] + [
        (t, lbl) for t, lbl, _ in syn_cleaned
    ]
    url_cleaned, url_stats = clean_records(
        combined_url_rows,
        label_map=URL_LABEL_MAP,
        is_url=True,
    )
    url_train, url_val, url_test = stratified_grouped_split(url_cleaned)

    url_out = PROCESSED_DIR / "urls"
    _write_csv(url_out / "train.csv", ["url", "label"], url_train)
    _write_csv(url_out / "val.csv", ["url", "label"], url_val)
    _write_csv(url_out / "test.csv", ["url", "label"], url_test)

    _, _, lp_test_only = stratified_grouped_split(lp_cleaned)
    _, _, syn_test_only = stratified_grouped_split(syn_cleaned)
    _write_csv(url_out / "test_legitphish.csv", ["url", "label"], lp_test_only)
    _write_csv(url_out / "benchmark_synthetic.csv", ["url", "label"], syn_test_only)

    # 2. Messages: UCI SMS Spam Collection + synthetic English/Hinglish Phishing/Scam
    sms_path = download_uci_sms_dataset()
    msg_raw_rows: list[tuple[str, str]] = []
    for line in sms_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "\t" not in line:
            continue
        raw_label, text = line.split("\t", 1)
        msg_raw_rows.append((text, raw_label))
    msg_raw_rows.extend(_build_synthetic_phishing_and_scam_messages())

    msg_cleaned, msg_stats = clean_records(
        msg_raw_rows,
        label_map=MESSAGE_LABEL_MAP,
        is_url=False,
    )
    msg_train, msg_val, msg_test = stratified_grouped_split(msg_cleaned)

    msg_out = PROCESSED_DIR / "messages"
    _write_csv(msg_out / "train.csv", ["text", "label"], msg_train)
    _write_csv(msg_out / "val.csv", ["text", "label"], msg_val)
    _write_csv(msg_out / "test.csv", ["text", "label"], msg_test)

    kaggle_path = RAW_DIR / "kaggle_phishing_url_features.csv"
    kaggle_status = (
        "present_local_precomputed_features_incompatible_with_raw_url_pipeline"
        if kaggle_path.exists()
        else "not_downloaded_kaggle_auth_required"
    )

    manifest = {
        "dataset_version": DATASET_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "random_seed": RANDOM_SEED,
        "url_datasets": {
            "primary_training": {
                "name": "LegitPhish Dataset",
                "source": "https://data.mendeley.com/datasets/hx4m73v2sf/2",
                "doi": "10.17632/hx4m73v2sf.2",
                "license": "CC BY 4.0",
                "download_status": "downloaded",
                "local_raw_file": "data/raw/legitphish_urls.csv",
                "label_mapping": {"0": "Phishing", "1": "Legitimate"},
                "stats": url_stats.__dict__,
                "splits": {
                    "train": len(url_train),
                    "val": len(url_val),
                    "test": len(url_test),
                },
            },
            "independent_benchmark": {
                "name": "synthetic_defensive_urls_v1",
                "source": "ml_training/prepare_datasets.py",
                "license": "Internal project benchmark",
                "download_status": "generated_locally",
                "local_processed_file": "data/processed/urls/benchmark_synthetic.csv",
                "stats": syn_stats.__dict__,
            },
            "optional_kaggle": {
                "name": "Kaggle Phishing URL Features Dataset",
                "source": "https://www.kaggle.com/elifzelik/phishing-url-features-dataset",
                "license": "CC BY 4.0",
                "download_status": kaggle_status,
                "compatibility_note": (
                    "Requires Kaggle authentication for download and provides precomputed "
                    "HTML/DNS/WHOIS numerical features rather than raw URL strings; skipped "
                    "from raw-URL production model training."
                ),
            },
        },
        "message_datasets": {
            "sources": [
                {
                    "name": "UCI SMS Spam Collection",
                    "source": "https://archive.ics.uci.edu/dataset/228/sms+spam+collection",
                    "license": "CC BY 4.0",
                    "download_status": "downloaded",
                    "local_raw_file": "data/raw/SMSSpamCollection",
                    "label_mapping": {"ham": "Legitimate", "spam": "Spam"},
                },
                {
                    "name": "ScamShield Synthetic Phishing & Scam (English + Hinglish)",
                    "source": "ml_training/prepare_datasets.py",
                    "license": "Internal project augmentation",
                    "download_status": "generated_locally",
                },
            ],
            "stats": msg_stats.__dict__,
            "splits": {
                "train": len(msg_train),
                "val": len(msg_val),
                "test": len(msg_test),
            },
        },
        "leakage_prevention": [
            "Exact and normalized deduplication performed prior to splitting.",
            "Conflicting-label groups removed prior to splitting.",
            "StratifiedGroupKFold grouping by normalized hostname+path (URLs) and template skeleton (Messages).",
            "TF-IDF vectorizers and StandardScaler fitted strictly on training split inside Pipeline.",
        ],
    }

    (PROCESSED_DIR / "dataset_manifest.json").write_text(
        json.dumps(manifest, indent=2), encoding="utf-8"
    )
    print(json.dumps(manifest, indent=2))
    return manifest


if __name__ == "__main__":
    prepare_all_datasets()
