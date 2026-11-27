"""Prepare deduplicated, leakage-free train/val/test datasets for URL and Message ML models."""

from __future__ import annotations

import csv
import io
import random
import zipfile
from pathlib import Path

import httpx
from sklearn.model_selection import train_test_split

BACKEND_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BACKEND_DIR / "data"
RAW_DIR = DATA_DIR / "raw"
PROCESSED_DIR = DATA_DIR / "processed"

UCI_SMS_URL = "https://archive.ics.uci.edu/static/public/228/sms+spam+collection.zip"
RANDOM_SEED = 42


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


def prepare_message_datasets() -> dict[str, int]:
    """Load UCI SMS + synthetic phishing/scam rows, deduplicate, and split 70/15/15."""
    sms_path = download_uci_sms_dataset()
    raw_rows: list[tuple[str, str]] = []

    for line in sms_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "\t" not in line:
            continue
        raw_label, text = line.split("\t", 1)
        cleaned = " ".join(text.split())
        if not cleaned:
            continue
        label = "Spam" if raw_label.strip().lower() == "spam" else "Legitimate"
        raw_rows.append((cleaned, label))

    raw_rows.extend(_build_synthetic_phishing_and_scam_messages())

    # Deduplicate by normalized lowercase text before splitting to prevent leakage
    seen: set[str] = set()
    deduped: list[tuple[str, str]] = []
    for text, label in raw_rows:
        norm = " ".join(text.lower().split())
        if norm and norm not in seen:
            seen.add(norm)
            deduped.append((text, label))

    texts = [r[0] for r in deduped]
    labels = [r[1] for r in deduped]

    X_train, X_temp, y_train, y_temp = train_test_split(
        texts, labels, test_size=0.30, random_state=RANDOM_SEED, stratify=labels
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, random_state=RANDOM_SEED, stratify=y_temp
    )

    out_dir = PROCESSED_DIR / "messages"
    out_dir.mkdir(parents=True, exist_ok=True)
    for split_name, sx, sy in [
        ("train", X_train, y_train),
        ("val", X_val, y_val),
        ("test", X_test, y_test),
    ]:
        with (out_dir / f"{split_name}.csv").open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["text", "label"])
            writer.writerows(zip(sx, sy))

    return {"total": len(deduped), "train": len(X_train), "val": len(X_val), "test": len(X_test)}


def prepare_url_datasets() -> dict[str, int]:
    """Generate a deduplicated, leakage-free synthetic defensive URL dataset (70/15/15)."""
    rng = random.Random(RANDOM_SEED)
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
            if rng.random() < 0.25:
                raw_urls.append((f"https://www.{d}{p}", "Legitimate"))

    for brand in phish_brands:
        for tld in phish_tlds:
            for p in phish_paths:
                raw_urls.append((f"http://{brand}-secure-login.{tld}{p}", "Phishing"))
                raw_urls.append((f"https://login.verify.account.{brand}-portal.{tld}{p}", "Phishing"))

    # Add IP-host, shortener, and @-obfuscated synthetic phishing URLs
    for idx in range(1, 35):
        raw_urls.append((f"http://192.168.{idx % 250}.{(idx * 7) % 250}/verify/login", "Phishing"))
        raw_urls.append((f"https://trusted.com@evil-host-{idx}.xyz/auth/kyc", "Phishing"))
        raw_urls.append((f"http://bit.ly/verify-acct-{idx}", "Phishing"))

    seen: set[str] = set()
    deduped: list[tuple[str, str]] = []
    for url, label in raw_urls:
        norm = url.strip().lower()
        if norm and norm not in seen:
            seen.add(norm)
            deduped.append((url, label))

    urls = [r[0] for r in deduped]
    labels = [r[1] for r in deduped]

    X_train, X_temp, y_train, y_temp = train_test_split(
        urls, labels, test_size=0.30, random_state=RANDOM_SEED, stratify=labels
    )
    X_val, X_test, y_val, y_test = train_test_split(
        X_temp, y_temp, test_size=0.50, random_state=RANDOM_SEED, stratify=y_temp
    )

    out_dir = PROCESSED_DIR / "urls"
    out_dir.mkdir(parents=True, exist_ok=True)
    for split_name, sx, sy in [
        ("train", X_train, y_train),
        ("val", X_val, y_val),
        ("test", X_test, y_test),
    ]:
        with (out_dir / f"{split_name}.csv").open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["url", "label"])
            writer.writerows(zip(sx, sy))

    return {"total": len(deduped), "train": len(X_train), "val": len(X_val), "test": len(X_test)}


if __name__ == "__main__":
    msg_stats = prepare_message_datasets()
    url_stats = prepare_url_datasets()
    print("Message dataset prepared:", msg_stats)
    print("URL dataset prepared:", url_stats)
