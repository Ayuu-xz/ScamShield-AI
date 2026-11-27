# ScamShield AI — Real-World ML Datasets & Provenance (v3.0.0)

## 1. URL Classification Datasets (`urls`)
- **LegitPhish Dataset** (`https://data.mendeley.com/datasets/hx4m73v2sf/2`, `CC BY 4.0`): Real-world benign and phishing URLs (`data/raw/legitphish_urls.csv`).
- **PhreshPhish** (`https://huggingface.co/datasets/phreshphish/phreshphish`, `CC BY 4.0`): Diverse real-world benign & time-stamped phishing URLs streamed via DuckDB without downloading HTML (`data/raw/phreshphish_train.csv`, `data/raw/phreshphish_test.csv`).
- **PhishTank** (`https://phishtank.org/`, `online-valid.csv`, `verified == "yes"`): Verified active phishing URLs (`data/raw/phishtank_online_valid.csv`).
- **URLhaus** (`https://urlhaus.abuse.ch/downloads/csv_recent/`): Skipped (`HTTP 410 Gone` + label policy keeps malware distribution separate from phishing).
- **Synthetic Benchmark** (`synthetic_defensive_urls_v1`): Kept strictly separate in `data/processed/urls/benchmark_synthetic.csv`.

## 2. Message Classification Datasets (`messages`)
- **UCI SMS Spam Collection** (`https://archive.ics.uci.edu/dataset/228/sms+spam+collection`, `CC BY 4.0`): `ham` → `Legitimate`, `spam` → `Spam`.
- **Mendeley Balanced Spam & Smishing Dataset** (`https://data.mendeley.com/datasets/vmg875v4xs/1`, `CC BY 4.0`, `10,191` rows): `ham` → `Legitimate`, `spam` → `Spam`, `smishing` → `Phishing`.
- **Mishra & Soni SMS Phishing Dataset** (`https://data.mendeley.com/datasets/f45bkkt8pr`, `CC BY 4.0`, `5,971` rows): `ham` → `Legitimate`, `spam` → `Spam`, `smishing` → `Phishing`.
- **Synthetic Hinglish & Scam**: Kept strictly separate in `data/processed/messages/benchmark_synthetic_hinglish.csv` (real-world `test.csv` contains zero synthetic records).

## 3. Leakage Prevention & Generated Reports (`data/processed/`)
- URLs grouped by **registrable domain** (`tldextract` offline PSL) via `StratifiedGroupKFold` (`0` domain overlap across `train`/`val`/`test`, plus time-separated `test_phreshphish_unseen.csv`).
- Messages grouped by normalized template skeleton via `StratifiedGroupKFold`.
- Reports generated: `dataset_manifest.json`, `dataset_quality_report.json`, `dataset_source_report.md`, `label_distribution_report.json`, `domain_diversity_report.json`.

## 4. Rollback Instructions
Previous production models are preserved in `app/ml/artifacts/backup_v2_0_0/` (and `backup_v1_0_0/`). To roll back:
```powershell
Copy-Item -Force backend\app\ml\artifacts\backup_v2_0_0\* backend\app\ml\artifacts\
```
