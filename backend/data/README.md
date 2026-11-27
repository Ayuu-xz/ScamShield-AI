# ScamShield AI — ML Datasets & Provenance

## 1. URL Classification Datasets (`urls`)

### Primary Training Dataset: LegitPhish Dataset
- **Source**: [Mendeley Data — LegitPhish Dataset](https://data.mendeley.com/datasets/hx4m73v2sf/2) (`DOI: 10.17632/hx4m73v2sf.2`).
- **License**: Creative Commons Attribution 4.0 International (`CC BY 4.0`).
- **Download**: Automatically downloaded by `ml_training/prepare_datasets.py` to `data/raw/legitphish_urls.csv` (`url_features_extracted1.csv`).
- **Expected Format**: CSV with `URL` (raw URL string) and `ClassLabel` (`0` → `Phishing`, `1` → `Legitimate`).
- **Compatibility Strategy**: Only the raw `URL` string and `ClassLabel` are ingested; the 15 lexical features + character n-gram TF-IDF are recomputed consistently at both training and inference time via `app/ml/features.py`.

### Independent Cross-Dataset Benchmark: `synthetic_defensive_urls_v1`
- **Source**: Generated locally by `ml_training/prepare_datasets.py` (`data/processed/urls/benchmark_synthetic.csv`).
- **Usage**: Kept strictly separate from LegitPhish training for independent cross-dataset evaluation.

### Optional External Dataset: Kaggle Phishing URL Features Dataset
- **Source**: [Kaggle — elifzelik/phishing-url-features-dataset](https://www.kaggle.com/elifzelik/phishing-url-features-dataset) (`CC BY 4.0`).
- **Download Status**: Requires Kaggle authentication (`kaggle.json` or manual download from Kaggle).
- **Compatibility Note**: Provides precomputed HTML/DNS/WHOIS/address-bar numerical features rather than raw URL strings; excluded from raw-URL production model training because HTML/DNS/WHOIS features are unavailable in text-only inference.

---

## 2. Message Classification Datasets (`messages`)

### Primary Public Source: UCI SMS Spam Collection
- **Source**: [UCI SMS Spam Collection](https://archive.ics.uci.edu/dataset/228/sms+spam+collection) (Almeida & Hidalgo, 2012).
- **License**: Creative Commons Attribution 4.0 International (`CC BY 4.0`).
- **Label Mapping**: `ham` → `Legitimate`, `spam` → `Spam`.

### Defensive Phishing & Scam Augmentation
- **Source**: Curated synthetic English and Hinglish templates in `ml_training/prepare_datasets.py` (`Phishing`, `Scam`, `Legitimate`).
- **Classes**: `Legitimate`, `Spam`, `Phishing`, `Scam`.

---

## 3. Preprocessing, Cleaning & Leakage Prevention

- Missing/blank text and unmapped labels are dropped and counted.
- Exact and normalized duplicates are removed **before** splitting.
- Conflicting-label groups (identical normalized text with different labels) are detected and excluded.
- Leakage-safe splitting uses `StratifiedGroupKFold` (`random_state=42`):
  - **URLs**: Grouped by normalized `hostname + path` so query-parameter variants do not leak across splits.
  - **Messages**: Grouped by template skeleton (URLs and numbers masked) so synthetic template siblings stay in the same split.
- `TfidfVectorizer` and `StandardScaler` are fitted strictly on the training split inside scikit-learn `Pipeline`.
- Full dataset statistics and provenance are saved to `data/processed/dataset_manifest.json`.

---

## 4. Training Commands & Outputs

```powershell
cd backend
.\.venv\Scripts\python.exe -m ml_training.prepare_datasets
.\.venv\Scripts\python.exe -m ml_training.train_url_model
.\.venv\Scripts\python.exe -m ml_training.train_message_model
```

- **Saved Artifacts (`app/ml/artifacts/`)**:
  - `url_model.joblib`, `url_model_v2.joblib`, `url_model_meta.json`
  - `message_model.joblib`, `message_model_v2.joblib`, `message_model_meta.json`
  - Baseline `v1.0.0` backups preserved in `app/ml/artifacts/backup_v1_0_0/`

---

## 5. Known Limitations

- LegitPhish legitimate URLs are heavily weighted toward Wikipedia and Stack Overflow; unfamiliar benign domains with tracking parameters can still produce false positives in cross-dataset testing.
- Synthetic `Phishing` and `Scam` message counts (`144` and `48` after deduplication) are small compared to UCI SMS `Legitimate` (`4,523`) and `Spam` (`642`).
- Large raw/processed datasets should not be committed to public repositories; regenerate locally via `prepare_datasets.py`.
