# ScamShield AI — Phishing Link, Scam Message & Threat Analytics Platform

ScamShield AI is a defensive cybersecurity web application and Chrome extension that inspects suspicious URLs, SMS/chat messages, and uploaded screenshots for phishing, malware, redirect, and tracker indicators. It combines a deterministic rule-based risk engine with calibrated Machine Learning (ML) models, optional external threat intelligence, English/Hindi/Hinglish explanations, SQLite scan history, detailed PDF/JSON reports, and a real-database analytics dashboard.

> **Core Security & Safety Principles**
> - Submitted URLs are analyzed **strictly as text** by default — they are never opened, clicked, fetched, crawled, or executed.
> - Optional isolated website inspection (`inspect_website=true`) enforces strict SSRF protections (blocks `localhost`, private/loopback/link-local IPs, cloud metadata `169.254.169.254`, DNS rebinding, and binary downloads) and never executes page JavaScript.
> - `Safe` or `No strong indicators detected` never guarantees 100% safety; automated analysis is advisory only.

---

## Features

- **Rule-Based URL Scanner (`POST /api/scan/url`)**: Evaluates URL normalization/validation, IP hosts, URL shorteners, excessive length/subdomains/hyphens/encoding, look-alike brand impersonation, suspicious redirects, credential URL patterns, dangerous file extensions, and missing HTTPS.
- **URL-First Message Scanner (`POST /api/scan/message`)**: Extracts and deduplicates URLs from messages and evaluates them through the shared URL engine so ordinary conversational text never inflates URL risk scores; aggregates multi-URL messages using maximum risk.
- **Screenshot & Image OCR Scanner (`POST /api/scan/message-image`)**: Validates JPG, JPEG, PNG, and WEBP uploads (up to 5 MB, dimension bounds enforced), extracts text locally via `rapidocr-onnxruntime` + `Pillow`, and analyzes extracted URLs.
- **Machine Learning Detection Layer (`POST /api/ml/predict/url`, `POST /api/ml/predict/message`)**: Calibrated scikit-learn pipelines (`url_model.joblib` for URLs, 4-class `message_model.joblib` for `Legitimate`, `Spam`, `Phishing`, `Scam`) running alongside rule-based scoring with graceful fallback if models are absent.
- **Multilingual Explanations (English, हिंदी, Hinglish)**: Instant client-side language switching backed by structured `multilingual_explanations` in API responses.
- **External Threat Intelligence Integration**: Modular multi-provider lookup supporting **Google Safe Browsing API v4**, **URLhaus by abuse.ch**, and a configurable custom JSON provider with TTL caching, rate-limit/timeout handling, and duplicate-evidence prevention.
- **Detailed Scan Reports & Exports (`GET /api/history/{id}/report`, `GET /api/history/{id}/export`)**: Generates validated reports with rule analysis, ML status, threat intelligence status, explanations, recommendations, privacy redaction, and downloadable **PDF** (`fpdf2`) and **JSON** exports.
- **Real-Database Analytics Dashboard (`GET /api/analytics`)**: Displays total scans, URL vs. Message/OCR breakdown, classification counts, risk score distribution, daily/weekly trends, top detected indicators, ML usage stats, and threat intelligence telemetry directly from SQLite.
- **Chrome Browser Extension (`browser-extension/`)**: Manifest V3 extension using minimal `activeTab` permission to scan the active tab's URL on explicit user click without automatically fetching or opening links.

---

## Architecture

- **Frontend (`frontend/`)**: React 18 + Vite 6 + Tailwind CSS 4 + Lucide React.
  - `src/services/api.js`: Centralized API client, response normalization (`normalizeScanResponse`), report download helper, and analytics/history queries. `VITE_API_BASE_URL` configures the backend; an empty value uses same-origin `/api` requests.
  - `src/components/`: `OverviewPage` (scanner-first), `ScannerPanel`, `DetectionResultCard`, `ScanHistoryPage` (search, date/type/classification filters, sorting, Detailed Report drawer, PDF/JSON export), `AnalyticsPage`, `ThreatAnalysisPage`, `HelpResourcesPage`, `Sidebar`, `TopHeader`.
  - `vite.config.js`: Local-only `/api` proxy to the development backend.
- **Backend (`backend/`)**: Python + FastAPI + Pydantic v2 + SQLAlchemy 2.0 (SQLite).
  - `app/core/config.py`: Environment-based configuration, risk thresholds, scoring weights, ML, OCR, and threat intel settings.
  - `app/api/routes.py`: REST API endpoints under `/api`.
  - `app/services/`: `url_analyzer.py`, `message_analyzer.py`, `risk_scorer.py`, `website_inspector.py`, `ocr_service.py`, `explanation_service.py`, `report_service.py`, `analytics_service.py`, `history_service.py`, and `rules/` (`phishing_detector.py`, `redirect_detector.py`, `file_download_detector.py`, `tracker_detector.py`, `threat_intel_service.py`).
  - `app/ml/`: Feature extraction (`features.py`), cached model predictor (`predictor.py`), and trained artifacts (`artifacts/`).
  - `app/db/`: SQLite engine + automatic lightweight migrations (`database.py`) and `ScanHistory` ORM (`models.py`).
- **Browser Extension (`browser-extension/`)**: Chrome Manifest V3 popup + background service worker (`src/popup.js`, `src/background.js`, `src/api.js`, `src/config.js`).

---

## Technology Stack

- **Frontend**: React 18, Vite 6, Tailwind CSS 4, Lucide React
- **Backend**: Python 3.11+ (verified on 3.14.3), FastAPI, Pydantic v2, Uvicorn
- **Database**: SQLite with SQLAlchemy 2.0
- **ML & OCR**: scikit-learn, joblib, RapidOCR (`rapidocr-onnxruntime`), Pillow
- **Reporting**: `fpdf2` (PDF generation)
- **Browser Extension**: Chrome Manifest V3 (Vanilla JS, HTML, CSS)

---

## Installation & Setup

### Prerequisites
- **Python** 3.11+
- **Node.js** 18+ and **npm**

### 1. Backend Setup
```powershell
cd backend
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env   # Optional: configure threat intel keys or CORS
```

### 2. Frontend Setup
```powershell
cd frontend
npm install
Copy-Item .env.example .env   # Optional: set VITE_API_BASE_URL
```

### 3. ML Model Setup (Pre-trained Artifacts Included)
Pre-trained artifacts are included in `backend/app/ml/artifacts/` (`url_model.joblib`, `message_model.joblib`). To retrain from local datasets:
```powershell
cd backend
.\.venv\Scripts\python.exe -m ml_training.prepare_datasets
.\.venv\Scripts\python.exe -m ml_training.train_url_model
.\.venv\Scripts\python.exe -m ml_training.train_message_model
```

### 4. OCR Requirements
`rapidocr-onnxruntime` and `Pillow` are installed via `backend/requirements.txt`. No external Tesseract binary is required.

### 5. Threat Intelligence Configuration (Optional)
Configure optional API keys in `backend/.env` (never commit real keys):
- `GOOGLE_SAFE_BROWSING_API_KEY`: Google Safe Browsing API v4 key
- `URLHAUS_ENABLED=true` & `URLHAUS_AUTH_KEY`: abuse.ch URLhaus Auth-Key
- `THREAT_INTEL_PROVIDER`, `THREAT_INTEL_API_KEY`, `THREAT_INTEL_ENDPOINT_URL`: Optional custom JSON provider

### 6. Browser Extension Setup
1. Open Chrome and navigate to `chrome://extensions/`.
2. Enable **Developer mode**.
3. Click **Load unpacked** and select the project's `browser-extension` folder.
4. Ensure the ScamShield AI backend is running on `http://127.0.0.1:8000`.

---

## Running the Application

**Terminal 1 — Backend (port `8000`)**
```powershell
cd backend
.\.venv\Scripts\uvicorn.exe app.main:app --host 127.0.0.1 --port 8000
```

**Terminal 2 — Frontend (port `5173`)**
```powershell
cd frontend
npm run dev -- --port 5173
```

Open `http://localhost:5173` in your browser. Interactive API docs are available at `http://127.0.0.1:8000/docs`.

---

## Deployment

### Vercel frontend

1. Import the repository into Vercel and set the project **Root Directory** to `frontend`.
2. Use `npm run build` as the build command and `dist` as the output directory (also declared in `frontend/vercel.json`).
3. Set the Vercel environment variable `VITE_API_BASE_URL` to the deployed Render service origin, for example `https://scamshield-api.onrender.com` (no trailing slash).
4. `frontend/vercel.json` rewrites frontend routes to `index.html` for SPA navigation.

### Render backend

The root `render.yaml` configures the existing FastAPI app from `backend/`, installs `backend/requirements.txt`, and starts `app.main:app` on Render's assigned `$PORT`. It also configures a 1 GB persistent disk at `/var/data` and stores SQLite there. The disk requires a paid Render instance; without persistent storage, SQLite scan history is lost when an instance is replaced or restarted.

After creating the Render service, set `CORS_ORIGINS` to the exact Vercel production origin (comma-separated if multiple origins are needed). Configure optional threat-intelligence keys in Render's environment settings; never put real keys in `.env.example`, source control, or frontend variables. Backend secrets are read from environment variables by `backend/app/core/config.py`.

### Database and public-service limitations

The application currently uses SQLAlchemy with SQLite. A migration is not required for a single Render instance with its persistent disk, but PostgreSQL (and a PostgreSQL driver/deployment configuration) is required for a multi-instance deployment or a host without persistent disks. No migration or existing database data is changed by these deployment files.

The local `backend/scamshield.db` may contain private scan history and must not be published; the root `.gitignore` excludes SQLite databases. Keep backups of any valuable history before changing hosting or storage. The current API has no authentication or per-user history isolation, and exposes history deletion endpoints. Treat a public deployment as a demo until authentication/authorization and data isolation are implemented; do not submit sensitive scans.

The included scikit-learn models are approximately 1.3 MB combined and load lazily on the first prediction. OCR is also initialized lazily on the first image scan; `rapidocr-onnxruntime` can increase runtime memory materially. Validate the selected Render instance against real OCR traffic and upgrade its memory if needed.

---

## GitHub Preparation

The root `.gitignore` excludes environment files, local databases and scan records, Python/Node caches, and generated build output while retaining `.env.example` files. The root `.env.example` documents the frontend and backend deployment variables with placeholders only. Before publishing, verify that the local database and any actual `.env` files are not already tracked, and inspect repository history for credentials; adding ignore rules does not remove previously committed files or secrets.

---

## Environment Variables

The complete placeholder list is in the root `.env.example`. For local work, use `frontend/.env.example` and `backend/.env.example`. Vite only exposes variables prefixed with `VITE_` to browser code, so put API keys exclusively in the backend hosting environment.

---

## API Endpoints

- `GET /api/health` — Backend health check
- `POST /api/scan/url` — URL analysis (rule-based + ML + optional threat intel / isolated inspection)
- `POST /api/scan/message` — URL-first message analysis + independent ML message classification
- `POST /api/scan/message-image` — Screenshot/image OCR + URL-first & ML analysis
- `POST /api/ml/predict/url` — Standalone ML phishing URL inference
- `POST /api/ml/predict/message` — Standalone 4-class ML message inference
- `GET /api/history` — Paginated scan history (`limit`, `offset`, `scan_type`, `risk_level`, `search`, `date_from`, `date_to`, `sort_by`)
- `GET /api/history/{scan_id}` — Single scan history detail
- `GET /api/history/{scan_id}/report` — Detailed validated scan report
- `GET /api/history/{scan_id}/export?format=json|pdf` — Downloadable JSON or PDF report
- `DELETE /api/history/{scan_id}` — Delete one scan record
- `DELETE /api/history` — Clear all scan history records
- `GET /api/analytics` — Real-database analytics (`scan_type`, `risk_level`, `date_from`, `date_to`)

---

## Testing Instructions

**Backend Tests (`pytest`)**
```powershell
cd backend
.\.venv\Scripts\pytest.exe -v
```

**Frontend Unit Tests & Production Build**
```powershell
cd frontend
node --test tests/api.test.mjs tests/awareness.test.mjs
npm run build
```

**Browser Extension Unit Tests**
```powershell
node --test browser-extension/tests/api.test.mjs
```

---

## Known Limitations

- **Threat Intelligence Credentials**: Live Google Safe Browsing and URLhaus lookups require valid API keys in `backend/.env`; without keys, lookups report `Check unavailable` rather than `Safe`.
- **Legacy History Rows**: Records created prior to the `report_payload` schema upgrade mark ML and threat intelligence sections as `unavailable` rather than fabricating findings.
- **PDF Font Encoding**: Standard PDF Helvetica fonts in `fpdf2` replace non-Latin-1 characters (such as Devanagari Hindi text or emojis) with `?`, whereas JSON exports preserve full UTF-8.
- **Single-Workspace Local Console**: No multi-user authentication is enabled; intended for local/single-team defensive analysis.
