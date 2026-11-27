# ScamShield AI — Chrome Browser Extension (Manifest V3)

On-demand phishing and scam URL checker for Google Chrome that connects directly to your local **ScamShield AI** FastAPI backend.

---

## Backend Configuration

The backend URL and request timeout are configured in one place:
- [src/config.js](src/config.js) (`API_BASE_URL = 'http://127.0.0.1:8000'`, `REQUEST_TIMEOUT_MS = 6000`).
- If you change the backend host or port, also update `host_permissions` in [manifest.json](manifest.json).

---

## Loading the Extension Locally in Chrome

1. Start the ScamShield AI backend:
   ```powershell
   cd backend
   .\.venv\Scripts\uvicorn.exe app.main:app --host 127.0.0.1 --port 8000
   ```
2. Open Chrome and navigate to `chrome://extensions/`.
3. Enable **Developer mode** (top-right toggle).
4. Click **Load unpacked** and select the `d:\HACKATHON\browser-extension` folder.
5. Pin **ScamShield AI** from the Extensions toolbar menu and click it to scan the active tab or any pasted URL.

---

## Permissions Requested & Purpose

- **`activeTab`**: Grants temporary access to read **only** the current active tab's URL when you explicitly open the extension popup. No `<all_urls>`, `history`, `tabs`, `cookies`, or `storage` permissions are requested.
- **`host_permissions` (`http://127.0.0.1:8000/*`, `http://localhost:8000/*`)**: Allows the background service worker to call `GET /api/health` and `POST /api/scan/url` on your local ScamShield AI backend.

---

## How Scanning Works & Privacy Guarantees

1. Clicking **Scan Current Website** or **Scan URL** sends **only the URL string** to `POST /api/scan/url` (`inspect_website: false`).
2. The extension **never** auto-scans visited websites, collects browsing history, injects content scripts, or transmits page contents, cookies, passwords, or form data.
3. Explanations are displayed in **English**, **हिंदी (Hindi)**, or **Hinglish** using the backend's `multilingual_explanations` response—switching languages is instant and does not trigger another scan.

---

## Known Limitations

- Designed for local development against `http://127.0.0.1:8000` (not published to the Chrome Web Store).
- Internal browser pages (`chrome://`, `about:`, `file://`) cannot be scanned.
- Performs text-only URL analysis (`inspect_website: false`) to keep popup checks fast and non-intrusive.
