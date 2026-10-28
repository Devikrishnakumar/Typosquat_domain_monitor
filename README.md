# 🛡️ CyberSentinel: Brand Impersonation & Phishing Detection Tool

A high-performance cybersecurity tool in Python that detects fraudulent lookalike domains and phishing sites impersonating trusted brands (e.g., **PayPal**).

Designed with a **simple, lightweight architecture** that avoids heavy containerization: runs entirely as **native local Python processes** backed by an **embedded SQLite database** (no database container required).

---

## 🚀 Quick Start (Native Local Setup)

### 1. Start everything on Windows

Double-click [`Launch_CyberSentinel.bat`](./Launch_CyberSentinel.bat) from File Explorer. On first run it creates a local Python environment and installs the project dependencies, then starts the landing page, dashboard, API, and the dashboard's built-in background monitor. It opens the landing page in your browser when all three web services are ready. The existing `start.bat` shortcut also works.

- Landing page: `http://localhost:8765`
- Dashboard: `http://localhost:8501`
- API documentation: `http://localhost:8000/docs`

Keep the service windows open while using the project.

### 2. Run manually on other platforms
```bash
pip install -r requirements.txt
streamlit run app.py
```
Start the API and landing-page servers separately when you need them.

The dashboard uses a custom CyberSentinel logo, a CSS-animated radar, and a lightweight aurora background. These visuals are illustrative; actual monitoring health and findings are shown separately using worker telemetry.

---

## 🌟 Core Features

### 1. 🎯 On-Demand Domain Check
- **Lookalike & Typosquat Generation:** Uses `dnstwist` to generate homoglyphs (e.g., `paypa1.com`), keyword additions (e.g., `paypal-verify.com`), omissions, transpositions, and TLD-swaps.
- **Certificate Transparency Cross-Check:** Queries public Certificate Transparency logs (`crt.sh`) to detect real, actively hosted domains that have obtained valid SSL/TLS certificates.
- **Fast DNS Discovery:** Resolves `A`, `AAAA`, `MX`, and `NS` records in parallel across candidates.

### 2. 🔍 Evidence Collection
For any flagged domain, the engine automatically gathers forensic evidence:
- **DNS & Reachability:** Resolves IP addresses and tests HTTP/HTTPS liveness, status codes, and server headers.
- **Credential Theft Detection:** Analyzes HTML for password inputs (`<input type="password">`) and deceptive security warnings ("account locked", "verify identity").
- **Automated Screenshots:** Captures high-resolution browser screenshots via Playwright (with automatic support for system Chrome, Microsoft Edge, or bundled Chromium).
- **Perceptual Visual Similarity:** Computes visual similarity against the official brand reference screenshot using **Pillow + ImageHash** (`pHash`), detecting pixel-accurate visual clones.
- **WHOIS & RDAP:** Retrieves registrar details, domain creation date, nameservers, and abuse reporting emails over HTTPS.

### 3. 📊 Transparent Risk Scoring
Combines all collected signals into an intuitive **0–100 score** with a simple risk badge:
- 🔴 **HIGH RISK (Score ≥ 70):** Live sites with high visual similarity, credential harvesting forms, or active mail servers. Immediate takedown required.
- 🟠 **MEDIUM RISK (Score 40–69):** Registered lookalike domains, parked holding portals, or homoglyphs without active phishing forms. Continuous monitoring recommended.
- 🟢 **LOW RISK (Score < 40):** Inactive domains, benign informational blogs, or stale registrations.

### 4. 🧪 Simulation / Demo Mode
- **No external test server needed:** Includes pre-packaged, realistic **LOW**, **MEDIUM**, and **HIGH** risk scenarios.
- Click **"✨ Load Pre-Built Demo Scenarios"** in the dashboard to immediately demonstrate all features (side-by-side screenshots, WHOIS records, risk breakdowns, and PDF exports) without waiting for network scans.

### 5. 📄 Reports & Takedown Support
- **PDF Evidence Dossiers:** Generates formal cybersecurity incident reports using **ReportLab** and **Jinja2**, featuring executive summaries, side-by-side visual comparisons, DNS records, and registrar abuse contact details.
- **Registrar Notices:** Prepares a takedown email draft with domain evidence and the registrar's published abuse contact.

### 6. 📡 Optional Live Continuous Monitoring (CertStream)
Listens continuously to the live global Certificate Transparency stream for newly issued certificates matching brand watchlists.

- **Option A (Local Python Process):**
  ```bash
  python certstream_monitor.py
  ```
- **Option B (Synthetic Offline Stream Demo):**
  ```bash
  python certstream_monitor.py --simulate-stream
  ```
- **Option C (Optional Docker Container):**
  *As per design, Docker is only required for this one optional long-running background service:*
  ```bash
  docker compose -f docker-compose.certstream.yml up -d
  ```

---

## 📂 Project Architecture

```
├── app.py                      # Main Streamlit Dashboard (run with: streamlit run app.py)
├── certstream_monitor.py       # Continuous CertStream background listener
├── requirements.txt            # Python dependencies
├── .env                        # Local environment configuration
├── docker-compose.certstream.yml # Optional Docker service for CertStream
├── Dockerfile.certstream       # Container definition for CertStream listener
├── data/
│   ├── phishing_detector.db    # Embedded SQLite database (zero containers needed)
│   ├── screenshots/            # Captured candidate screenshots & demo evidence
│   └── certstream_events.jsonl # Live CT log event telemetry
├── reference_assets/
│   └── brands/                 # Official brand reference screenshots for pHash comparison
├── reports/                    # Generated PDF incident and takedown dossiers
├── src/
│   ├── discovery/              # dnstwist scanner & crt.sh CT discovery
│   ├── investigation/          # Multi-signal DNS & HTTP analyzer
│   ├── enrichment/             # Screenshots, WHOIS/RDAP, and pHash similarity
│   ├── scoring/                # Transparent risk scoring engine (LOW/MED/HIGH)
│   ├── simulation/             # Pre-built realistic demo scenarios
│   ├── reporting/              # ReportLab & Jinja2 PDF generators
│   ├── alerts/                 # Notification providers and delivery helpers
│   └── storage/                # SQLite SQLAlchemy engine and models
└── tests/                      # Full automated test suite (pytest)
```

---

## ⚙️ Configuration (`.env`)

```dotenv
# Embedded SQLite Database (Default - No setup required)
DATABASE_URL=sqlite:///data/phishing_detector.db

# CertStream WebSocket Endpoint
CERTSTREAM_URL=wss://certstream.calidog.io/
```

---

## 🧪 Running Automated Tests

Run the full automated test suite (66+ unit and integration tests):
```bash
pytest
```
