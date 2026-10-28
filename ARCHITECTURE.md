# Architecture Specification — Fake Website Detector (Typosquad)

## 1. System Overview

**Fake Website Detector (Typosquad)** is a modular, event-driven cybersecurity system designed to detect, analyze, triage, and alert on fraudulent lookalike websites impersonating corporate brands.

```
+----------------------------------------------------------------------------------------+
|                                    DATA INGESTION                                      |
|                                                                                        |
|  [CertStream Server (Go)]              [crt.sh Historical CT]        [Threat Adapters] |
|              |                                     |                        |          |
+--------------|-------------------------------------|------------------------|----------+
               | (WebSocket Stream)                  | (HTTP JSON)            |
               v                                     v                        v
+----------------------------------------------------------------------------------------+
|                           DOMAIN NORMALIZATION & RECOGNITION                           |
|                                                                                        |
|  [Domain Normalizer & PSL Parser (tldextract)]                                         |
|  - Case / trailing dot removal                                                         |
|  - IDN / Punycode decoding (UTS46 / IDNA2008)                                          |
|  - Public Suffix List registered domain extraction                                     |
|  - Official Brand & Approved Allowlist Exclusions                                      |
|  - dnstwist Homoglyph & Typosquat Permutation Matching                                 |
+----------------------------------------------------------------------------------------+
                                         |
                                         v
+----------------------------------------------------------------------------------------+
|                             PERSISTENCE & SCHEDULING (PostgreSQL)                      |
|                                                                                        |
|  [SQLAlchemy 2.0 Models & Alembic Migrations]                                          |
|  - Organizations, Users, Brands, ApprovedDomains                                       |
|  - Candidates, DiscoveryObservations, DomainInvestigations                              |
|  - DnsObservations, CertificateObservations, RiskAssessments, AlertRecords              |
+----------------------------------------------------------------------------------------+
                                         |
                                         v
+----------------------------------------------------------------------------------------+
|                               INVESTIGATION ENGINE                                     |
|                                                                                        |
|  [DNS Prober]         [TLS Certificate Prober]    [HTTP / SSRF Guard]   [Browser Page]  |
|  - A, AAAA, CNAME,    - X.509 Subject & Issuer     - Redirect chain     - Title & text  |
|    MX, NS records     - Validity & SANs            - Final hostname     - Password form |
|  [WHOIS / RDAP]       - Fingerprint (SHA-256)      - HTTP Status code   - Screenshot    |
+----------------------------------------------------------------------------------------+
                                         |
                                         v
+----------------------------------------------------------------------------------------+
|                              RISK SCORING & CLASSIFICATION                             |
|                                                                                        |
|  [EnterpriseRiskEngine]                                                                |
|  - Domain Similarity (0-20 pts)                                                        |
|  - Liveness & Reachability (0-15 pts)                                                  |
|  - Visual Perceptual Similarity (0-25 pts)                                             |
|  - Credential Form Harvesting (0-25 pts)                                               |
|  - Suspicious Text Content (0-10 pts)                                                  |
|  - Domain Registration Age (0-5 pts)                                                   |
|  --> Output: 0-100 Score, Severity (CRITICAL/HIGH/MEDIUM/LOW), Confidence, Action      |
+----------------------------------------------------------------------------------------+
                                         |
                       +-----------------+-----------------+
                       |                                   |
                       v                                   v
+---------------------------------------+ +---------------------------------------+
|          NOTIFICATION SUBSYSTEM       | |         PRESENTATION SUBSYSTEM        |
|                                       | |                                       |
|  [NotificationManager]                | |  [FastAPI Backend (Port 8000)]        |
|  - Telegram Bot API (Markdown alerts) | |  - OpenAPI / Swagger documentation    |
|  - Extensible SMTP Email provider     | |  - JWT Auth & Multi-tenant RBAC       |
|  - Deduplication & Delivery Tracking  | |  [Streamlit Dashboard (Port 8501)]    |
|  - Automated Retry with Backoff       | |  - Triage UI & CSV / PDF Export       |
+---------------------------------------+ +---------------------------------------+
```

## 2. Core Modules

| Module | Location | Purpose |
|---|---|---|
| **Storage Engine** | `src/storage/` | PostgreSQL relational schema (`models.py`) and migration management (`alembic`). Preserves backwards-compatible Candidate APIs in `db.py`. |
| **Domain Normalizer** | `src/normalization/` | RFC-compliant hostname syntax checking, IDN/punycode decoding, PSL extraction, and brand allowlist exclusion. |
| **Historical Discovery** | `src/discovery/` | Pluggable Certificate Transparency provider engine (`CrtShProvider`, `MockHistoricalProvider`) with rate limiting and pagination. |
| **Investigation Engine** | `src/investigation/` | Bounded probing of DNS records, TLS certificates, HTTP/HTTPS redirect chains, RDAP registration, and Playwright screenshots. |
| **Risk Engine** | `src/scoring/` | Multi-signal transparent evaluation generating 0-100 scores, 4 severity bands, confidence ratings, and analyst action recommendations. |
| **Alerting Subsystem** | `src/alerts/` | Telegram and Email dispatchers with deduplication and delivery audit logging. |
| **REST API** | `src/api/` | FastAPI enterprise application providing complete REST CRUD for brands, candidates, investigations, and health. |
| **Analyst Dashboard** | `dashboard/app.py` | Responsive Streamlit UI providing overview telemetry, domain explorer, historical discovery, brand management, and report downloads. |
