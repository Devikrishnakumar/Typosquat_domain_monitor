# Development Roadmap & Feature Audit — Fake Website Detector (Typosquad)

## 1. Implemented Features

### Enterprise Data & Ingestion Architecture
- **Multi-Brand Relational Architecture:** Full PostgreSQL data models for Organizations, Users, Brands, ApprovedDomains, Candidates, DiscoveryObservations, DomainInvestigations, DnsObservations, CertificateObservations, RiskAssessments, AlertRecords, MonitoringJobs, and AuditLogs.
- **Versioned Alembic Migrations:** Production-ready migrations (`001_initial_enterprise_schema.py`) supporting upgrades and downgrades with zero breaking changes to existing data.
- **Continuous CT Stream Listening:** Persistent WebSocket worker connecting to CertStream, with bounded concurrency, heartbeat telemetry, and reconnect backoff.
- **Historical Certificate Transparency Discovery:** Search engine leveraging `crt.sh` with source attribution, pagination, rate-limit resilience, and separate `observed_at` vs `imported_at` tracking.

### Domain Normalization & Investigation Engine
- **Public Suffix List Extraction:** Maintained PSL parser (`tldextract`) separating registered domains from hostnames and subdomains.
- **IDN / Punycode Support:** Full UTS46 & IDNA2008 decoding and encoding.
- **Multi-Signal Investigation:**
  - DNS resolution across A, AAAA, CNAME, MX, and NS records with error capture.
  - HTTP/HTTPS probing with redirect chain capture, final hostname, latency, and status code.
  - X.509 TLS certificate probing with subject, issuer, validity period, SANs, and SHA-256 fingerprinting.
  - RDAP / WHOIS lookup for domain creation date and registrar information.
  - Content analysis detecting password inputs and credential harvesting forms.
  - Perceptual visual similarity using perceptual image hashing against authentic brand screenshots.
- **Strict SSRF Defenses:** Enforces that web probes resolve only to globally routable IP addresses, rejecting private networks and loopbacks.

### Risk Scoring & Classification
- **Transparent Multi-Signal Engine (`EnterpriseRiskEngine`):** Combines domain similarity, DNS/HTTPS reachability, visual similarity, login form detection, suspicious keyword phrases, and domain registration age into a 0–100 score.
- **Severity Bands:**
  - `CRITICAL`: 80–100
  - `HIGH`: 60–79
  - `MEDIUM`: 30–59
  - `LOW`: 0–29
- **Confidence Levels:** `LOW`, `MEDIUM`, `HIGH`, `CONFIRMED`.
- **Explanatory Evidence:** Outputs detailed breakdown, supporting reasons, missing evidence warnings, and recommended analyst triage actions.

### Alerting & Notifications
- **Telegram Bot API Integration:** Rich Markdown alerts with deep links to case findings.
- **Extensible Email Channel:** SMTP delivery and mock provider simulation.
- **Intelligent Deduplication:** Prevents repeated alerts for the same logical event and records delivery audit trails in database.

### Interfaces & Deployment
- **FastAPI REST Backend:** Documented OpenAPI / Swagger interface (`/docs`) with JWT authentication, role-based access control, and organization isolation.
- **Streamlit Analyst Dashboard:**
  - **Overview:** Real-time metrics for total candidates, new discoveries, severe findings, historical archives, pending investigations, alert delivery, and worker health.
  - **Domain Explorer:** Multiselect risk filters, hostname search, case details, review actions, and CSV export.
  - **Historical Monitoring:** On-demand crt.sh discovery queries, findings archive, and coverage explanations.
  - **Brand Management:** Brand configuration, keyword management, notification threshold tuning, and approved allowlist domains.
  - **Operations & Health:** Live engine telemetry, monitoring job execution history, alert dispatch audit, and test alert trigger.
  - **Simulation & Reports:** Isolated simulation page and downloadable PDF takedown reports.
- **Docker Compose:** Multi-service orchestration including Database, CertStream, Worker, API, Dashboard, and Simulation Site.

---

## 2. Tested & Verified Areas
1. Brand configuration validation
2. Domain normalization and internationalized domains (IDN)
3. Official-domain and approved-domain exclusion
4. Historical source ingestion (crt.sh / CT)
5. Live discovery event processing
6. Database persistence and query helpers
7. Duplicate-event handling
8. Risk scoring, severity bands, and evidence explanations
9. Investigation timeouts and failure handling
10. Alert creation and delivery retries
11. Worker restart recovery and telemetry
12. Authentication, JWT session management, and organization isolation
13. API validation and authorization
14. Dashboard data loading and aggregation
15. Database migrations and schema rollback

---

## 3. Remaining Limitations & Operational Recommendations

1. **Third-Party Rate Limits (`crt.sh`):**
   - Public crt.sh can enforce temporary rate limits during aggressive search bursts. Operational deployments should cache results and utilize multiple provider adapters if available.
2. **Headless Browser Resource Footprint:**
   - Playwright Chromium execution requires sufficient memory (minimum 2 GB per worker container). In large-scale deployments, browser rendering should be distributed across disposable worker nodes.
3. **Analyst Review Mandatory:**
   - In accordance with cybersecurity best practices, risk scores are heuristic triage signals. No automated domain takedown should be executed without human verification.
