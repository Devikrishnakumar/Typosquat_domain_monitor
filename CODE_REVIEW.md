# Code review and bug fixes

Reviewed on 29 October 2026. Scope: both Streamlit entry points, API/authentication, storage, ingestion workers, enrichment, risk scoring, reports, the packaged table/radar component, the landing server, and the standalone React hero frontend.

## Fixed findings

| Area | Bug | Result |
| --- | --- | --- |
| Authentication | Missing bearer tokens silently became an administrator, including automatic account creation. | Protected API endpoints return 401 without a valid token. |
| Authentication | Passlib's bcrypt backend crashed registration with the installed bcrypt version. | New passwords use PBKDF2-SHA256 with 600,000 rounds; existing bcrypt hashes remain verifiable. Long new passwords work without truncation. |
| Authentication | JWT signing used a known hard-coded fallback secret. | Configured JWT_SECRET is used; an unconfigured local process gets a random secret. |
| Account data | `/auth/me` exposed the stored password hash. | The response is limited to public user fields. |
| Registration | Reusing an organization display name could join an existing tenant. | Signup atomically creates an independent organization. Duplicate emails do not leave orphan organizations. Roles and request limits are validated. |
| API ownership | Candidate details/reviews/investigation, approved domains, discovery, alerts, and jobs could cross tenant boundaries. | Ownership is checked before reads, writes, or network work. Organization-scoped lists exclude unassigned records. Investigation domains must match the selected candidate. |
| Storage | Candidate deduplication ignored organization ownership. | Identical domains in different organizations remain distinct. File-backed SQLite no longer shares a single StaticPool connection across concurrent sessions. |
| Networking | HTTP clients followed redirects without validating the new destination; content retrieval could read unbounded bodies. | Each redirect is validated before requesting it, response size is bounded, and connections are closed. Local investigation targets require an explicit allowlist. |
| TLS evidence | Certificate metadata was read through `getpeercert()` with verification disabled, which can return an empty dictionary. | Metadata is decoded from DER certificate bytes, including subject, issuer, validity, SANs, and serial number. |
| Monitoring | Disabled brands could still be monitored; findings lacked tenant ownership. | Target selection honors monitoring_enabled and propagates ownership. Default brands are attached to a real organization. |
| Monitoring | Certificate events fabricated visual/content scores and reset analyst reviews. | Only observed signals contribute to new certificate-only scores; completed evidence, risk assessments, and review decisions are preserved. |
| Monitoring | Hot reload could spawn additional monitor threads. Windows file locks could interrupt event callbacks. | Process-wide runtime state survives reloads. Atomic file replacement retries transient locks, and display-log failures are contained. |
| Risk scoring | Fractional scores in the gaps immediately below 30, 60, or 80 could become CRITICAL. | Classification follows lower severity thresholds without fractional gaps. |
| Enterprise dashboard | Risk charts referenced undefined variables; unsupported `alt` arguments crashed charts, images, and tables. | Charts derive their counts from records and calls match the installed Streamlit API. |
| Domain Explorer | A duplicate evidence column crashed table serialization; regex characters in search could raise exceptions. | Column names are unique and search uses literal matching. |
| Charts | CRITICAL findings were labeled as unassessed and missing severity was treated as LOW. | CRITICAL has its own category and unassessed findings stay separate. |
| Reports | Unescaped evidence markup could break PDF generation, string email addresses were joined character by character, and CRITICAL used a low-risk banner color. | External text is escaped, string email values stay intact, and CRITICAL uses the high-risk banner. Generated filenames include microseconds. |
| Standalone monitor | A missing Optional import prevented module definition. | Type annotation names resolve correctly. |
| Frontend packaging | Wildcard asset names could match stale bundles retained by Python packaging. | The component loads exact `index.js` and `style.css` assets. Packaging staging directories are excluded from Docker build context. |
| React hero | TypeScript and PostCSS configuration were missing; Tailwind utilities were absent from production CSS. | Added configurations and a dependency lockfile. The production build includes generated utility styles. |
| Dependencies | API tests could not collect because Starlette's TestClient required httpx2. | Added the compatible dependency to requirements. |
| API browser access | Credentialed CORS used a wildcard origin. | Browser origins are configured through CORS_ALLOWED_ORIGINS, with local dashboard origins as defaults. |

## Validation

- Complete Python suite: **98 tests passed**, including 22 added regression tests.
- Both dashboard entry points exercised across every menu destination using Streamlit AppTest, including a populated database and literal `[` search.
- Undefined-name scan passed for application, API, dashboard, worker, landing, simulation, and migration code.
- Python compilation, installed dependency consistency, and Streamlit keyword compatibility checks passed.
- Packaged table/radar frontend: TypeScript checks and production build passed.
- Standalone React hero: TypeScript checks and production build passed; Tailwind CSS is present in the output.
- Browser smoke check: radar movement confirmed, one visual after automatic refresh, table rows rendered, no Streamlit exceptions or JavaScript errors. Mobile viewport had no horizontal overflow.
- PDF regression confirms malformed external text remains printable and string email addresses stay intact.

## Behavior and validation limits

- API clients must now authenticate. Public signup creates a new organization; an organization name is not an invitation to join an existing tenant.
- Set a stable JWT_SECRET for sessions that must survive API restarts or work across API processes. Configure CORS_ALLOWED_ORIGINS for nonlocal browser clients.
- Legacy records without organization ownership remain visible in the local dashboard, but are excluded from tenant API queries. They were not assigned to a tenant automatically.
- Previously stored risk scores were not rewritten. New certificate-only findings no longer invent page evidence.
- Database integration tests used isolated SQLite databases, including migration upgrade/downgrade. A live PostgreSQL/Docker deployment was not exercised.
- Destination checks validate DNS results and each HTTP redirect. DNS rebinding resistance and network-level egress isolation were not established by these tests.
