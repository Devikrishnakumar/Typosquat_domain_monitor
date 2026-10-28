# REST API Specification — Fake Website Detector (Typosquad)

FastAPI provides an OpenAPI 3.1 compliant REST API.
Interactive Swagger documentation is available at `http://localhost:8000/docs` and ReDoc at `http://localhost:8000/redoc`.

---

## Base URL
```
http://localhost:8000/api/v1
```

## Authentication & Headers
Protected endpoints require an `Authorization` header containing a valid JWT token:
```
Authorization: Bearer <access_token>
```

---

## 1. Authentication Endpoints

### `POST /auth/register`
Creates an organization and administrator account.
- **Request Body:**
  ```json
  {
    "email": "analyst@brand.example",
    "password": "SecurePassword123!",
    "full_name": "Security Analyst",
    "organization_name": "Acme Brand Corp",
    "role": "analyst"
  }
  ```
- **Response (200 OK):**
  ```json
  {
    "access_token": "eyJhbGciOi...",
    "token_type": "bearer",
    "user": {
      "id": 1,
      "email": "analyst@brand.example",
      "organization_id": 1,
      "role": "analyst"
    }
  }
  ```

### `POST /auth/login`
Authenticates a user and returns a session JWT.
- **Request Body:**
  ```json
  {
    "email": "analyst@brand.example",
    "password": "SecurePassword123!"
  }
  ```

### `GET /auth/me`
Returns current authenticated user details.

---

## 2. Brand Management Endpoints

### `GET /brands`
Lists all monitored brands configured for the authenticated organization.

### `POST /brands`
Creates or updates a brand monitoring profile.
- **Request Body:**
  ```json
  {
    "name": "PayPal",
    "official_domain": "paypal.com",
    "official_website_url": "https://www.paypal.com",
    "keywords": ["paypal", "payment", "checkout"],
    "monitoring_enabled": true,
    "check_interval_minutes": 5,
    "alert_threshold": 70,
    "telegram_alerts_enabled": true,
    "email_alerts_enabled": false,
    "email_recipients": []
  }
  ```

### `POST /brands/{brand_id}/approved-domains`
Adds an approved legitimate domain or CDN to prevent false-positive alerts.
- **Request Body:**
  ```json
  {
    "domain": "paypal-objects.com",
    "notes": "Official static asset CDN"
  }
  ```

### `GET /brands/{brand_id}/approved-domains`
Lists approved legitimate domains for a brand.

---

## 3. Candidate Domain & Triage Endpoints

### `GET /candidates`
Lists candidate impersonation domains with optional filtering.
- **Query Parameters:**
  - `brand_id` (int): Filter by brand.
  - `min_risk` (float): Minimum risk score.
  - `severity` (string): `LOW`, `MEDIUM`, `HIGH`, `CRITICAL`.
  - `status` (string): `new`, `under_investigation`, `false_positive`, `resolved`, `takedown_requested`.
  - `search` (string): Hostname or brand search.

### `GET /candidates/{candidate_id}`
Returns full detail for a candidate domain, including DNS records, TLS certificates, and evidence status.

### `POST /candidates/{candidate_id}/review`
Updates analyst review status and case notes.
- **Request Body:**
  ```json
  {
    "status": "under_investigation",
    "analyst_notes": "Identified active credential harvesting form. Takedown requested from registrar."
  }
  ```

---

## 4. Historical Discovery Endpoints

### `POST /discovery/historical`
Triggers an on-demand historical Certificate Transparency discovery query.
- **Request Body:**
  ```json
  {
    "brand_id": 1,
    "max_results": 50
  }
  ```
- **Response (200 OK):**
  ```json
  {
    "job_id": 12,
    "status": "completed",
    "source": "crt.sh",
    "discovered_count": 8,
    "total_queried": 50
  }
  ```

### `GET /discovery/sources`
Returns supported historical and live discovery sources with their coverage and limitations.

---

## 5. Domain Investigation & Risk Endpoints

### `POST /investigation/run`
Executes an immediate multi-signal investigation against a candidate domain.
- **Request Body:**
  ```json
  {
    "candidate_id": 42
  }
  ```

---

## 6. Alerts & Telemetry Endpoints

### `GET /alerts`
Lists past alert delivery attempts, status (`sent` or `failed`), and channels.

### `POST /alerts/test`
Sends a test alert payload to verify Telegram or Email delivery.
- **Request Body:**
  ```json
  {
    "channel": "telegram"
  }
  ```

### `GET /health/system`
Returns system status and database connectivity.
