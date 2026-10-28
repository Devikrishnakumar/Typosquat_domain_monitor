# Troubleshooting Guide — Fake Website Detector (Typosquad)

## Common Issues & Resolutions

### 1. Database Connection Refused (`connection to server at "localhost" port 5432 failed`)
- **Cause:** PostgreSQL container is not started or application is trying to connect to `localhost` rather than container host `db`.
- **Resolution:**
  - In Docker Compose: Ensure services specify `PGHOST: db`.
  - In local development: Start PostgreSQL or run `docker compose up -d db`.

### 2. Worker Health Status Shows "Reconnecting" or "Stale"
- **Cause:** WebSocket connection to CertStream server was interrupted or rate-limited.
- **Resolution:**
  - Verify CertStream container is running:
    ```bash
    docker compose ps certstream-server
    ```
  - Check worker logs:
    ```bash
    docker compose logs -f monitor-worker
    ```
  - The worker automatically applies exponential backoff and reconnects within 1–60 seconds.

### 3. Playwright Screenshot Capture Times Out
- **Cause:** Candidate target site is hanging, throttling connections, or executing infinite redirect loops.
- **Resolution:**
  - The investigation engine enforces strict 8-second request timeouts and 25-second browser timeouts.
  - If a candidate times out, the engine safely marks `evidence_status: partial` or `not_live` without crashing the enrichment worker.

### 4. `crt.sh` Discovery Returns Empty or Rate Limit (429)
- **Cause:** Public `crt.sh` is occasionally saturated or enforcing rate limits on aggressive query bursts.
- **Resolution:**
  - The discovery engine uses automatic retries with backoff.
  - Reduce max search results slider in dashboard (e.g., from 100 to 30).
  - Use specific brand stems rather than broad generic terms.

### 5. Telegram Notifications Not Delivering
- **Cause:** `TELEGRAM_BOT_TOKEN` or `TELEGRAM_CHAT_ID` is missing, invalid, or the bot has not been started by the user in Telegram.
- **Resolution:**
  - Ensure you clicked `/start` in the Telegram chat with your bot.
  - Verify credentials using the Test Alert button on the **Operations & Health** dashboard page or `/api/v1/alerts/test` API endpoint.
