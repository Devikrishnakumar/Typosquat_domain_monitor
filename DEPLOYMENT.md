# Deployment & Security Guide — Fake Website Detector (Typosquad)

## 1. Production Deployment Topology

The recommended production deployment topology isolates the untrusted web probe worker and browser runner while placing public interfaces behind a secure reverse proxy with TLS termination.

```
                           +----------------------+
                           |   Internet Ingress   |
                           +----------------------+
                                      |
                     TLS / 443        |
                                      v
                      +-------------------------------+
                      |   Reverse Proxy (Nginx/Caddy) |
                      |   - TLS Termination (Certbot) |
                      |   - Rate Limiting             |
                      |   - Basic / OAuth Auth Gate   |
                      +-------------------------------+
                                      |
                 +--------------------+--------------------+
                 |                                         |
     Proxy to 127.0.0.1:8501                   Proxy to 127.0.0.1:8000
                 |                                         |
                 v                                         v
   +---------------------------+             +---------------------------+
   | Streamlit Dashboard       |             | FastAPI Backend           |
   | Container                 |             | Container                 |
   +---------------------------+             +---------------------------+
                 |                                         |
                 +--------------------+--------------------+
                                      |
                                      v
                      +-------------------------------+
                      | Internal Docker Network       |
                      | - PostgreSQL (Port 5432)      |
                      | - Monitoring Worker           |
                      | - CertStream Go Server (8081) |
                      +-------------------------------+
```

---

## 2. Security Hardening Checklist

1. **Database Secrets:**
   - Always change default database credentials in `.env`.
   - Never expose PostgreSQL (port 5432) on public network interfaces.
2. **SSRF Protections:**
   - `src/enrichment/network_safety.py` validates that all HTTP and Playwright requests resolve only to globally routable IP addresses.
   - Non-routable and private address spaces (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8, 169.254.0.0/16) are rejected before socket connection.
3. **HTTP Security Headers:**
   - `src/api/main.py` enforces:
     - `X-Content-Type-Options: nosniff`
     - `X-Frame-Options: DENY`
     - `X-XSS-Protection: 1; mode=block`
     - `Strict-Transport-Security: max-age=31536000; includeSubDomains`
4. **JWT Secret:**
   - Generate a strong random 256-bit string for `JWT_SECRET` in `.env`:
     ```bash
     openssl rand -hex 32
     ```

---

## 3. Reverse Proxy Configuration (Nginx Example)

```nginx
server {
    listen 80;
    server_name detector.yourdomain.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name detector.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/detector.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/detector.yourdomain.com/privkey.pem;

    # Streamlit Analyst Dashboard
    location / {
        proxy_pass http://127.0.0.1:8501;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # FastAPI REST Backend
    location /api/ {
        proxy_pass http://127.0.0.1:8000/api/;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

---

## 4. Resource Allocation & Limits

Recommended minimum container resource limits:
- **PostgreSQL:** 1 CPU, 2 GB RAM, 20 GB SSD volume
- **Monitor Worker:** 2 CPU, 4 GB RAM (supports headless browser execution)
- **FastAPI Backend:** 1 CPU, 1 GB RAM
- **Streamlit Dashboard:** 1 CPU, 1 GB RAM
