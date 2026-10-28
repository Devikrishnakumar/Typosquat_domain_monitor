# Backup & Recovery Guide — Fake Website Detector (Typosquad)

## 1. Database Backup (PostgreSQL)

To create a consistent snapshot of candidate records, investigations, risk assessments, and brand configurations:

### Automated Backup Script
```bash
# In Linux/macOS
docker exec -t fake-website-detector-db pg_dump -U typosquat_user -d typosquat -F c -b -v -f /tmp/backup.dump
docker cp fake-website-detector-db:/tmp/backup.dump ./backups/typosquat_$(date +%Y%m%d_%H%M%S).dump

# In Windows PowerShell
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
docker exec -t fake-website-detector-db pg_dump -U typosquat_user -d typosquat -F c -b -v -f "/tmp/backup.dump"
docker cp fake-website-detector-db:/tmp/backup.dump ".\backups\typosquat_$timestamp.dump"
```

---

## 2. Evidence & Report Storage Backup

Evidence files, screenshots, and generated takedown PDF reports are stored in:
- `data/screenshots/`
- `reports/`

Backup using tar or standard volume snapshots:
```bash
tar -czvf evidence_backup_$(date +%Y%m%d).tar.gz ./data ./reports
```

---

## 3. Database Restoration Procedure

To restore from an existing `.dump` archive:

1. **Stop Application Services:**
   ```bash
   docker compose stop monitor-worker dashboard api
   ```

2. **Restore PostgreSQL Dump:**
   ```bash
   docker cp ./backups/your_backup.dump fake-website-detector-db:/tmp/restore.dump
   docker exec -t fake-website-detector-db pg_restore -U typosquat_user -d typosquat -c -v /tmp/restore.dump
   ```

3. **Run Alembic Migrations (if schema changes exist):**
   ```bash
   docker compose run --rm db-init
   ```

4. **Restart Services:**
   ```bash
   docker compose start monitor-worker dashboard api
   ```

5. **Verify Health:**
   Check `http://localhost:8000/api/v1/health/system` or inspect the **Operations & Health** page in the Streamlit dashboard.
