# Production Operations Runbook

This is the operating checklist for a 24/7 self-hosted deployment. It assumes
Docker Compose, Cloudflare Tunnel, and an analyst token in `.env`.

## Backup Runtime Data

Create a non-secret backup of analysis artifacts:

```bash
python scripts/backup_runtime_data.py --destination backups --retention-days 14
```

Backed up by default:
- `data/results.jsonl`
- `data/alerts.jsonl`
- `data/feedback.db`
- `data/sender_profiles.db`

Credentials are excluded by default. If you must back up account tokens, run:

```bash
python scripts/backup_runtime_data.py --include-secrets --destination backups
```

Store secret backups encrypted and off the host. Do not commit `backups/`.

Recommended cron:

```cron
17 2 * * * cd /srv/Automated-Phishing-Detection && /usr/bin/python3 scripts/backup_runtime_data.py --destination backups --retention-days 14 >> logs/backup.log 2>&1
```

## Log Rotation

Docker JSON logs are capped in `docker-compose.production.yml`:

```yaml
logging:
  driver: "json-file"
  options:
    max-size: "10m"
    max-file: "3"
```

Host-side script logs should rotate with logrotate:

```conf
/srv/Automated-Phishing-Detection/logs/*.log {
  daily
  rotate 14
  compress
  missingok
  notifempty
  copytruncate
}
```

## Uptime And Alerts

Health probe:

```bash
python scripts/production_health_check.py \
  --base-url https://detect.example.com \
  --token "$ANALYST_API_TOKEN" \
  --require-monitor-running \
  --alert-webhook "$ALERT_WEBHOOK_URL"
```

The script exits `0` when healthy and `2` when it should alert. It checks:
- `/api/health`
- `/api/monitor/stats`
- monitor running state when requested
- monitor error count
- last poll freshness

Recommended cron:

```cron
*/5 * * * * cd /srv/Automated-Phishing-Detection && /usr/bin/python3 scripts/production_health_check.py --base-url https://detect.example.com --token "$ANALYST_API_TOKEN" --require-monitor-running --alert-webhook "$ALERT_WEBHOOK_URL" >> logs/health.log 2>&1
```

Cloudflare or another uptime monitor should also hit `/api/health` every
minute from outside the host.

## Runtime Retention

Default retention is 30 days through `DATA_RETENTION_DAYS`. Run:

```bash
python main.py purge --target all
```

For a data subject erasure:

```bash
python main.py purge --target all --by-address person@example.com
```

Run daily in production:

```cron
37 2 * * * cd /srv/Automated-Phishing-Detection && /usr/bin/python3 main.py purge --target all >> logs/retention.log 2>&1
```

## Auth And Session Checks

Production must set a high-entropy analyst token:

```bash
python3 -c "import secrets; print(secrets.token_urlsafe(32))"
```

Use `/login` for browser sessions. API clients should use
`Authorization: Bearer $ANALYST_API_TOKEN`.

Operational checks:
- Rotate `ANALYST_API_TOKEN` if it has been shared in chat, logs, or tickets.
- Keep Cloudflare Access or Tailscale in front of the dashboard for demos.
- If `PUBLIC_DEMO_MODE=true`, verify only `/demo` is public. It must not expose
  live analysis, mailbox data, feedback learning, paid API usage, or account
  management.
- Do not expose port `8000` publicly. The production compose file uses
  a loopback-only host port, `127.0.0.1:8000:8000`, for local health probes.

## Docker Self-Healing

Docker restart policies do not restart a container that is still running but
marked `unhealthy`. Run the host-level self-heal script from cron so unhealthy
containers are restarted without mounting the Docker socket into a privileged
helper container:

```cron
* * * * * cd /srv/Automated-Phishing-Detection && /usr/bin/bash scripts/docker_self_heal.sh >> logs/docker-self-heal.log 2>&1
```

For code updates, use:

```bash
bash scripts/docker_deploy.sh
```

That script fast-forwards git, rebuilds the production stack, removes orphaned
old containers, and waits for `phishing-orchestrator` to become healthy.

## Load And Error Probe

Run a short probe against a deployment with the mailbox monitor enabled:

```bash
python scripts/monitor_load_test.py \
  --base-url https://detect.example.com \
  --token "$ANALYST_API_TOKEN" \
  --duration-seconds 60 \
  --concurrency 8 \
  --require-monitor-running
```

This repeatedly checks health, monitor stats, and recent compact logs. It does
not fetch mailbox contents itself, so it is safe to run against production.
