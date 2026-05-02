# Deploying to a Self-Hosted Machine via Cloudflare Tunnel

This guide deploys the phishing detection pipeline on a 24/7 machine
behind Cloudflare Tunnel. No ports are opened on the host. All public
traffic routes through Cloudflare's edge network with automatic HTTPS.

## Prerequisites

On the deployment machine:
- Docker and Docker Compose (v2)
- Git
- A Cloudflare account (free tier is fine)
- Your domain (e.g. mdpstudio.com.au) with DNS on Cloudflare

## Step 1: Create the Cloudflare Tunnel

1. Log in to https://one.dash.cloudflare.com
2. Go to **Networks > Tunnels > Create a tunnel**
3. Choose **Cloudflared** connector
4. Name it something like `phishing-detector`
5. Copy the tunnel token (starts with `eyJ...`)
6. Under **Public Hostnames**, add a route:
   - Subdomain: whatever you want (e.g. `detect.mdpstudio.com.au` or just `mdpstudio.com.au`)
   - Service: `http://orchestrator:8000`
   
   The service URL uses the Docker container name because cloudflared
   runs in the same Docker network as the app.

## Step 2: Clone and Configure

```bash
git clone https://github.com/meidielo/Automated-Phishing-Detection.git
cd Automated-Phishing-Detection

# Copy the production env template
cp .env.production .env

# Edit .env -- fill in your API keys
nano .env
```

At minimum, fill in:
- `VIRUSTOTAL_API_KEY`
- `ANTHROPIC_API_KEY`
- `GOOGLE_SAFE_BROWSING_API_KEY`
- `ANALYST_API_TOKEN` (generate one: `python3 -c "import secrets; print(secrets.token_urlsafe(32))"`)
- `SAAS_SESSION_SECRET` (generate separately: `python3 -c "import secrets; print(secrets.token_urlsafe(48))"`)
- `ACCOUNTS_ENCRYPTION_KEY` if you will store monitored mailbox credentials
  (generate separately: `python3 -c "import secrets; print(secrets.token_urlsafe(48))"`).
  Set this before adding accounts and keep it stable across rebuilds. If it is
  missing or changed, previously saved mailbox passwords cannot be decrypted
  and those mailboxes must be reconnected.
  When the monitor shows `Reconnect account`, keep the key as-is and re-enter
  the mailbox app password once from `/monitor`; adding the same email replaces
  the stale encrypted credential.

Optional public preview:
- Set `PUBLIC_DEMO_MODE=true` only if you want `/demo` to be reachable without login. It is sample-only: it does not expose live upload analysis, mailbox monitoring, paid API-backed checks, feedback learning, dashboard data, or account management.
- `/api/demo/plans` is also public in demo mode. It exposes non-secret plan and lock metadata only, so visitors can see which analyzers require Starter, Pro, or Business.
- Leave `SAAS_PUBLIC_SIGNUP_ENABLED=false` until the deployment is ready to accept visitor email uploads. `/app` and `/api/saas/*` support normal user accounts, tenant-scoped scan storage, and free-tier quota gates, but public signup is an explicit deployment decision.

Stripe subscription setup:
- Set `PUBLIC_BASE_URL` to the public HTTPS origin, for example `https://phishanalyze.mdpstudio.com.au`.
- Set `STRIPE_SECRET_KEY` and `STRIPE_PRICE_STARTER` / `STRIPE_PRICE_PRO` / `STRIPE_PRICE_BUSINESS`.
- Register `https://your-domain/api/stripe/webhook` in Stripe for `checkout.session.completed` and `customer.subscription.*`, then set `STRIPE_WEBHOOK_SECRET`.
- Checkout and Customer Portal stay unavailable if required Stripe env vars are missing or Stripe rejects the runtime secret key.

Avoid `$` in `.env` values unless you know how to escape Docker Compose
interpolation. If `docker compose config` prints warnings about a variable that
looks like part of a secret, regenerate that secret with `secrets.token_urlsafe`
or quote/escape it before deploying.

Add the Cloudflare tunnel token:
```bash
echo "CLOUDFLARE_TUNNEL_TOKEN=eyJ..." >> .env
```

## Step 3: Deploy

```bash
bash scripts/docker_deploy.sh
```

Check it's healthy:
```bash
docker compose -f docker-compose.production.yml ps
# cloudflared, orchestrator, and browser-sandbox should show "running";
# orchestrator should become healthy.

# Test locally
docker exec phishing-orchestrator python -c \
  "import urllib.request; print(urllib.request.urlopen('http://localhost:8000/api/health').read())"
```

Visit your domain. You should see the login page for the dashboard.
Use `/login` with `ANALYST_API_TOKEN` for browser access.
If `PUBLIC_DEMO_MODE=true`, `/demo` is the only public sample page.

The production stack also binds `127.0.0.1:8000:8000` on the host. This is
only for SSH/cron health probes on the deployment machine; it is not exposed on
the public interface or the Tailscale IP.

## Step 4: Verify API Keys Work

SSH into the machine (or use Tailscale) and run:
```bash
docker exec -it phishing-orchestrator python -c "
import os
keys = {
    'VirusTotal': 'VIRUSTOTAL_API_KEY',
    'Google Safe Browsing': 'GOOGLE_SAFE_BROWSING_API_KEY',
    'URLScan': 'URLSCAN_API_KEY',
    'AbuseIPDB': 'ABUSEIPDB_API_KEY',
    'Anthropic': 'ANTHROPIC_API_KEY',
    'Hybrid Analysis': 'HYBRID_ANALYSIS_API_KEY',
}
for name, env_var in keys.items():
    status = 'OK' if os.environ.get(env_var) else 'MISSING (analyzer will abstain)'
    print(f'  {name}: {status}')
"
```

## Updating

```bash
cd Automated-Phishing-Detection
bash scripts/docker_deploy.sh
```

The deploy script fast-forwards git, rebuilds the app image with the new code,
pulls the browser/tunnel images when possible, removes orphaned old containers,
injects the current git SHA into the image for `/api/health` and static asset
cache busting, requires `CLOUDFLARE_TUNNEL_TOKEN` for the production tunnel,
and waits for the orchestrator container to become healthy plus
`cloudflared-tunnel` to stay running.

After deploy, confirm the active build:

```bash
curl -s https://phishanalyze.mdpstudio.com.au/api/health
```

The `build_sha` value should match `git rev-parse --short=12 HEAD`.

## Operations

After deployment, follow `docs/production-operations.md` for backups,
retention, log rotation, uptime checks, alerting, and load/error probes.

## Troubleshooting

**Tunnel won't connect:**
```bash
docker logs cloudflared-tunnel
```
Usually a missing or bad `CLOUDFLARE_TUNNEL_TOKEN`. The deploy script now
fails before recreating containers if the token is missing from `.env` and
prints recent tunnel logs if the tunnel keeps restarting.

**App unhealthy:**
```bash
docker logs phishing-orchestrator --tail 50
bash scripts/docker_self_heal.sh
```
Check that `.env` exists and has the required `ANALYST_API_TOKEN`. If the app
stays unhealthy after self-heal, rebuild with `bash scripts/docker_deploy.sh`.

**URL detonation reports Playwright version mismatch:**
Run `bash scripts/docker_deploy.sh` so the browser sandbox is recreated from
the checked-in Compose file. Compose pins `npx playwright@... run-server` to the
same version as the Python client in `requirements.lock`; `pytest
tests/unit/test_docker_playwright_version.py` catches drift before deploy.

**Cloudflare shows 502:**
The app has not finished its startup health window yet or crashed. Check
orchestrator logs.

**From Tailscale:**
The production compose file only publishes the app on host loopback:
`http://127.0.0.1:8000`. To debug from another machine, SSH into the host or use
Cloudflare Tunnel rather than exposing port 8000 directly.
