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

Add the Cloudflare tunnel token:
```bash
echo "CLOUDFLARE_TUNNEL_TOKEN=eyJ..." >> .env
```

## Step 3: Deploy

```bash
docker compose -f docker-compose.production.yml up -d --build
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

Visit your domain. You should see the dashboard.
Use `/login` with `ANALYST_API_TOKEN` for browser access.

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
git pull
docker compose -f docker-compose.production.yml up -d --build
```

The `--build` flag rebuilds the image with the new code.
The tunnel reconnects automatically.

## Troubleshooting

**Tunnel won't connect:**
```bash
docker logs cloudflared-tunnel
```
Usually a bad token. Regenerate in the Cloudflare dashboard.

**App unhealthy:**
```bash
docker logs phishing-orchestrator --tail 50
```
Check that .env exists and has the required ANALYST_API_TOKEN.

**Cloudflare shows 502:**
The app hasn't started yet (15s start period) or crashed. Check orchestrator logs.

**From Tailscale:**
You can still access the app directly via Tailscale IP at port 8000
if you add `ports: ["8000:8000"]` back to the orchestrator service
in docker-compose.production.yml. Useful for debugging without
going through the tunnel.
