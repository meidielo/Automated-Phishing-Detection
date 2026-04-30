#!/usr/bin/env bash
#
# Pull current code, rebuild the production stack, and wait for health.

set -euo pipefail

COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.production.yml}"
HEALTH_WAIT_SECONDS="${HEALTH_WAIT_SECONDS:-180}"
APP_CONTAINER="${APP_CONTAINER:-phishing-orchestrator}"

if ! command -v docker >/dev/null 2>&1; then
    echo "[deploy] docker CLI not found" >&2
    exit 1
fi

if [ ! -f "$COMPOSE_FILE" ]; then
    echo "[deploy] compose file not found: $COMPOSE_FILE" >&2
    exit 1
fi

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git pull --ff-only
fi

docker compose -f "$COMPOSE_FILE" pull browser-sandbox cloudflared || true
docker compose -f "$COMPOSE_FILE" up -d --build --remove-orphans

deadline=$((SECONDS + HEALTH_WAIT_SECONDS))
while [ "$SECONDS" -lt "$deadline" ]; do
    health="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$APP_CONTAINER" 2>/dev/null || true)"
    if [ "$health" = "healthy" ]; then
        docker compose -f "$COMPOSE_FILE" ps
        echo "[deploy] $APP_CONTAINER is healthy"
        exit 0
    fi
    sleep 5
done

docker compose -f "$COMPOSE_FILE" ps >&2 || true
docker logs "$APP_CONTAINER" --tail 120 >&2 || true
echo "[deploy] $APP_CONTAINER did not become healthy within ${HEALTH_WAIT_SECONDS}s" >&2
exit 1
