#!/usr/bin/env bash
#
# Pull current code, rebuild the production stack, and wait for health.

set -euo pipefail

COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.production.yml}"
APP_ENV_FILE="${APP_ENV_FILE:-.env}"
HEALTH_WAIT_SECONDS="${HEALTH_WAIT_SECONDS:-180}"
APP_CONTAINER="${APP_CONTAINER:-phishing-orchestrator}"
TUNNEL_CONTAINER="${TUNNEL_CONTAINER:-cloudflared-tunnel}"
REQUIRE_TUNNEL="${REQUIRE_TUNNEL:-1}"
TUNNEL_STABLE_SECONDS="${TUNNEL_STABLE_SECONDS:-10}"

export APP_ENV_FILE

if ! command -v docker >/dev/null 2>&1; then
    echo "[deploy] docker CLI not found" >&2
    exit 1
fi

if [ ! -f "$COMPOSE_FILE" ]; then
    echo "[deploy] compose file not found: $COMPOSE_FILE" >&2
    exit 1
fi

if [ ! -f "$APP_ENV_FILE" ]; then
    echo "[deploy] env file not found: $APP_ENV_FILE" >&2
    exit 1
fi

compose() {
    docker compose --env-file "$APP_ENV_FILE" -f "$COMPOSE_FILE" "$@"
}

if [ "$REQUIRE_TUNNEL" = "1" ] \
    && [ -z "${CLOUDFLARE_TUNNEL_TOKEN:-}" ] \
    && ! grep -q '^CLOUDFLARE_TUNNEL_TOKEN=.' "$APP_ENV_FILE" 2>/dev/null; then
    echo "[deploy] CLOUDFLARE_TUNNEL_TOKEN is required for production tunnel deploys" >&2
    exit 1
fi

if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git pull --ff-only
    export APP_BUILD_SHA="${APP_BUILD_SHA:-$(git rev-parse --short=12 HEAD)}"
else
    export APP_BUILD_SHA="${APP_BUILD_SHA:-unknown}"
fi

compose pull browser-sandbox cloudflared || true
compose up -d --build --remove-orphans

deadline=$((SECONDS + HEALTH_WAIT_SECONDS))
while [ "$SECONDS" -lt "$deadline" ]; do
    health="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$APP_CONTAINER" 2>/dev/null || true)"
    if [ "$health" = "healthy" ]; then
        if [ "$REQUIRE_TUNNEL" != "1" ]; then
            compose ps
            echo "[deploy] $APP_CONTAINER is healthy"
            exit 0
        fi

        tunnel_status="$(docker inspect --format '{{.State.Status}}' "$TUNNEL_CONTAINER" 2>/dev/null || true)"
        if [ "$tunnel_status" = "running" ]; then
            sleep "$TUNNEL_STABLE_SECONDS"
            tunnel_status="$(docker inspect --format '{{.State.Status}}' "$TUNNEL_CONTAINER" 2>/dev/null || true)"
            if [ "$tunnel_status" = "running" ]; then
                compose ps
                echo "[deploy] $APP_CONTAINER is healthy and $TUNNEL_CONTAINER is running"
                exit 0
            fi
        fi
    fi
    sleep 5
done

compose ps >&2 || true
docker logs "$APP_CONTAINER" --tail 120 >&2 || true
if [ "$REQUIRE_TUNNEL" = "1" ]; then
    docker logs "$TUNNEL_CONTAINER" --tail 120 >&2 || true
    tunnel_status="$(docker inspect --format '{{.State.Status}}' "$TUNNEL_CONTAINER" 2>/dev/null || true)"
    echo "[deploy] $APP_CONTAINER health=$health; $TUNNEL_CONTAINER status=${tunnel_status:-missing}" >&2
fi
echo "[deploy] production stack did not become ready within ${HEALTH_WAIT_SECONDS}s" >&2
exit 1
