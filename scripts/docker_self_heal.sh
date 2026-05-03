#!/usr/bin/env bash
#
# Restart unhealthy or stopped production containers.
#
# Docker's restart policy restarts crashed containers, but it does not restart a
# container that is still running with Health=unhealthy. Run this from host cron
# or systemd, not inside a container, so we do not mount the Docker socket into
# another privileged helper container.

set -euo pipefail

COMPOSE_FILE="${COMPOSE_FILE:-docker-compose.production.yml}"
APP_ENV_FILE="${APP_ENV_FILE:-.env}"
SERVICES=(phishing-browser-sandbox phishing-orchestrator cloudflared-tunnel)

export APP_ENV_FILE

if ! command -v docker >/dev/null 2>&1; then
    echo "[self-heal] docker CLI not found" >&2
    exit 1
fi

if [ ! -f "$COMPOSE_FILE" ]; then
    echo "[self-heal] compose file not found: $COMPOSE_FILE" >&2
    exit 1
fi

if [ ! -f "$APP_ENV_FILE" ]; then
    echo "[self-heal] env file not found: $APP_ENV_FILE" >&2
    exit 1
fi

compose() {
    docker compose --env-file "$APP_ENV_FILE" -f "$COMPOSE_FILE" "$@"
}

changed=0

for container in "${SERVICES[@]}"; do
    if ! docker inspect "$container" >/dev/null 2>&1; then
        echo "[self-heal] missing $container; recreating stack"
        compose up -d --build --remove-orphans
        changed=1
        continue
    fi

    state="$(docker inspect --format '{{.State.Status}}' "$container")"
    health="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$container")"

    if [ "$state" != "running" ]; then
        echo "[self-heal] starting $container (state=$state)"
        docker start "$container" >/dev/null
        changed=1
        continue
    fi

    if [ "$health" = "unhealthy" ]; then
        echo "[self-heal] restarting $container (health=unhealthy)"
        docker restart "$container" >/dev/null
        changed=1
    fi
done

if [ "$changed" = "0" ]; then
    echo "[self-heal] all containers running"
fi
