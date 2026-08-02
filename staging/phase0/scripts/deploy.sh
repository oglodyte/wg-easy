#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=common.sh
source "${SCRIPT_DIR}/common.sh"

"${SCRIPT_DIR}/preflight.sh"
load_image_environment

ensure_network wg-easy-phase0-underlay 172.30.110.0/24 true
ensure_network wg-easy-phase0-exit-egress 172.30.111.0/24 true
ensure_network wg-easy-phase0-management 172.30.113.0/24 false

if ! "${docker_cmd[@]}" volume inspect "$WG_EASY_VOLUME" >/dev/null 2>&1; then
  "${docker_cmd[@]}" volume create \
    --label com.wg-easy.phase=0 \
    "$WG_EASY_VOLUME" >/dev/null
fi

"${docker_cmd[@]}" pull "$WG_EASY_IMAGE"
"${docker_cmd[@]}" pull "$WG_CLIENT_IMAGE"
"${docker_cmd[@]}" pull "$AWG_CLIENT_IMAGE"
"${docker_cmd[@]}" pull "$TRAFFIC_SINK_IMAGE"

"${server_compose[@]}" config --quiet
"${lab_compose[@]}" config --quiet
"${server_compose[@]}" up -d --remove-orphans

for _ in $(seq 1 60); do
  status=$("${docker_cmd[@]}" inspect wg-easy-phase0 --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}')
  if [ "$status" = healthy ]; then
    if curl --fail --silent --show-error "${PHASE0_API_URL}/api/information" >/dev/null 2>&1; then
      echo "Phase 0 server is healthy at immutable image ${WG_EASY_IMAGE}."
      exit 0
    fi
  fi
  if [ "$status" = exited ] || [ "$status" = dead ]; then
    "${docker_cmd[@]}" logs --tail 100 wg-easy-phase0
    fail "server stopped during deployment"
  fi
  sleep 2
done

"${docker_cmd[@]}" logs --tail 100 wg-easy-phase0
fail "server did not become healthy within 120 seconds"
