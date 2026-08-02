#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=common.sh
source "${SCRIPT_DIR}/common.sh"

snapshot_name=${1:-}
if [[ ! $snapshot_name =~ ^phase0-[a-z0-9][a-z0-9._-]{0,63}$ ]]; then
  fail "snapshot name must match phase0-[a-z0-9._-]+"
fi

load_image_environment
backup_parent=$(dirname "$PHASE0_BACKUP_ROOT")
sudo -n install -d -m 0710 -o root -g "$(id -gn)" "$backup_parent"
sudo -n install -d -m 0750 -o root -g "$(id -gn)" "$PHASE0_BACKUP_ROOT"

archive=${PHASE0_BACKUP_ROOT}/${snapshot_name}.tar.gz
checksum=${archive}.sha256
[ ! -e "$archive" ] || fail "refusing to overwrite immutable snapshot: $archive"

"${docker_cmd[@]}" volume inspect "$WG_EASY_VOLUME" >/dev/null

restart_required=false
if "${docker_cmd[@]}" ps --format '{{.Names}}' | grep -qx wg-easy-phase0; then
  restart_required=true
  "${server_compose[@]}" stop wg-easy
fi

restart_server() {
  if [ "$restart_required" = true ]; then
    "${server_compose[@]}" up -d wg-easy >/dev/null
  fi
}
trap restart_server EXIT

"${docker_cmd[@]}" run --rm \
  --read-only \
  --mount "type=volume,src=${WG_EASY_VOLUME},dst=/source,readonly" \
  --mount "type=bind,src=${PHASE0_BACKUP_ROOT},dst=/backup" \
  docker.io/library/alpine@sha256:7c8cb692ae09657cbc4a3f3cbd0e8d5a2690ba38386aaaf252dbb060bf5eb2e6 \
  tar -czf "/backup/${snapshot_name}.tar.gz" -C /source .

sudo -n tar -tzf "$archive" | grep -E '(^|/)wg-easy\.db$' >/dev/null || fail "snapshot does not contain wg-easy.db"
sudo -n tar -tzf "$archive" | grep -E '(^|/)wg0\.conf$' >/dev/null || fail "snapshot does not contain wg0.conf"
sudo -n sha256sum "$archive" | sudo -n tee "$checksum" >/dev/null
sudo -n chmod 0440 "$archive" "$checksum"

restart_server
restart_required=false
trap - EXIT

echo "$archive"
