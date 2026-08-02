#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=common.sh
source "${SCRIPT_DIR}/common.sh"

if [ "$#" -ne 2 ]; then
  echo "Usage: $0 SNAPSHOT_NAME TARGET_VOLUME" >&2
  exit 2
fi

snapshot_name=$1
target_volume=$2
[[ $snapshot_name =~ ^phase0-[a-z0-9][a-z0-9._-]{0,63}$ ]] || fail "invalid snapshot name"
[[ $target_volume =~ ^wg-easy-phase0-(clone|rollback)-[a-z0-9][a-z0-9._-]{0,63}$ ]] || fail "invalid restore volume name"

archive=${PHASE0_BACKUP_ROOT}/${snapshot_name}.tar.gz
checksum=${archive}.sha256
backup_parent=$(dirname "$PHASE0_BACKUP_ROOT")
sudo -n install -d -m 0710 -o root -g "$(id -gn)" "$backup_parent"
sudo -n install -d -m 0750 -o root -g "$(id -gn)" "$PHASE0_BACKUP_ROOT"
[ -f "$archive" ] || fail "snapshot is missing: $archive"
[ -f "$checksum" ] || fail "snapshot checksum is missing: $checksum"
(cd "$PHASE0_BACKUP_ROOT" && sudo -n sha256sum --check "${snapshot_name}.tar.gz.sha256")

if "${docker_cmd[@]}" volume inspect "$target_volume" >/dev/null 2>&1; then
  fail "target volume already exists; refusing to overwrite: $target_volume"
fi

"${docker_cmd[@]}" volume create \
  --label com.wg-easy.phase=0 \
  --label com.wg-easy.restore-of="$snapshot_name" \
  "$target_volume" >/dev/null

restore_succeeded=false
cleanup_failed_restore() {
  if [ "$restore_succeeded" = false ]; then
    "${docker_cmd[@]}" volume rm "$target_volume" >/dev/null 2>&1 || true
  fi
}
trap cleanup_failed_restore EXIT

"${docker_cmd[@]}" run --rm \
  --read-only \
  --mount "type=volume,src=${target_volume},dst=/target" \
  --mount "type=bind,src=${PHASE0_BACKUP_ROOT},dst=/backup,readonly" \
  docker.io/library/alpine@sha256:7c8cb692ae09657cbc4a3f3cbd0e8d5a2690ba38386aaaf252dbb060bf5eb2e6 \
  tar -xzf "/backup/${snapshot_name}.tar.gz" -C /target

"${docker_cmd[@]}" run --rm \
  --read-only \
  --mount "type=volume,src=${target_volume},dst=/target,readonly" \
  docker.io/library/alpine@sha256:7c8cb692ae09657cbc4a3f3cbd0e8d5a2690ba38386aaaf252dbb060bf5eb2e6 \
  test -f /target/wg-easy.db

restore_succeeded=true
trap - EXIT
echo "$target_volume"
