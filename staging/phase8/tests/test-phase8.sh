#!/usr/bin/env bash
set -euo pipefail

TEST_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PHASE8_DIR=$(cd "${TEST_DIR}/.." && pwd)
REPOSITORY_ROOT=$(cd "${PHASE8_DIR}/../.." && pwd)
WORKFLOW="${REPOSITORY_ROOT}/.github/workflows/deploy-phase.yml"
METRICS="${REPOSITORY_ROOT}/src/server/routes/metrics/prometheus.get.ts"
ONE_TIME_LINK="${REPOSITORY_ROOT}/src/server/database/repositories/oneTimeLink/service.ts"
ONE_TIME_LINK_TYPES="${REPOSITORY_ROOT}/src/server/database/repositories/oneTimeLink/types.ts"
COMMAND_RUNNER="${REPOSITORY_ROOT}/src/server/utils/cmd.ts"
CONFIG_ROUTE="${REPOSITORY_ROOT}/src/server/api/client/[clientId]/configuration.get.ts"
QR_ROUTE="${REPOSITORY_ROOT}/src/server/api/client/[clientId]/qrcode.svg.get.ts"
ONE_TIME_LINK_ROUTE="${REPOSITORY_ROOT}/src/server/api/client/[clientId]/generateOneTimeLink.post.ts"

while IFS= read -r script; do
  bash -n "$script"
done < <(find "$PHASE8_DIR" -type f -name '*.sh' -print | sort)

grep -q 'privileged-routing:' "$WORKFLOW"
grep -q 'WG_EASY_RUN_PRIVILEGED_TESTS=1 pnpm test:integration' "$WORKFLOW"
grep -q 'docker/setup-qemu-action@v4' "$WORKFLOW"
grep -q 'platforms: linux/amd64,linux/arm64' "$WORKFLOW"
grep -q 'for platform in linux/amd64 linux/arm64' "$WORKFLOW"

grep -q "randomBytes(32).toString('base64url')" "$ONE_TIME_LINK"
if grep -Eq 'Math\.random|CRC32|crc-32' "$ONE_TIME_LINK"; then
  echo "One-time links must not use predictable or checksum-based tokens." >&2
  exit 1
fi
grep -q '\.max(128' "$ONE_TIME_LINK_TYPES"
grep -q '\^\[A-Za-z0-9_-\]' "$ONE_TIME_LINK_TYPES"

grep -q 'shell: false' "$COMMAND_RUNNER"
grep -q "mode: 0o600" "$COMMAND_RUNNER"
for route in "$CONFIG_ROUTE" "$QR_ROUTE" "$ONE_TIME_LINK_ROUTE"; do
  grep -q 'definePermissionEventHandler' "$route"
  grep -q 'checkPermissions(client)' "$route"
done
grep -q "defineMetricsHandler('prometheus'" "$METRICS"

for metric in \
  wg_easy_interface_info \
  wg_easy_client_info \
  wg_easy_routing_groups_total \
  wg_easy_routing_group_active \
  wg_easy_routing_group_all_exits_down \
  wg_easy_client_is_exit \
  wg_easy_exit_client_candidate_priority; do
  grep -q "$metric" "$METRICS"
done

grep -q 'is a separate action requiring explicit authorization' \
  "$PHASE8_DIR/README.md"
grep -q 'Never start the older image' \
  "$PHASE8_DIR/README.md"

echo "Phase 8 non-destructive hardening validation passed."
