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
AWG_PATCH="${REPOSITORY_ROOT}/staging/phase0/client-lab/patch-awg-quick.sh"
SERVER_COMPOSE="${REPOSITORY_ROOT}/staging/phase0/compose.server.yml"
LAB_COMPOSE="${REPOSITORY_ROOT}/staging/phase0/compose.lab.yml"
DOCKERFILE="${REPOSITORY_ROOT}/Dockerfile"
DATABASE_NATIVE_SMOKE="${PHASE8_DIR}/database-native-smoke.mjs"
PNPM_WORKSPACE="${REPOSITORY_ROOT}/src/pnpm-workspace.yaml"

while IFS= read -r script; do
  bash -n "$script"
done < <(find "$PHASE8_DIR" -type f -name '*.sh' -print | sort)

grep -q 'privileged-routing:' "$WORKFLOW"
grep -q 'WG_EASY_RUN_PRIVILEGED_TESTS=1 node node_modules/vitest/vitest.mjs run --project integration' "$WORKFLOW"
grep -q 'docker/setup-qemu-action@v4' "$WORKFLOW"
grep -q 'platforms: linux/amd64,linux/arm64' "$WORKFLOW"
grep -q 'for architecture in amd64 arm64' "$WORKFLOW"
grep -q 'expected exactly one platform manifest' "$WORKFLOW"
grep -Fq 'node-version: "24.19.0"' "$WORKFLOW"
grep -Fq 'timeout 30s node --expose-gc /tmp/database-native-smoke.mjs' "$WORKFLOW"
grep -Fq 'node:24.19.0-alpine3.23@sha256:244cc2b53f46f9e876304391d17682b0ddae9ac33491f4857e25e35a36ba7995' "$DOCKERFILE"
grep -Fq 'corepack prepare "pnpm@${PNPM_VERSION}" --activate' "$DOCKERFILE"
grep -Fq 'pnpm install --frozen-lockfile' "$DOCKERFILE"
grep -Fq 'for (let round = 0; round < 100; round += 1)' \
  "$DATABASE_NATIVE_SMOKE"
grep -Fq 'import { DatabaseSync } from "node:sqlite"' \
  "$DATABASE_NATIVE_SMOKE"
grep -Fq "from 'node:sqlite'" \
  "$REPOSITORY_ROOT/src/server/database/nodeSqlite.ts"
if grep -Fq 'corepack@latest' "$DOCKERFILE"; then
  echo "The production image must not install a moving Corepack release." >&2
  exit 1
fi
if rg -q '@libsql/client|drizzle-orm/libsql|libsql@' \
  "$REPOSITORY_ROOT/src/package.json" \
  "$REPOSITORY_ROOT/src/server" \
  "$REPOSITORY_ROOT/src/cli" \
  "$DOCKERFILE"; then
  echo "The production runtime must not load the external libSQL addon." >&2
  exit 1
fi
grep -Fq 'autoInstallPeers: false' "$PNPM_WORKSPACE"
grep -Fq '"vue": "3.5.40"' "$REPOSITORY_ROOT/src/package.json"
if grep -Fq 'process.exit(0)' "$DATABASE_NATIVE_SMOKE"; then
  echo "The database smoke must exit naturally after deterministic close." >&2
  exit 1
fi
grep -Fq 'AWG_FORCE_USERSPACE:-false' "$AWG_PATCH"
grep -Fq 'WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1' "$AWG_PATCH"
grep -Fq '/dev/net/tun:/dev/net/tun' "$SERVER_COMPOSE"
[ "$(grep -c 'AWG_FORCE_USERSPACE: ${AWG_FORCE_USERSPACE:-false}' \
  "$LAB_COMPOSE")" -eq 3 ]
grep -q '^AWG_FORCE_USERSPACE=false$' \
  "$REPOSITORY_ROOT/staging/phase0/server.env.example"
grep -q 'AWG_FORCE_USERSPACE=true' "$PHASE8_DIR/README.md"
grep -q '/dev/net/tun' "$PHASE8_DIR/README.md"

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
