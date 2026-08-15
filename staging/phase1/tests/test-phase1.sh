#!/usr/bin/env bash
set -euo pipefail

TEST_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PHASE1_DIR=$(cd "${TEST_DIR}/.." && pwd)
REPOSITORY_ROOT=$(cd "${PHASE1_DIR}/../.." && pwd)

while IFS= read -r script; do
  bash -n "$script"
done < <(find "$PHASE1_DIR" -type f -name '*.sh' -print | sort)

grep -q 'AMNEZIAWG_GO_VERSION=v3.0.20260805' \
  "$REPOSITORY_ROOT/Dockerfile"
grep -q 'AMNEZIAWG_GO_COMMIT=08d68cdae27762c3e07f36bbb12d2bad32f81926' \
  "$REPOSITORY_ROOT/Dockerfile"
grep -q 'AMNEZIAWG_TOOLS_VERSION=v3.0.20260805' \
  "$REPOSITORY_ROOT/Dockerfile"
grep -q 'AMNEZIAWG_TOOLS_COMMIT=9f70177d204d5be66c5b043518a57b7d62b3f9d1' \
  "$REPOSITORY_ROOT/Dockerfile"
grep -q 'git -C amneziawg-go rev-parse HEAD' "$REPOSITORY_ROOT/Dockerfile"
grep -q 'git -C amneziawg-tools rev-parse HEAD' "$REPOSITORY_ROOT/Dockerfile"
grep -q 'iproute2' "$REPOSITORY_ROOT/Dockerfile"
grep -q 'patch-awg-quick.sh' "$REPOSITORY_ROOT/Dockerfile"
grep -q 'patch-awg-quick.sh' \
  "$REPOSITORY_ROOT/staging/phase0/client-lab/Dockerfile"
grep -Fq 'AWG_FORCE_USERSPACE:-false' \
  "$REPOSITORY_ROOT/staging/phase0/client-lab/patch-awg-quick.sh"
grep -Fq 'WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1' \
  "$REPOSITORY_ROOT/staging/phase0/client-lab/patch-awg-quick.sh"
awg_patch_fixture=$(mktemp)
trap 'rm -f -- "$awg_patch_fixture"' EXIT
cp "$PHASE1_DIR/fixtures/awg-quick-add-if.sh" "$awg_patch_fixture"
sh "$REPOSITORY_ROOT/staging/phase0/client-lab/patch-awg-quick.sh" \
  "$awg_patch_fixture"
grep -Fq 'AWG_FORCE_USERSPACE:-false' "$awg_patch_fixture"
grep -Fq 'WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1' \
  "$awg_patch_fixture"
bash -n "$awg_patch_fixture"
rm -f -- "$awg_patch_fixture"
trap - EXIT
grep -Fq '/dev/net/tun:/dev/net/tun' "$REPOSITORY_ROOT/docker-compose.yml"
grep -Fq '/dev/net/tun:/dev/net/tun' \
  "$REPOSITORY_ROOT/staging/phase0/compose.server.yml"
grep -q 'amneziawg-go awgcompat' "$PHASE1_DIR/compatibility-smoke.sh"
grep -q 'WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1' \
  "$PHASE1_DIR/compatibility-smoke.sh"
grep -q '/var/run/amneziawg/awgcompat.sock' \
  "$PHASE1_DIR/compatibility-smoke.sh"
grep -q 'tun type tun' "$PHASE1_DIR/compatibility-smoke.sh"
grep -q 'awg setconf awgcompat' "$PHASE1_DIR/compatibility-smoke.sh"
grep -q 'wg show client latest-handshakes' "$PHASE1_DIR/compatibility-smoke.sh"
grep -q 'compatibility configs contain AWG-only directives' \
  "$PHASE1_DIR/compatibility-smoke.sh"

echo "Phase 1 non-destructive script validation passed."
