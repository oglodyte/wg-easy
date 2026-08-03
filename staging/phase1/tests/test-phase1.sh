#!/usr/bin/env bash
set -euo pipefail

TEST_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PHASE1_DIR=$(cd "${TEST_DIR}/.." && pwd)
REPOSITORY_ROOT=$(cd "${PHASE1_DIR}/../.." && pwd)

while IFS= read -r script; do
  bash -n "$script"
done < <(find "$PHASE1_DIR" -type f -name '*.sh' -print | sort)

grep -q 'AMNEZIAWG_GO_COMMIT=9f5d948bc72cc554791cfe0fb91527e4acfb6b79' \
  "$REPOSITORY_ROOT/Dockerfile"
grep -q 'AMNEZIAWG_TOOLS_COMMIT=d09ecc38425082e472368dd2bf8c4c42d10cae03' \
  "$REPOSITORY_ROOT/Dockerfile"
grep -q 'git -C amneziawg-go checkout --detach' "$REPOSITORY_ROOT/Dockerfile"
grep -q 'git -C amneziawg-tools checkout --detach' "$REPOSITORY_ROOT/Dockerfile"
grep -q 'iproute2' "$REPOSITORY_ROOT/Dockerfile"
grep -q 'amneziawg-go awgcompat' "$PHASE1_DIR/compatibility-smoke.sh"
grep -q 'awg setconf awgcompat' "$PHASE1_DIR/compatibility-smoke.sh"
grep -q 'wg show client latest-handshakes' "$PHASE1_DIR/compatibility-smoke.sh"
grep -q 'compatibility configs contain AWG-only directives' \
  "$PHASE1_DIR/compatibility-smoke.sh"

echo "Phase 1 non-destructive script validation passed."
