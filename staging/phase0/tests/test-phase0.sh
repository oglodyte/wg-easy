#!/usr/bin/env bash
set -euo pipefail

TEST_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PHASE0_DIR=$(cd "${TEST_DIR}/.." && pwd)
REPOSITORY_ROOT=$(cd "${PHASE0_DIR}/../.." && pwd)
TEMP_DIR=$(mktemp -d)
cleanup() {
  rm -r "$TEMP_DIR"
}
trap cleanup EXIT

while IFS= read -r script; do
  bash -n "$script"
done < <(find "$PHASE0_DIR" -type f -name '*.sh' -print | sort)

while IFS= read -r script; do
  python3 -c 'import ast, pathlib, sys; ast.parse(pathlib.Path(sys.argv[1]).read_text())' "$script"
done < <(find "$PHASE0_DIR" -type f -name '*.py' -print | sort)

(
  # shellcheck source=../scripts/common.sh
  source "${PHASE0_DIR}/scripts/common.sh"
  require_digest_ref TEST_IMAGE 'ghcr.io/example/image@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
)

if (
  # shellcheck source=../scripts/common.sh
  source "${PHASE0_DIR}/scripts/common.sh"
  require_digest_ref TEST_IMAGE 'ghcr.io/example/image:mutable'
) >/dev/null 2>&1; then
  echo "Mutable image validation unexpectedly passed." >&2
  exit 1
fi

printf '%s\n' '[{"Name":"bridge","IPAM":{"Config":null}}]' |
  python3 "${PHASE0_DIR}/scripts/check-network-reservations.py"

if printf '%s\n' \
  '[{"Name":"unrelated","IPAM":{"Config":[{"Subnet":"172.30.110.128/25"}]}}]' |
  python3 "${PHASE0_DIR}/scripts/check-network-reservations.py" >/dev/null 2>&1; then
  echo "Overlapping Docker network validation unexpectedly passed." >&2
  exit 1
fi

grep -q -- \
  '--preserve-env=WG_EASY_IMAGE,WG_EASY_ENV_FILE,WG_EASY_VOLUME' \
  "${PHASE0_DIR}/scripts/common.sh"
grep -q -- \
  '--preserve-env=WG_CLIENT_IMAGE,AWG_CLIENT_IMAGE,TRAFFIC_SINK_IMAGE,LAB_ARTIFACT_ROOT' \
  "${PHASE0_DIR}/scripts/common.sh"
grep -q 'ensure_network wg-easy-phase0-management 172.30.113.0/24 false' \
  "${PHASE0_DIR}/scripts/deploy.sh"
grep -q '127.0.0.1:51821:51821/tcp' "${PHASE0_DIR}/compose.server.yml"
grep -q 'net.ipv4.conf.all.src_valid_mark: 1' "${PHASE0_DIR}/compose.lab.yml"
grep -q 'privileged: true' "${PHASE0_DIR}/compose.lab.yml"
grep -q 'if curl --fail --silent --show-error' "${PHASE0_DIR}/scripts/deploy.sh"
grep -q 'install -d -m 0710 -o root' "${PHASE0_DIR}/scripts/seed-baseline.sh"
grep -q 'install -d -m 0710 -o root' "${PHASE0_DIR}/scripts/generate-manifest.sh"
grep -q 'sub("\^;\[\[:space:\]\]\*"; "")' "${PHASE0_DIR}/scripts/seed-baseline.sh"
grep -q 'ip route replace "${sink_ip}/32" dev wg0' \
  "${PHASE0_DIR}/scripts/run-client-lab.sh"

grep -q 'target: wg-client' "$REPOSITORY_ROOT/.github/workflows/deploy-phase.yml"

jq -n '
  def client($name; $enabled; $keepalive; $server_allowed; $expires): {
    name: $name,
    enabled: $enabled,
    persistentKeepalive: $keepalive,
    serverAllowedIps: $server_allowed,
    expiresAt: $expires
  };
  {
    schemaVersion: 1,
    interface: {name: "wg0"},
    clients: [
      client("phase0-wg-member"; true; 21; []; null),
      client("phase0-awg-member"; true; 21; []; null),
      client("phase0-exit-primary"; true; 25; ["172.30.111.100/32"]; null),
      client("phase0-exit-backup"; true; 25; []; null),
      client("phase0-disabled"; false; 21; []; null),
      client("phase0-future"; true; 21; []; "2037-01-01T00:00:00.000Z")
    ]
  }
' >"${TEMP_DIR}/manifest.json"
python3 "${PHASE0_DIR}/scripts/validate-manifest.py" "${TEMP_DIR}/manifest.json"

jq '.interface.privateKey = "must-not-appear"' \
  "${TEMP_DIR}/manifest.json" >"${TEMP_DIR}/manifest-with-secret.json"
if python3 "${PHASE0_DIR}/scripts/validate-manifest.py" \
  "${TEMP_DIR}/manifest-with-secret.json" >/dev/null 2>&1; then
  echo "Manifest secret-field validation unexpectedly passed." >&2
  exit 1
fi

echo "Phase 0 non-destructive script validation passed."
