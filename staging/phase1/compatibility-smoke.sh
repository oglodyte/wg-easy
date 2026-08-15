#!/usr/bin/env bash
set -euo pipefail

readonly EXPECTED_AWG_GO_COMMIT=08d68cdae27762c3e07f36bbb12d2bad32f81926
readonly EXPECTED_AWG_TOOLS_COMMIT=9f70177d204d5be66c5b043518a57b7d62b3f9d1
readonly FORCE_USERSPACE_ENV=WG_I_PREFER_BUGGY_USERSPACE_TO_POLISHED_KMOD=1
readonly COMPAT_SUBNET=172.30.114.0/24
readonly SERVER_UNDERLAY_IP=172.30.114.2
readonly SERVER_TUNNEL_IP=10.251.250.1
readonly CLIENT_TUNNEL_IP=10.251.250.2
readonly LISTEN_PORT=51990

fail() {
  echo "Phase 1 compatibility smoke failed: $*" >&2
  exit 1
}

require_digest_ref() {
  local name=$1
  local value=$2
  if [[ ! $value =~ @sha256:[0-9a-f]{64}$ ]]; then
    fail "$name must be an immutable sha256 image reference"
  fi
}

: "${PHASE1_SERVER_IMAGE:?Set PHASE1_SERVER_IMAGE to the immutable Phase 1 server image digest}"
: "${PHASE0_WG_CLIENT_IMAGE:?Set PHASE0_WG_CLIENT_IMAGE to the immutable generic WireGuard client image digest}"
require_digest_ref PHASE1_SERVER_IMAGE "$PHASE1_SERVER_IMAGE"
require_digest_ref PHASE0_WG_CLIENT_IMAGE "$PHASE0_WG_CLIENT_IMAGE"

docker_cmd=(docker)
if ! docker info >/dev/null 2>&1; then
  docker_cmd=(sudo -n docker)
fi
"${docker_cmd[@]}" info >/dev/null

suffix="$$"
network_name="wg-easy-phase1-compat-${suffix}"
server_name="wg-easy-phase1-awg-${suffix}"
client_name="wg-easy-phase1-wg-${suffix}"
artifact_dir=$(mktemp -d "${TMPDIR:-/tmp}/wg-easy-phase1-compat.XXXXXX")
chmod 0700 "$artifact_dir"

cleanup() {
  "${docker_cmd[@]}" rm -f "$client_name" "$server_name" >/dev/null 2>&1 || true
  "${docker_cmd[@]}" network rm "$network_name" >/dev/null 2>&1 || true
  rm -r "$artifact_dir"
}
trap cleanup EXIT

"${docker_cmd[@]}" pull "$PHASE1_SERVER_IMAGE" >/dev/null
"${docker_cmd[@]}" pull "$PHASE0_WG_CLIENT_IMAGE" >/dev/null

go_revision=$("${docker_cmd[@]}" image inspect "$PHASE1_SERVER_IMAGE" \
  --format '{{ index .Config.Labels "org.opencontainers.image.amneziawg-go.revision" }}')
tools_revision=$("${docker_cmd[@]}" image inspect "$PHASE1_SERVER_IMAGE" \
  --format '{{ index .Config.Labels "org.opencontainers.image.amneziawg-tools.revision" }}')
[ "$go_revision" = "$EXPECTED_AWG_GO_COMMIT" ] || fail "unexpected amneziawg-go revision label"
[ "$tools_revision" = "$EXPECTED_AWG_TOOLS_COMMIT" ] || fail "unexpected amneziawg-tools revision label"

"${docker_cmd[@]}" network create \
  --label com.wg-easy.phase=1 \
  --subnet "$COMPAT_SUBNET" \
  "$network_name" >/dev/null

server_private=$("${docker_cmd[@]}" run --rm --entrypoint awg \
  "$PHASE1_SERVER_IMAGE" genkey)
server_public=$(printf '%s\n' "$server_private" | \
  "${docker_cmd[@]}" run --rm -i --entrypoint awg \
    "$PHASE1_SERVER_IMAGE" pubkey)
client_private=$("${docker_cmd[@]}" run --rm --entrypoint wg \
  "$PHASE0_WG_CLIENT_IMAGE" genkey)
client_public=$(printf '%s\n' "$client_private" | \
  "${docker_cmd[@]}" run --rm -i --entrypoint wg \
    "$PHASE0_WG_CLIENT_IMAGE" pubkey)

umask 077
printf '%s\n' \
  '[Interface]' \
  "PrivateKey = ${server_private}" \
  "ListenPort = ${LISTEN_PORT}" \
  '' \
  '[Peer]' \
  "PublicKey = ${client_public}" \
  "AllowedIPs = ${CLIENT_TUNNEL_IP}/32" \
  >"${artifact_dir}/server.conf"
printf '%s\n' \
  '[Interface]' \
  "PrivateKey = ${client_private}" \
  "Address = ${CLIENT_TUNNEL_IP}/24" \
  '' \
  '[Peer]' \
  "PublicKey = ${server_public}" \
  "AllowedIPs = ${SERVER_TUNNEL_IP}/32" \
  "Endpoint = ${SERVER_UNDERLAY_IP}:${LISTEN_PORT}" \
  'PersistentKeepalive = 5' \
  >"${artifact_dir}/client.conf"

if grep -Eiq '^(Jc|Jmin|Jmax|S[1-4]|H[1-4]|I[1-5])[[:space:]]*=' \
  "${artifact_dir}/server.conf" "${artifact_dir}/client.conf"; then
  fail "compatibility configs contain AWG-only directives"
fi

"${docker_cmd[@]}" run -d \
  --name "$server_name" \
  --network "$network_name" \
  --ip "$SERVER_UNDERLAY_IP" \
  --cap-add NET_ADMIN \
  --device /dev/net/tun \
  --entrypoint /bin/sh \
  "$PHASE1_SERVER_IMAGE" -c 'trap : TERM INT; sleep infinity & wait' >/dev/null
"${docker_cmd[@]}" run -d \
  --name "$client_name" \
  --network "$network_name" \
  --cap-add NET_ADMIN \
  --device /dev/net/tun \
  --entrypoint /bin/sh \
  "$PHASE0_WG_CLIENT_IMAGE" -c 'trap : TERM INT; sleep infinity & wait' >/dev/null

"${docker_cmd[@]}" cp "${artifact_dir}/server.conf" "${server_name}:/tmp/server.conf"
"${docker_cmd[@]}" cp "${artifact_dir}/client.conf" "${client_name}:/tmp/client.conf"

"${docker_cmd[@]}" exec --env "$FORCE_USERSPACE_ENV" \
  "$server_name" amneziawg-go awgcompat
"${docker_cmd[@]}" exec "$server_name" \
  test -S /var/run/amneziawg/awgcompat.sock || \
  fail "amneziawg-go did not create its userspace control socket"
"${docker_cmd[@]}" exec "$server_name" \
  ip -details link show awgcompat | grep -q 'tun type tun' || \
  fail "compatibility interface is not backed by the userspace TUN device"
"${docker_cmd[@]}" exec "$server_name" awg setconf awgcompat /tmp/server.conf
"${docker_cmd[@]}" exec "$server_name" ip address add "${SERVER_TUNNEL_IP}/24" dev awgcompat
"${docker_cmd[@]}" exec "$server_name" ip link set awgcompat up
"${docker_cmd[@]}" exec "$client_name" wg-quick up /tmp/client.conf >/dev/null

handshake_seen=false
for _ in $(seq 1 30); do
  timestamp=$("${docker_cmd[@]}" exec "$client_name" \
    wg show client latest-handshakes 2>/dev/null | awk 'NR == 1 {print $2}')
  if [[ $timestamp =~ ^[0-9]+$ ]] && [ "$timestamp" -gt 0 ]; then
    handshake_seen=true
    break
  fi
  sleep 1
done
[ "$handshake_seen" = true ] || fail "generic WireGuard peer did not handshake"

"${docker_cmd[@]}" exec "$client_name" ping -c 2 -W 2 "$SERVER_TUNNEL_IP" >/dev/null
"${docker_cmd[@]}" exec "$server_name" awg show awgcompat transfer | \
  awk '{if ($2 > 0 || $3 > 0) found=1} END {exit !found}' || \
  fail "AWG userspace tunnel counters did not advance"

awg_version=$("${docker_cmd[@]}" exec "$server_name" awg --version | head -n 1)
awg_go_version=$("${docker_cmd[@]}" exec "$server_name" amneziawg-go --version | head -n 1)
wg_version=$("${docker_cmd[@]}" exec "$client_name" wg --version | head -n 1)
echo "Phase 1 compatibility smoke passed: generic WireGuard peer handshook and passed traffic through pinned AWG userspace."
echo "Server tools: ${awg_version}; ${awg_go_version}"
echo "Generic peer tools: ${wg_version}"
