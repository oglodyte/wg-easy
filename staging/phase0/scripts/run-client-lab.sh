#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=common.sh
source "${SCRIPT_DIR}/common.sh"

load_image_environment
require_command curl
require_command jq

for config_name in wg-member awg-member exit-primary exit-backup; do
  require_restricted_file "${LAB_ARTIFACT_ROOT}/${config_name}.conf"
done
require_restricted_file "${LAB_ARTIFACT_ROOT}/lab-state.json"

server_ip=$(jq -er '.serverIp' "${LAB_ARTIFACT_ROOT}/lab-state.json")
member_ip=$(jq -er '.wgMemberIp' "${LAB_ARTIFACT_ROOT}/lab-state.json")
sink_ip=$(jq -er '.sinkIp' "${LAB_ARTIFACT_ROOT}/lab-state.json")
server_sink_route_added=false

cleanup() {
  if [ "$server_sink_route_added" = true ]; then
    "${docker_cmd[@]}" exec wg-easy-phase0 \
      ip route del "${sink_ip}/32" dev wg0 >/dev/null 2>&1 || true
  fi
  if [ "${KEEP_PHASE0_LAB:-false}" != true ]; then
    "${lab_compose[@]}" down --remove-orphans >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

"${lab_compose[@]}" config --quiet
"${lab_compose[@]}" up -d --remove-orphans

wait_for_handshake() {
  local container=$1
  local tool=$2
  local timestamp

  for _ in $(seq 1 60); do
    if "${docker_cmd[@]}" exec "$container" test -f /run/wg-easy-vpn/ready 2>/dev/null; then
      timestamp=$("${docker_cmd[@]}" exec "$container" "$tool" show client latest-handshakes 2>/dev/null | awk 'NR == 1 {print $2}')
      if [[ $timestamp =~ ^[0-9]+$ ]] && [ "$timestamp" -gt 0 ]; then
        return
      fi
    fi
    sleep 2
  done
  "${docker_cmd[@]}" logs --tail 100 "$container"
  fail "$container did not establish a tunnel handshake"
}

wait_for_handshake wg-easy-phase0-wg-member wg
wait_for_handshake wg-easy-phase0-awg-member awg
wait_for_handshake wg-easy-phase0-exit-primary awg
wait_for_handshake wg-easy-phase0-exit-backup awg

"${docker_cmd[@]}" exec wg-easy-phase0 ip route replace "${sink_ip}/32" dev wg0
server_sink_route_added=true

for container in \
  wg-easy-phase0-wg-member \
  wg-easy-phase0-awg-member \
  wg-easy-phase0-exit-primary \
  wg-easy-phase0-exit-backup; do
  "${docker_cmd[@]}" exec "$container" ping -c 2 -W 2 "$server_ip" >/dev/null
done

configure_exit_egress() {
  local container=$1
  local egress_device

  egress_device=$("${docker_cmd[@]}" exec "$container" \
    sh -c "ip -o route get '$sink_ip' | awk '{for (i=1; i<=NF; i++) if (\$i == \"dev\") print \$(i+1)}'" | head -n 1)
  [ -n "$egress_device" ] || fail "could not determine egress device for $container"

  "${docker_cmd[@]}" exec "$container" \
    iptables -C FORWARD -i client -o "$egress_device" -j ACCEPT 2>/dev/null ||
    "${docker_cmd[@]}" exec "$container" \
      iptables -A FORWARD -i client -o "$egress_device" -j ACCEPT
  "${docker_cmd[@]}" exec "$container" \
    iptables -C FORWARD -i "$egress_device" -o client -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null ||
    "${docker_cmd[@]}" exec "$container" \
      iptables -A FORWARD -i "$egress_device" -o client -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  "${docker_cmd[@]}" exec "$container" \
    iptables -t nat -C POSTROUTING -d 172.30.111.0/24 -o "$egress_device" -j MASQUERADE 2>/dev/null ||
    "${docker_cmd[@]}" exec "$container" \
      iptables -t nat -A POSTROUTING -d 172.30.111.0/24 -o "$egress_device" -j MASQUERADE
}

configure_exit_egress wg-easy-phase0-exit-primary
configure_exit_egress wg-easy-phase0-exit-backup

egress_device=$("${docker_cmd[@]}" exec wg-easy-phase0-exit-primary \
  sh -c "ip -o route get '$sink_ip' | awk '{for (i=1; i<=NF; i++) if (\$i == \"dev\") print \$(i+1)}'" | head -n 1)

nat_on=$("${docker_cmd[@]}" exec wg-easy-phase0-wg-member \
  curl --fail --silent --show-error --max-time 10 "http://${sink_ip}:8080/nat-on")
[ "$(jq -r '.sourceAddress' <<<"$nat_on")" = 172.30.111.10 ] || fail "NAT-on sink source was not the primary exit"

"${docker_cmd[@]}" exec wg-easy-phase0-exit-primary \
  iptables -t nat -D POSTROUTING -d 172.30.111.0/24 -o "$egress_device" -j MASQUERADE

nat_off=$("${docker_cmd[@]}" exec wg-easy-phase0-wg-member \
  curl --fail --silent --show-error --max-time 10 "http://${sink_ip}:8080/nat-off")
[ "$(jq -r '.sourceAddress' <<<"$nat_off")" = "$member_ip" ] || fail "NAT-off sink source did not preserve the member address"

"${docker_cmd[@]}" exec wg-easy-phase0-wg-member \
  wg-quick down /run/wg-easy-vpn/client.conf >/dev/null
if "${docker_cmd[@]}" exec wg-easy-phase0-wg-member \
  curl --fail --silent --max-time 3 "http://${sink_ip}:8080/bypass-check" >/dev/null 2>&1; then
  fail "member reached the sink with its tunnel down"
fi
"${docker_cmd[@]}" exec wg-easy-phase0-wg-member \
  wg-quick up /run/wg-easy-vpn/client.conf >/dev/null
wait_for_handshake wg-easy-phase0-wg-member wg

if ! "${docker_cmd[@]}" exec wg-easy-phase0-wg-member \
  wg show client transfer | awk '{if ($2 > 0 || $3 > 0) found=1} END {exit !found}'; then
  fail "generic member tunnel counters did not advance"
fi

echo "Phase 0 client lab passed: four handshakes, tunnel traffic, NAT on/off source checks, and no member bypass path."
