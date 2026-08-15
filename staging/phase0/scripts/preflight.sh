#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=common.sh
source "${SCRIPT_DIR}/common.sh"

require_command curl
require_command jq
require_command python3
require_command sha256sum
require_command ssh
require_restricted_file "$WG_EASY_ENV_FILE"
load_image_environment

mapfile -t network_ids < <("${docker_cmd[@]}" network ls -q)
if ((${#network_ids[@]} > 0)); then
  "${docker_cmd[@]}" network inspect "${network_ids[@]}" |
    python3 "${SCRIPT_DIR}/check-network-reservations.py"
fi

if sudo -n ip -j rule show | jq -e '
  any(.[]; (.priority // -1) >= 22001 and (.priority // -1) <= 23000)
' >/dev/null; then
  fail "reserved policy-rule priorities 22001-23000 are already in use"
fi

if sudo -n ip -j route show table all | jq -e '
  any(.[];
    ((.table | tonumber?) // -1) as $table |
    $table == 51999 or ($table >= 52001 and $table <= 52999)
  )
' >/dev/null; then
  fail "reserved route tables 51999 or 52001-52999 are already in use"
fi

if sudo -n iptables-save | grep -Eiq '0x54000000|0xffff0000|WG_ROUTE_MARK|WG_ROUTE_NAT'; then
  fail "reserved routing mark namespace or chain names are already in use"
fi

if ss -H -ltn '( sport = :51821 )' | grep -q .; then
  if ! "${docker_cmd[@]}" ps --format '{{.Names}}' | grep -qx 'wg-easy-phase0'; then
    fail "TCP port 51821 is already in use by a non-Phase-0 process"
  fi
fi

if ss -H -lun '( sport = :51820 )' | grep -q .; then
  if ! "${docker_cmd[@]}" ps --format '{{.Names}}' | grep -qx 'wg-easy-phase0'; then
    fail "UDP port 51820 is already in use by a non-Phase-0 process"
  fi
fi

if ss -H -lun '( sport = :51821 )' | grep -q .; then
  if ! "${docker_cmd[@]}" ps --format '{{.Names}}' | grep -qx 'wg-easy-phase0'; then
    fail "UDP port 51821 is already in use by a non-Phase-0 process"
  fi
fi

echo "Phase 0 reservation and secret-file preflight passed."
