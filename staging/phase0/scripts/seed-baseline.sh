#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=common.sh
source "${SCRIPT_DIR}/common.sh"

require_command curl
require_command jq
require_restricted_file "$WG_EASY_ENV_FILE"

admin_username=$(read_env_value INIT_USERNAME "$WG_EASY_ENV_FILE")
admin_password=$(read_env_value INIT_PASSWORD "$WG_EASY_ENV_FILE")
cookie_jar=$(mktemp)
link_download=$(mktemp)

cleanup() {
  rm -f "$cookie_jar" "$link_download"
}
trap cleanup EXIT

api_get() {
  curl --fail --silent --show-error \
    --cookie "$cookie_jar" \
    "${PHASE0_API_URL}$1"
}

api_post() {
  local path=$1
  local body=$2
  curl --fail --silent --show-error \
    --cookie "$cookie_jar" \
    --header 'Content-Type: application/json' \
    --request POST \
    --data "$body" \
    "${PHASE0_API_URL}${path}"
}

login_body=$(jq -cn \
  --arg username "$admin_username" \
  --arg password "$admin_password" \
  '{username: $username, password: $password, remember: false}')
curl --fail --silent --show-error \
  --cookie-jar "$cookie_jar" \
  --header 'Content-Type: application/json' \
  --request POST \
  --data "$login_body" \
  "${PHASE0_API_URL}/api/auth/password" >/dev/null
api_get /api/session >/dev/null

user_config=$(api_get /api/admin/userconfig)
user_config_payload=$(jq -c '
  {
    port,
    defaultMtu: 1380,
    defaultPersistentKeepalive: 21,
    defaultDns: ["1.1.1.1", "9.9.9.9"],
    defaultAllowedIps: ["0.0.0.0/0", "::/0"],
    defaultJC,
    defaultJMin,
    defaultJMax,
    defaultI1,
    defaultI2,
    defaultI3,
    defaultI4,
    defaultI5,
    host
  }
' <<<"$user_config")
api_post /api/admin/userconfig "$user_config_payload" >/dev/null

hooks=$(api_get /api/admin/hooks)
hooks_payload=$(jq -c '
  {
    preUp: (if .preUp | contains("phase0-baseline") then .preUp else .preUp + "; : phase0-baseline" end),
    postUp,
    preDown,
    postDown
  }
' <<<"$hooks")
api_post /api/admin/hooks "$hooks_payload" >/dev/null

create_client() {
  local name=$1
  local expires_at=$2
  local clients existing body response

  clients=$(api_get /api/client)
  existing=$(jq -r --arg name "$name" '[.[] | select(.name == $name)] | length' <<<"$clients")
  if [ "$existing" -gt 1 ]; then
    fail "more than one client exists with baseline name $name"
  fi
  if [ "$existing" -eq 1 ]; then
    jq -r --arg name "$name" '.[] | select(.name == $name) | .id' <<<"$clients"
    return
  fi

  body=$(jq -cn --arg name "$name" --arg expires "$expires_at" '
    {name: $name, expiresAt: (if $expires == "null" then null else $expires end)}
  ')
  response=$(api_post /api/client "$body")
  jq -er '.clientId' <<<"$response"
}

update_client() {
  local client_id=$1
  local enabled=$2
  local keepalive=$3
  local server_allowed=$4
  local clients payload

  clients=$(api_get /api/client)
  payload=$(jq -ce \
    --argjson id "$client_id" \
    --argjson enabled "$enabled" \
    --argjson keepalive "$keepalive" \
    --arg server_allowed "$server_allowed" '
      .[] | select(.id == $id) |
      {
        name,
        enabled: $enabled,
        expiresAt,
        ipv4Address,
        ipv6Address,
        preUp,
        postUp,
        preDown,
        postDown,
        allowedIps,
        serverAllowedIps: (if $server_allowed == "" then [] else [$server_allowed] end),
        firewallIps,
        mtu,
        jC,
        jMin,
        jMax,
        i1,
        i2,
        i3,
        i4,
        i5,
        persistentKeepalive: $keepalive,
        serverEndpoint,
        dns
      }
    ' <<<"$clients")
  api_post "/api/client/${client_id}" "$payload" >/dev/null
}

wg_member_id=$(create_client phase0-wg-member null)
awg_member_id=$(create_client phase0-awg-member null)
exit_primary_id=$(create_client phase0-exit-primary null)
exit_backup_id=$(create_client phase0-exit-backup null)
disabled_id=$(create_client phase0-disabled null)
future_id=$(create_client phase0-future 2037-01-01T00:00:00.000Z)

update_client "$wg_member_id" true 21 ""
update_client "$awg_member_id" true 21 ""
update_client "$exit_primary_id" true 25 172.30.111.100/32
update_client "$exit_backup_id" true 25 ""
update_client "$disabled_id" false 21 ""
update_client "$future_id" true 21 ""

sudo -n install -d -m 0700 -o "$(id -un)" -g "$(id -gn)" "$LAB_ARTIFACT_ROOT"

declare -A config_clients=(
  [wg-member]="$wg_member_id"
  [awg-member]="$awg_member_id"
  [exit-primary]="$exit_primary_id"
  [exit-backup]="$exit_backup_id"
)

for config_name in wg-member awg-member exit-primary exit-backup; do
  client_id=${config_clients[$config_name]}
  api_get "/api/client/${client_id}/configuration" >"${LAB_ARTIFACT_ROOT}/${config_name}.conf"
  chmod 0600 "${LAB_ARTIFACT_ROOT}/${config_name}.conf"
done

clients=$(api_get /api/client)
jq -n \
  --argjson wg_member "$wg_member_id" \
  --argjson awg_member "$awg_member_id" \
  --argjson exit_primary "$exit_primary_id" \
  --argjson exit_backup "$exit_backup_id" \
  --argjson disabled "$disabled_id" \
  --argjson future "$future_id" \
  '{
    "phase0-wg-member": $wg_member,
    "phase0-awg-member": $awg_member,
    "phase0-exit-primary": $exit_primary,
    "phase0-exit-backup": $exit_backup,
    "phase0-disabled": $disabled,
    "phase0-future": $future
  }' >"${LAB_ARTIFACT_ROOT}/client-ids.json"

jq -n \
  --arg wg_member_ip "$(jq -r --argjson id "$wg_member_id" '.[] | select(.id == $id) | .ipv4Address' <<<"$clients")" \
  --arg server_ip 10.251.0.1 \
  --arg sink_ip 172.30.111.100 \
  '{wgMemberIp: $wg_member_ip, serverIp: $server_ip, sinkIp: $sink_ip}' \
  >"${LAB_ARTIFACT_ROOT}/lab-state.json"
chmod 0600 "${LAB_ARTIFACT_ROOT}/client-ids.json" "${LAB_ARTIFACT_ROOT}/lab-state.json"

# Exercise a complete one-time-link lifecycle without persisting its token.
api_post "/api/client/${disabled_id}/generateOneTimeLink" '{}' >/dev/null
clients=$(api_get /api/client)
consumed_token=$(jq -er --argjson id "$disabled_id" '.[] | select(.id == $id) | .oneTimeLink.oneTimeLink' <<<"$clients")
curl --fail --silent --show-error \
  "${PHASE0_API_URL}/cnf/${consumed_token}" >"$link_download"
[ -s "$link_download" ] || fail "one-time-link lifecycle download was empty"

# Leave a fresh, unconsumed row in the baseline. The token remains only in the
# restricted artifact directory and must never be copied into the manifest.
api_post "/api/client/${future_id}/generateOneTimeLink" '{}' >/dev/null
clients=$(api_get /api/client)
fresh_token=$(jq -er --argjson id "$future_id" '.[] | select(.id == $id) | .oneTimeLink.oneTimeLink' <<<"$clients")
printf '%s' "$fresh_token" >"${LAB_ARTIFACT_ROOT}/fresh-one-time-link-token"
chmod 0600 "${LAB_ARTIFACT_ROOT}/fresh-one-time-link-token"

echo "Representative Phase 0 baseline seeded through supported API paths."
