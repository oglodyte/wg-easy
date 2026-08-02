#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=common.sh
source "${SCRIPT_DIR}/common.sh"

manifest_name=${1:-baseline-current.json}
[[ $manifest_name =~ ^[A-Za-z0-9._-]+\.json$ ]] || fail "manifest name must be a simple .json filename"

require_command curl
require_command jq
require_command sha256sum
require_restricted_file "$WG_EASY_ENV_FILE"
load_image_environment

admin_username=$(read_env_value INIT_USERNAME "$WG_EASY_ENV_FILE")
admin_password=$(read_env_value INIT_PASSWORD "$WG_EASY_ENV_FILE")
cookie_jar=$(mktemp)
fingerprints=$(mktemp)

cleanup() {
  rm -f "$cookie_jar" "$fingerprints"
}
trap cleanup EXIT

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

api_get() {
  curl --fail --silent --show-error --cookie "$cookie_jar" "${PHASE0_API_URL}$1"
}

interface=$(api_get /api/admin/interface)
clients=$(api_get /api/client)
hooks=$(api_get /api/admin/hooks)
user_config=$(api_get /api/admin/userconfig)
information=$(api_get /api/information)

hooks_sha=$(jq -cS '{preUp, postUp, preDown, postDown}' <<<"$hooks" | sha256sum | awk '{print $1}')
defaults_sha=$(jq -cS '
  {
    port,
    defaultMtu,
    defaultPersistentKeepalive,
    defaultDns,
    defaultAllowedIps,
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
' <<<"$user_config" | sha256sum | awk '{print $1}')

printf '[]' >"$fingerprints"
for config_name in wg-member awg-member exit-primary exit-backup; do
  config_path=${LAB_ARTIFACT_ROOT}/${config_name}.conf
  require_restricted_file "$config_path"
  config_sha=$(sha256sum "$config_path" | awk '{print $1}')
  updated=$(jq -c \
    --arg name "$config_name" \
    --arg sha "$config_sha" \
    '. + [{name: $name, sha256: $sha}]' "$fingerprints")
  printf '%s\n' "$updated" >"$fingerprints"
done

server_image_id=$("${docker_cmd[@]}" inspect wg-easy-phase0 --format '{{.Image}}')
wg_version=$("${docker_cmd[@]}" run --rm --entrypoint wg "$WG_CLIENT_IMAGE" --version | head -n 1)
awg_version=$("${docker_cmd[@]}" run --rm --entrypoint awg "$AWG_CLIENT_IMAGE" --version | head -n 1)

phase0_artifact_root=$(dirname "$PHASE0_MANIFEST_ROOT")
artifact_parent=$(dirname "$phase0_artifact_root")
sudo -n install -d -m 0710 -o root -g "$(id -gn)" \
  "$artifact_parent" "$phase0_artifact_root"
sudo -n install -d -m 0750 -o "$(id -un)" -g "$(id -gn)" "$PHASE0_MANIFEST_ROOT"
manifest_path=${PHASE0_MANIFEST_ROOT}/${manifest_name}
[ ! -e "$manifest_path" ] || fail "refusing to overwrite existing manifest: $manifest_path"

jq -nS \
  --arg generated_at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --argjson interface "$interface" \
  --argjson clients "$clients" \
  --argjson information "$information" \
  --arg hooks_sha "$hooks_sha" \
  --arg defaults_sha "$defaults_sha" \
  --argjson fingerprints "$(cat "$fingerprints")" \
  --arg server_ref "$WG_EASY_IMAGE" \
  --arg server_image_id "$server_image_id" \
  --arg wg_ref "$WG_CLIENT_IMAGE" \
  --arg awg_ref "$AWG_CLIENT_IMAGE" \
  --arg sink_ref "$TRAFFIC_SINK_IMAGE" \
  --arg wg_version "$wg_version" \
  --arg awg_version "$awg_version" '
  {
    schemaVersion: 1,
    generatedAt: $generated_at,
    release: $information.currentRelease,
    interface: {
      name: $interface.name,
      device: $interface.device,
      port: $interface.port,
      publicKey: $interface.publicKey,
      ipv4Cidr: $interface.ipv4Cidr,
      ipv6Cidr: $interface.ipv6Cidr,
      mtu: $interface.mtu,
      enabled: $interface.enabled,
      firewallEnabled: $interface.firewallEnabled
    },
    clients: ($clients | map({
      id,
      name,
      interfaceId,
      publicKey,
      ipv4Address,
      ipv6Address,
      enabled,
      expiresAt,
      persistentKeepalive,
      serverAllowedIps,
      oneTimeLink: (
        if .oneTimeLink == null then null
        else {id: .oneTimeLink.id, expiresAt: .oneTimeLink.expiresAt}
        end
      )
    }) | sort_by(.id)),
    checksums: {
      hooksSha256: $hooks_sha,
      userConfigSha256: $defaults_sha
    },
    configurationFingerprints: $fingerprints,
    images: {
      server: $server_ref,
      serverImageId: $server_image_id,
      genericWireGuardClient: $wg_ref,
      amneziaWGClient: $awg_ref,
      trafficSink: $sink_ref
    },
    toolVersions: {
      genericWireGuard: $wg_version,
      amneziaWG: $awg_version
    }
  }
' >"$manifest_path"
python3 "${SCRIPT_DIR}/validate-manifest.py" "$manifest_path"
chmod 0640 "$manifest_path"
sha256sum "$manifest_path" >"${manifest_path}.sha256"
chmod 0640 "${manifest_path}.sha256"

echo "$manifest_path"
