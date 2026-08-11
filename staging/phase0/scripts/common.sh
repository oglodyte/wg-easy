#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
PHASE0_DIR=$(cd "${SCRIPT_DIR}/.." && pwd)
REPOSITORY_ROOT=$(cd "${PHASE0_DIR}/../.." && pwd)

PHASE0_IMAGE_ENV=${PHASE0_IMAGE_ENV:-/opt/wg-easy-staging/secrets/phase0-images.env}
WG_EASY_ENV_FILE=${WG_EASY_ENV_FILE:-/opt/wg-easy-staging/secrets/phase0-server.env}
WG_EASY_VOLUME=${WG_EASY_VOLUME:-wg-easy-phase0-data}
LAB_ARTIFACT_ROOT=${LAB_ARTIFACT_ROOT:-/var/lib/wg-easy-test-artifacts/phase0/configs}
PHASE0_BACKUP_ROOT=${PHASE0_BACKUP_ROOT:-/var/backups/wg-easy-staging/phase0}
PHASE0_MANIFEST_ROOT=${PHASE0_MANIFEST_ROOT:-/var/lib/wg-easy-test-artifacts/phase0/manifests}
PHASE0_API_URL=${PHASE0_API_URL:-http://127.0.0.1:51821}
PHASE0_ENDPOINT_HOST=${PHASE0_ENDPOINT_HOST:-wg-easy-stage.lan}

SERVER_COMPOSE=${PHASE0_DIR}/compose.server.yml
LAB_COMPOSE=${PHASE0_DIR}/compose.lab.yml

docker_cmd=(sudo -n docker)
server_compose=(
  sudo -n --preserve-env=WG_EASY_IMAGE,WG_EASY_ENV_FILE,WG_EASY_VOLUME
  docker compose -f "$SERVER_COMPOSE"
)
lab_compose=(
  sudo -n --preserve-env=WG_CLIENT_IMAGE,AWG_CLIENT_IMAGE,TRAFFIC_SINK_IMAGE,LAB_ARTIFACT_ROOT,AWG_FORCE_USERSPACE
  docker compose -f "$LAB_COMPOSE"
)

fail() {
  echo "Phase 0: $*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || fail "required command is unavailable: $1"
}

require_restricted_file() {
  local path=$1
  local mode

  [ -f "$path" ] || fail "required file is missing: $path"
  [ -r "$path" ] || fail "required file is not readable: $path"
  mode=$(stat -c '%a' "$path")
  if (( (8#$mode & 077) != 0 )); then
    fail "file must not be group/world accessible (expected mode 0600): $path"
  fi
}

require_digest_ref() {
  local name=$1
  local value=$2

  if [[ ! $value =~ ^[a-zA-Z0-9._:/-]+@sha256:[a-f0-9]{64}$ ]]; then
    fail "$name must use an immutable name@sha256:digest reference"
  fi
}

require_endpoint_host() {
  local value=$1

  if [[ ! $value =~ ^[A-Za-z0-9][A-Za-z0-9.-]{0,252}$ ]] ||
    [[ $value == .* ]] || [[ $value == *. ]] || [[ $value == *..* ]]; then
    fail "PHASE0_ENDPOINT_HOST must be a hostname or address without a URL scheme"
  fi
}

load_image_environment() {
  require_restricted_file "$PHASE0_IMAGE_ENV"
  set -a
  # shellcheck disable=SC1090
  source "$PHASE0_IMAGE_ENV"
  set +a

  : "${WG_EASY_IMAGE:?Missing WG_EASY_IMAGE}"
  : "${WG_CLIENT_IMAGE:?Missing WG_CLIENT_IMAGE}"
  : "${AWG_CLIENT_IMAGE:?Missing AWG_CLIENT_IMAGE}"
  : "${TRAFFIC_SINK_IMAGE:?Missing TRAFFIC_SINK_IMAGE}"
  AWG_FORCE_USERSPACE=${AWG_FORCE_USERSPACE:-false}

  if [ "$AWG_FORCE_USERSPACE" != false ] && [ "$AWG_FORCE_USERSPACE" != true ]; then
    fail "AWG_FORCE_USERSPACE must be true or false"
  fi

  require_digest_ref WG_EASY_IMAGE "$WG_EASY_IMAGE"
  require_digest_ref WG_CLIENT_IMAGE "$WG_CLIENT_IMAGE"
  require_digest_ref AWG_CLIENT_IMAGE "$AWG_CLIENT_IMAGE"
  require_digest_ref TRAFFIC_SINK_IMAGE "$TRAFFIC_SINK_IMAGE"
  require_endpoint_host "$PHASE0_ENDPOINT_HOST"

  export WG_EASY_IMAGE WG_CLIENT_IMAGE AWG_CLIENT_IMAGE TRAFFIC_SINK_IMAGE
  export AWG_FORCE_USERSPACE
  export WG_EASY_ENV_FILE WG_EASY_VOLUME LAB_ARTIFACT_ROOT PHASE0_ENDPOINT_HOST
}

read_env_value() {
  local key=$1
  local file=$2
  local value

  value=$(sed -n "s/^${key}=//p" "$file" | tail -n 1)
  [ -n "$value" ] || fail "$key is missing from $file"

  if [[ $value == \"*\" && $value == *\" ]]; then
    value=${value:1:${#value}-2}
  elif [[ $value == \'*\' && $value == *\' ]]; then
    value=${value:1:${#value}-2}
  fi
  printf '%s' "$value"
}

ensure_network() {
  local name=$1
  local subnet=$2
  local internal=${3:-false}
  local actual
  local actual_internal

  if "${docker_cmd[@]}" network inspect "$name" >/dev/null 2>&1; then
    actual=$("${docker_cmd[@]}" network inspect "$name" --format '{{(index .IPAM.Config 0).Subnet}}')
    actual_internal=$("${docker_cmd[@]}" network inspect "$name" --format '{{.Internal}}')
    [ "$actual" = "$subnet" ] || fail "network $name exists with unexpected subnet $actual"
    [ "$actual_internal" = "$internal" ] || fail "network $name has unexpected internal setting $actual_internal"
    return
  fi

  local create_args=(network create --driver bridge --subnet "$subnet" --label com.wg-easy.phase=0)
  if [ "$internal" = true ]; then
    create_args+=(--internal)
  fi
  create_args+=("$name")
  "${docker_cmd[@]}" "${create_args[@]}" >/dev/null
}
