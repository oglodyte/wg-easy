#!/bin/sh
set -eu

readonly_config=${VPN_CONFIG:-/run/wg-easy-lab/client.conf}
runtime_dir=/run/wg-easy-vpn
runtime_config=${runtime_dir}/client.conf
tool=${VPN_TOOL:-wg}

if [ ! -r "$readonly_config" ]; then
  echo "VPN configuration is missing: $readonly_config" >&2
  exit 1
fi

case "$tool" in
  wg)
    quick=wg-quick
    ;;
  awg)
    quick=awg-quick
    ;;
  *)
    echo "Unsupported VPN_TOOL: $tool" >&2
    exit 1
    ;;
esac

mkdir -p "$runtime_dir"
cp "$readonly_config" "$runtime_config"
chmod 0600 "$runtime_config"
# DNS is part of the exported compatibility fingerprint, but container DNS is
# controlled by the isolated lab networks. Avoid mutating read-only resolv.conf.
sed -i '/^DNS[[:space:]]*=/d' "$runtime_config"

cleanup() {
  "$quick" down "$runtime_config" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

"$quick" up "$runtime_config"
touch /run/wg-easy-vpn/ready

while :; do
  sleep 3600 &
  wait $!
done
