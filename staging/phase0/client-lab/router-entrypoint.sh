#!/bin/sh
set -eu

# This is an operator-controlled lab router, not application route management.
# Each exported profile remains a separate, read-only mount with distinct keys.
umask 077
runtime_dir=/run/wg-easy-router
mkdir -p "$runtime_dir"
started_a=false
started_b=false

cleanup() {
  trap - EXIT INT TERM
  rm -f "$runtime_dir/ready"
  if [ "$started_b" = true ]; then
    awg-quick down "$runtime_dir/site-b.conf" >/dev/null 2>&1 || true
  fi
  if [ "$started_a" = true ]; then
    awg-quick down "$runtime_dir/site-a.conf" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT
trap 'exit 0' INT TERM

for profile in a b; do
  source_config="/run/wg-easy-lab/router-${profile}.conf"
  runtime_config="$runtime_dir/site-${profile}.conf"
  if [ ! -r "$source_config" ]; then
    echo "Router profile ${profile} is missing" >&2
    exit 1
  fi
  # Keep automatic default tables and container DNS out of this two-tunnel lab.
  # Explicit return routes/conntrack marks are configured by the test operator.
  awk '
    /^[[:space:]]*(DNS|Table)[[:space:]]*=/ { next }
    { print }
    /^\[Interface\][[:space:]]*$/ { print "Table = off" }
  ' "$source_config" > "$runtime_config"
  chmod 0600 "$runtime_config"
done

awg-quick up "$runtime_dir/site-a.conf"
started_a=true
awg-quick up "$runtime_dir/site-b.conf"
started_b=true
touch "$runtime_dir/ready"

while :; do
  sleep 3600 &
  wait $!
done
