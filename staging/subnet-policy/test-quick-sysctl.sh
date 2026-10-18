#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
test_root=$(mktemp -d)
trap 'rm -rf -- "$test_root"' EXIT
cat >"$test_root/quick" <<'QUICK'
set_mark() {
  [[ $proto == -4 ]] && cmd sysctl -q net.ipv4.conf.all.src_valid_mark=1
  :
}
QUICK
sh "$root/staging/phase0/client-lab/patch-quick-sysctl.sh" "$test_root/quick"
bash -n "$test_root/quick"
# shellcheck source=/dev/null
source "$test_root/quick"
cmd() { printf '%s\n' "$*" >>"$test_root/writes"; }
sysctl() { printf '%s\n' "$observed"; }
proto=-4
observed=1
set_mark
[ ! -e "$test_root/writes" ]
observed=0
set_mark
[ "$(cat "$test_root/writes")" = 'sysctl -q net.ipv4.conf.all.src_valid_mark=1' ]
rm -- "$test_root/writes"
proto=-6
set_mark
[ ! -e "$test_root/writes" ]
echo 'Quick sysctl checks passed: preserve a pre-set mark, configure a missing mark, and leave IPv6 unchanged.'
