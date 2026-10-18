#!/bin/sh
set -eu

target=${1:?Usage: patch-quick-sysctl.sh /path/to/quick}
needle='[[ $proto == -4 ]] && cmd sysctl -q net.ipv4.conf.all.src_valid_mark=1'
[ "$(grep -Fc "$needle" "$target")" -eq 1 ]

# Docker supplies this namespaced sysctl before startup. A NET_ADMIN container
# cannot rewrite read-only /proc/sys; skip only the already-satisfied write.
sed -i.bak \
  's|\[\[ $proto == -4 \]\] && cmd sysctl -q net\.ipv4\.conf\.all\.src_valid_mark=1|[[ $proto == -4 ]] \&\& [[ $(sysctl -n net.ipv4.conf.all.src_valid_mark) != 1 ]] \&\& cmd sysctl -q net.ipv4.conf.all.src_valid_mark=1|' \
  "$target"
rm -f -- "$target.bak"

grep -Fq '[[ $(sysctl -n net.ipv4.conf.all.src_valid_mark) != 1 ]]' "$target"
