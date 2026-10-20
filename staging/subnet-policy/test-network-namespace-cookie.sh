#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
temporary=$(mktemp -d /tmp/wg-easy-netns-cookie.XXXXXXXX)
trap 'rm -f "$temporary/helper"; rmdir "$temporary"' EXIT
cc -std=c11 -Wall -Wextra -Werror -O2 \
  "$root/src/native/network-namespace-cookie.c" -o "$temporary/helper"

first=$("$temporary/helper")
second=$("$temporary/helper")
[[ $first =~ ^[1-9][0-9]{0,19}$ && $first = "$second" ]]
other=$(unshare --net "$temporary/helper")
replacement=$(unshare --net "$temporary/helper")
[[ $other =~ ^[1-9][0-9]{0,19}$ && $replacement =~ ^[1-9][0-9]{0,19}$ ]]
[[ $other != "$first" && $replacement != "$first" && $other != "$replacement" ]]
printf 'Network namespace cookie PASS: stable repeated reads, distinct namespace lifetimes\n'
