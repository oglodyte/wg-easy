#!/bin/sh
set -eu

target=${1:?Usage: patch-awg-quick.sh /path/to/awg-quick}

grep -Fq 'if ! cmd ip link add "$INTERFACE" type amneziawg; then' "$target"
grep -Fq '[[ -e /sys/module/amneziawg ]] || ! command -v "${WG_QUICK_USERSPACE_IMPLEMENTATION:-amneziawg-go}" >/dev/null && exit $ret' "$target"

sed -i.bak \
  -e 's#if ! cmd ip link add "$INTERFACE" type amneziawg; then#if [[ ${AWG_FORCE_USERSPACE:-false} == true ]] || ! cmd ip link add "$INTERFACE" type amneziawg; then#' \
  -e 's#\[\[ -e /sys/module/amneziawg \]\] || ! command -v "${WG_QUICK_USERSPACE_IMPLEMENTATION:-amneziawg-go}" >/dev/null && exit $ret#[[ -e /sys/module/amneziawg \&\& ${AWG_FORCE_USERSPACE:-false} != true ]] || ! command -v "${WG_QUICK_USERSPACE_IMPLEMENTATION:-amneziawg-go}" >/dev/null \&\& exit $ret#' \
  -e 's#\[!\] Missing WireGuard (Amnezia VPN) kernel module. Falling back to slow userspace implementation.#[!] Using the slow userspace AmneziaWG implementation (forced or kernel unavailable).#' \
  "$target"
rm -f -- "$target.bak"

grep -Fq 'if [[ ${AWG_FORCE_USERSPACE:-false} == true ]] || ! cmd ip link add "$INTERFACE" type amneziawg; then' "$target"
grep -Fq '[[ -e /sys/module/amneziawg && ${AWG_FORCE_USERSPACE:-false} != true ]] || ! command -v "${WG_QUICK_USERSPACE_IMPLEMENTATION:-amneziawg-go}" >/dev/null && exit $ret' "$target"
