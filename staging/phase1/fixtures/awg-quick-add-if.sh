#!/usr/bin/env bash

add_if() {
	local ret
	if ! cmd ip link add "$INTERFACE" type amneziawg; then
		ret=$?
		[[ -e /sys/module/amneziawg ]] || ! command -v "${WG_QUICK_USERSPACE_IMPLEMENTATION:-amneziawg-go}" >/dev/null && exit $ret
		echo "[!] Missing WireGuard (Amnezia VPN) kernel module. Falling back to slow userspace implementation." >&2
		cmd "${WG_QUICK_USERSPACE_IMPLEMENTATION:-amneziawg-go}" "$INTERFACE"
	fi
}
