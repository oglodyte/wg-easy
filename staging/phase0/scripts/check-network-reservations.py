from __future__ import annotations

import ipaddress
import json
import sys


EXPECTED = {
    "wg-easy-phase0-underlay": ipaddress.ip_network("172.30.110.0/24"),
    "wg-easy-phase0-exit-egress": ipaddress.ip_network("172.30.111.0/24"),
    "wg-easy-phase0-application": ipaddress.ip_network("172.30.112.0/24"),
    "wg-easy-phase0-management": ipaddress.ip_network("172.30.113.0/24"),
}


def main() -> None:
    networks = json.load(sys.stdin)
    conflicts: list[str] = []
    for network in networks:
        name = network.get("Name", "unknown")
        ipam = network.get("IPAM") or {}
        for config in ipam.get("Config") or []:
            raw_subnet = config.get("Subnet")
            if not raw_subnet:
                continue
            existing = ipaddress.ip_network(raw_subnet, strict=False)
            for expected_name, expected in EXPECTED.items():
                if existing.version != expected.version or not existing.overlaps(expected):
                    continue
                if name == expected_name and existing == expected:
                    continue
                conflicts.append(f"{expected_name} {expected} overlaps {name} {existing}")

    if conflicts:
        print("\n".join(conflicts), file=sys.stderr)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
