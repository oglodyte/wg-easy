#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
export WG_CLIENT_IMAGE=ghcr.io/example/wg@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
export AWG_CLIENT_IMAGE=ghcr.io/example/awg@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
export TRAFFIC_SINK_IMAGE=ghcr.io/example/sink@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
export LAB_ARTIFACT_ROOT=/tmp/wg-easy-compose-fixture

docker compose -f "$root/staging/phase0/compose.lab.yml" config --format json |
  python3 -c '
import json,sys
services=json.load(sys.stdin)["services"]
for name in ["wg-member","awg-member","exit-primary","exit-backup"]:
    service=services[name]
    assert not service.get("privileged",False),name
    assert "NET_ADMIN" in service["cap_add"] and "SYS_MODULE" not in service["cap_add"],name
    assert service["read_only"],name
    for key in ["net.ipv4.conf.all.src_valid_mark","net.ipv4.ip_forward","net.ipv6.conf.all.forwarding"]:
        assert str(service["sysctls"][key])=="1",(name,key)
    assert all(m["read_only"] and m["target"]=="/run/wg-easy-lab/client.conf" for m in service["volumes"]),name
    assert set(service["networks"])==({"underlay"} if name.endswith("member") else {"underlay","exit-egress"}),name
print("Composed client capabilities, sysctls, isolated networks and read-only config mounts PASS")
'
