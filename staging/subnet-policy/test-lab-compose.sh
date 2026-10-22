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

docker compose -f "$root/staging/phase0/compose.lab.yml" -f "$root/staging/subnet-policy/compose.router.yml" config --format json |
  python3 -c '
import json,sys
config=json.load(sys.stdin)
services=config["services"]
router=services["subnet-router"]
sink=services["subnet-sink"]
assert router["image"]==services["awg-member"]["image"]
assert router["entrypoint"]==["/usr/local/bin/router-entrypoint"]
assert set(router["networks"])=={"underlay","router-lan","host-site"}
assert set(sink["networks"])=={"router-lan"}
assert set(services["wg-member"]["networks"])=={"underlay"}
assert set(services["awg-member"]["networks"])=={"underlay"}
for service in [router,sink]:
    assert service["read_only"] and not service.get("privileged",False)
    assert service["cap_add"]==["NET_ADMIN"] and not service.get("ports")
assert len(router["volumes"])==2
assert {m["target"] for m in router["volumes"]}=={"/run/wg-easy-lab/router-a.conf","/run/wg-easy-lab/router-b.conf"}
assert all(m["read_only"] and m["type"]=="bind" for m in router["volumes"])
assert sink["environment"]["SINK_IPV6_LISTEN"]=="true"
assert all(config["networks"][n]["external"] for n in ["router-lan","host-site"])
print("Dual-profile router isolation, credentials mounts, privileges and IPv6 sink opt-in PASS")
'
