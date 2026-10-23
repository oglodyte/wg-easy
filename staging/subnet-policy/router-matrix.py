#!/usr/bin/env python3
"""Staging-only HTTP/real-tunnel matrix on an already started restored clone.

Credentials/config exports stay in a restricted artifact directory. Output is
limited to stages, sources, revisions and counters. Never run on production.
"""
from __future__ import annotations

import argparse
import hashlib
import http.cookiejar
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import time
import urllib.error
import urllib.request


GROUPS = "/api/admin/routing-groups"
CLIENT_FIELDS = "name enabled expiresAt ipv4Address ipv6Address preUp postUp preDown postDown allowedIps serverAllowedIps firewallIps mtu jC jMin jMax i1 i2 i3 i4 i5 persistentKeepalive serverEndpoint dns preferredConfigFormat".split()
WG = "wg-easy-phase0-wg-member"
AWG = "wg-easy-phase0-awg-member"
ROUTER = "wg-easy-subnet-router"
SINK = "wg-easy-subnet-sink"
PUBLIC = "198.18.42.100"
LAN = "172.30.114.100"


def emit(stage: str, **values: object) -> None:
    print(json.dumps({"stage": stage, **values}, sort_keys=True), flush=True)


def parse_environment(path: Path) -> dict[str, str]:
    return {
        k: v.strip().strip("\"'")
        for line in path.read_text().splitlines()
        if "=" in line and not line.startswith("#")
        for k, v in [line.split("=", 1)]
    }


class Matrix:
    def __init__(self, args: argparse.Namespace):
        assert socket.gethostname() == "wg-easy-stage", "Dedicated staging only"
        assert (
            args.server_ip
            == {"wg-easy-subnet-p4": "172.30.110.42", "wg-easy-phase0": "172.30.110.2"}[
                args.server
            ]
        ), "Server identity/address mismatch"
        self.args = args
        self.root = args.artifacts.resolve()
        assert str(self.root).startswith(
            "/var/lib/wg-easy-test-artifacts/subnet-policies/"
        )
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.secrets = self.root / "client-configs"
        self.secrets.mkdir(mode=0o700, exist_ok=True)
        self.env = {
            **os.environ,
            **parse_environment(args.images),
            "LAB_ARTIFACT_ROOT": str(self.secrets),
            "AWG_FORCE_USERSPACE": "true",
        }
        for name in (
            "WG_EASY_IMAGE",
            "WG_CLIENT_IMAGE",
            "AWG_CLIENT_IMAGE",
            "TRAFFIC_SINK_IMAGE",
        ):
            immutable = re.fullmatch(r"[\w./:-]+@sha256:[a-f0-9]{64}", self.env[name])
            development = (
                args.development_lab_images
                and args.server == "wg-easy-subnet-p4"
                and name in ("AWG_CLIENT_IMAGE", "TRAFFIC_SINK_IMAGE")
                and re.fullmatch(
                    r"wg-easy-subnet-p4-(awg|sink):dev-[a-f0-9]{12}", self.env[name]
                )
            )
            assert immutable or development, name
        props = json.loads(self.docker("inspect", args.server))[0]
        assert props["Config"]["Image"] == self.env["WG_EASY_IMAGE"]
        assert props["State"]["Health"]["Status"] == "healthy"
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
            urllib.request.ProxyHandler({}),
        )
        credentials = parse_environment(args.server_env)
        self.request(
            "/api/auth/password",
            {
                "username": credentials["INIT_USERNAME"],
                "password": credentials["INIT_PASSWORD"],
                "remember": False,
            },
        )
        self.created_clients: list[int] = []
        self.created_groups: list[int] = []
        self.secret_values: list[str] = []
        self.original = self.request("/api/client")
        self.original_hashes = {
            str(i): hashlib.sha256(
                self.request(f"/api/client/{i}/configuration", raw=True)
            ).hexdigest()
            for i in (1, 2, 3, 4, 8)
        }
        self.original_groups = self.request(GROUPS)["groups"]
        assert (
            len(self.original_groups) == 1
            and self.original_groups[0]["id"] == 1
            and not self.original_groups[0]["enabled"]
        )
        settings = self.request("/api/admin/routing-settings")
        self.health = {
            k: settings[v]
            for k, v in {
                "healthCheckIntervalSeconds": "routingExitHealthCheckIntervalSeconds",
                "healthTimeoutSeconds": "routingExitHealthTimeoutSeconds",
                "minHoldSeconds": "routingExitMinHoldSeconds",
                "failbackDelaySeconds": "routingExitFailbackDelaySeconds",
            }.items()
        }
        source = Path(__file__).resolve().parents[2]
        override = self.root / "endpoint.override.yml"
        override.write_text(
            "services:\n"
            + "".join(
                f'  {service}:\n    extra_hosts: !override ["wg-easy-stage.lan:{args.server_ip}"]\n'
                for service in (
                    "wg-member",
                    "awg-member",
                    "exit-primary",
                    "exit-backup",
                    "subnet-router",
                )
            )
        )
        self.lab = [
            "docker",
            "compose",
            "-p",
            "wg-easy-phase0-lab",
            "-f",
            str(source / "staging/phase0/compose.lab.yml"),
            "-f",
            str(source / "staging/subnet-policy/compose.router.yml"),
            "-f",
            str(override),
        ]
        self.site_attached = False

    def command(
        self, *args: str, check: bool = True, input: str | None = None
    ) -> subprocess.CompletedProcess:
        result = subprocess.run(
            args, input=input, capture_output=True, text=True, env=self.env, timeout=180
        )
        if check and result.returncode:
            # Commands/config output can contain credentials. Never include it.
            raise RuntimeError(
                f"Lab command failed: {args[0]} exit {result.returncode}"
            )
        return result

    def docker(self, *args: str) -> str:
        return self.command("docker", *args).stdout.strip()

    def request(
        self,
        path: str,
        body: object = None,
        method: str | None = None,
        *,
        raw: bool = False,
    ):
        request = urllib.request.Request(
            f"http://{self.args.server_ip}:51821{path}",
            data=None if body is None else json.dumps(body).encode(),
            headers={"Content-Type": "application/json"},
            method=method,
        )
        data = self.opener.open(request, timeout=30).read()
        return data if raw else json.loads(data)

    def idle(self) -> dict:
        for _ in range(100):
            state = self.request(GROUPS)
            if state["lastError"]:
                raise RuntimeError("Policy reconciliation reported an error")
            if (
                state["status"] == "idle"
                and state["desiredRevision"] == state["appliedRevision"]
            ):
                return state
            time.sleep(1)
        raise RuntimeError("Desired policy was not verified applied")

    def selected(self, group: int, status: str, client: int | None) -> None:
        for _ in range(270):
            state = self.request(f"{GROUPS}/{group}")["runtime"]
            if state["status"] == status and state["appliedExitClientId"] == client:
                self.idle()
                emit("selection", group=group, status=status, client=client)
                return
            time.sleep(1)
        raise RuntimeError("Exit health/selection did not converge")

    def profile(self, client: int, **changes: object) -> None:
        saved = self.request(f"/api/client/{client}")
        self.request(
            f"/api/client/{client}", {**{k: saved[k] for k in CLIENT_FIELDS}, **changes}
        )
        self.idle()

    def export(self, role: str, client: int) -> None:
        data = self.request(f"/api/client/{client}/configuration", raw=True)
        path = self.secrets / (role + ".conf")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
        self.secret_values.extend(
            line.split(" = ", 1)[1]
            for line in data.decode().splitlines()
            if line.startswith(("PrivateKey = ", "PresharedKey = "))
        )

    def create_group(self, data: dict) -> int:
        result = self.request(GROUPS, data)
        identifier = result["group"]["id"]
        self.created_groups.append(identifier)
        self.idle()
        return identifier

    def update(self, group: int, data: dict) -> None:
        self.request(f"{GROUPS}/{group}", data)
        self.idle()

    def reject(
        self,
        path: str,
        body: object = None,
        method: str | None = None,
        codes: tuple = (409,),
    ) -> None:
        before = self.request(GROUPS)
        identity_fields = "id enabled interfaceId ipv4Address ipv6Address publicKey serverAllowedIps".split()
        clients_before = [
            {k: c[k] for k in identity_fields} for c in self.request("/api/client")
        ]
        try:
            self.request(path, body, method)
        except urllib.error.HTTPError as error:
            assert error.code in codes, f"Unexpected rejection status {error.code}"
        else:
            raise RuntimeError("Invalid final state was accepted")
        after = self.request(GROUPS)
        assert before["desiredRevision"] == after["desiredRevision"]
        fields = "id name enabled natEnabled allExitsDownPolicy routedIpv4Prefixes excludedIpv4Prefixes members exits".split()
        assert [{k: g[k] for k in fields} for g in before["groups"]] == [
            {k: g[k] for k in fields} for g in after["groups"]
        ]
        assert clients_before == [
            {k: c[k] for k in identity_fields} for c in self.request("/api/client")
        ]

    def traffic(
        self, member: str, destination: str, expected: str | None, label: str
    ) -> None:
        self.idle()
        host = f"[{destination}]" if ":" in destination else destination
        url = f"http://{host}:8080/{label}-{time.time_ns()}"
        if member == self.args.server:
            # The shipped server has Node, but deliberately does not need curl.
            client = [
                "node",
                "--input-type=module",
                "-e",
                "const r=await fetch(process.argv[1],{signal:AbortSignal.timeout(5000)});if(!r.ok)process.exit(1);process.stdout.write(await r.text())",
                url,
            ]
        else:
            client = [
                "curl",
                "--noproxy",
                "*",
                "--fail",
                "--silent",
                "--max-time",
                "5",
                url,
            ]
        result = self.command("docker", "exec", member, *client, check=False)
        assert result.returncode not in (126, 127), "Traffic tool unavailable"
        if expected is None:
            assert result.returncode != 0, f"Unexpected reachable path: {label}"
        else:
            assert (
                result.returncode == 0
            ), f"Traffic failed: {label}; exit {result.returncode}"
            assert (
                json.loads(result.stdout)["sourceAddress"] == expected
            ), f"Incorrect source: {label}"
        emit(
            "new-flow",
            label=label,
            member=member,
            destination=destination,
            source=expected,
            denied=expected is None,
        )

    def route_device(self, container: str, address: str) -> str:
        device = json.loads(
            self.docker("exec", container, "ip", "-j", "route", "get", address)
        )[0]["dev"]
        assert re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", device)
        return device

    def router_os(self) -> None:
        # The router is an isolated new namespace. Only these named lab chains,
        # two reserved marks and two tables are owned by this test operator.
        lan = self.route_device(ROUTER, LAN)
        site = self.route_device(ROUTER, "172.30.115.3")
        for binary in ("iptables", "ip6tables"):
            self.command(
                "docker", "exec", ROUTER, binary, "-N", "WGEP4_LAN", check=False
            )
            self.docker("exec", ROUTER, binary, "-F", "WGEP4_LAN")
            if self.command(
                "docker",
                "exec",
                ROUTER,
                binary,
                "-C",
                "FORWARD",
                "-j",
                "WGEP4_LAN",
                check=False,
            ).returncode:
                self.docker(
                    "exec", ROUTER, binary, "-I", "FORWARD", "1", "-j", "WGEP4_LAN"
                )
            for device in ("site-a", "site-b", site):
                self.docker(
                    "exec",
                    ROUTER,
                    binary,
                    "-A",
                    "WGEP4_LAN",
                    "-i",
                    device,
                    "-o",
                    lan,
                    "-j",
                    "ACCEPT",
                )
            self.docker(
                "exec",
                ROUTER,
                binary,
                "-A",
                "WGEP4_LAN",
                "-i",
                lan,
                "-m",
                "conntrack",
                "--ctstate",
                "ESTABLISHED,RELATED",
                "-j",
                "ACCEPT",
            )
            self.docker("exec", ROUTER, binary, "-A", "WGEP4_LAN", "-j", "DROP")
        for device, table, mark, priority in (
            ("site-a", "100", "0x71", "1000"),
            ("site-b", "101", "0x72", "1001"),
        ):
            for prefix in ("10.251.0.0/24", "10.252.0.0/24"):
                self.docker(
                    "exec",
                    ROUTER,
                    "ip",
                    "route",
                    "replace",
                    "table",
                    table,
                    prefix,
                    "dev",
                    device,
                )
            self.command(
                "docker",
                "exec",
                ROUTER,
                "ip",
                "rule",
                "del",
                "priority",
                priority,
                check=False,
            )
            self.docker(
                "exec",
                ROUTER,
                "ip",
                "rule",
                "add",
                "priority",
                priority,
                "fwmark",
                mark,
                "lookup",
                table,
            )
        self.command(
            "docker",
            "exec",
            ROUTER,
            "iptables",
            "-t",
            "mangle",
            "-N",
            "WGEP4_RETURN",
            check=False,
        )
        self.docker("exec", ROUTER, "iptables", "-t", "mangle", "-F", "WGEP4_RETURN")
        if self.command(
            "docker",
            "exec",
            ROUTER,
            "iptables",
            "-t",
            "mangle",
            "-C",
            "PREROUTING",
            "-j",
            "WGEP4_RETURN",
            check=False,
        ).returncode:
            self.docker(
                "exec",
                ROUTER,
                "iptables",
                "-t",
                "mangle",
                "-I",
                "PREROUTING",
                "1",
                "-j",
                "WGEP4_RETURN",
            )
        for device, mark in (("site-a", "0x71"), ("site-b", "0x72")):
            self.docker(
                "exec",
                ROUTER,
                "iptables",
                "-t",
                "mangle",
                "-A",
                "WGEP4_RETURN",
                "-i",
                device,
                "-j",
                "CONNMARK",
                "--set-mark",
                mark,
            )
        self.docker(
            "exec",
            ROUTER,
            "iptables",
            "-t",
            "mangle",
            "-A",
            "WGEP4_RETURN",
            "-i",
            lan,
            "-j",
            "CONNMARK",
            "--restore-mark",
        )
        for prefix, device in (
            ("10.251.0.0/24", "site-a"),
            ("10.252.0.0/24", "site-b"),
            ("fd42:251::/64", "site-a"),
            # IPv6 stays on the legacy site owner a, even for members of b's
            # server interface. It is not part of IPv4 common-routing failover.
            ("fd42:252::/64", "site-a"),
        ):
            self.docker("exec", ROUTER, "ip", "route", "replace", prefix, "dev", device)
        for prefix in ("fd42:251::/64", "fd42:252::/64"):
            self.docker(
                "exec",
                SINK,
                "ip",
                "-6",
                "route",
                "replace",
                prefix,
                "via",
                "fd42:114::2",
            )

        for prefix in ("10.251.0.0/24", "10.252.0.0/24", "172.30.115.0/24"):
            self.docker(
                "exec", SINK, "ip", "route", "replace", prefix, "via", "172.30.114.2"
            )
        for address, gateway in (
            ("10.251.0.1", "172.30.114.2"),
            ("10.252.0.1", "172.30.114.2"),
            ("172.30.115.3", "172.30.114.2"),
            ("fd42:251::2", "fd42:114::2"),
            ("fd42:252::2", "fd42:114::2"),
        ):
            returned = json.loads(
                self.docker("exec", SINK, "ip", "-j", "route", "get", address)
            )[0]
            assert (
                returned.get("gateway") == gateway
            ), "Missing explicit sink return route"

    def prepare(self) -> tuple[int, int]:
        existing = set(self.docker("ps", "-a", "--format", "{{.Names}}").splitlines())
        assert not existing.intersection(
            {
                WG,
                AWG,
                ROUTER,
                SINK,
                "wg-easy-phase0-exit-primary",
                "wg-easy-phase0-exit-backup",
            }
        )
        self.request(
            "/api/admin/routing-settings",
            {
                "healthCheckIntervalSeconds": 10,
                "healthTimeoutSeconds": 180,
                "minHoldSeconds": 0,
                "failbackDelaySeconds": 0,
            },
        )
        router_ids = []
        credentials_by_id = {}
        for interface in ("wg0", "awg-p2"):
            private = self.docker("exec", self.args.server, "awg", "genkey")
            psk = self.docker("exec", self.args.server, "awg", "genpsk")
            public = self.command(
                "docker",
                "exec",
                "-i",
                self.args.server,
                "awg",
                "pubkey",
                input=private + "\n",
            ).stdout.strip()
            self.secret_values.extend((private, psk))
            created = self.request(
                "/api/client",
                {
                    "name": "Phase4 router " + interface,
                    "interfaceId": interface,
                    "privateKey": private,
                    "publicKey": public,
                    "preSharedKey": psk,
                    "dns": [],
                    "persistentKeepalive": 25,
                    "mtu": 1280,
                },
            )
            identifier = created["clientId"]
            self.created_clients.append(identifier)
            router_ids.append(identifier)
            credentials_by_id[identifier] = (private, psk)
            assert self.request(f"/api/client/{identifier}")["publicKey"] == public
        for role, identifier in (
            ("wg-member", 1),
            ("awg-member", 8),
            ("exit-primary", 3),
            ("exit-backup", 4),
            ("router-a", router_ids[0]),
            ("router-b", router_ids[1]),
        ):
            self.export(role, identifier)
            if identifier in credentials_by_id:
                exported = dict(
                    line.split(" = ", 1)
                    for line in (self.secrets / (role + ".conf"))
                    .read_text()
                    .splitlines()
                    if " = " in line
                )
                assert (
                    exported["PrivateKey"],
                    exported["PresharedKey"],
                ) == credentials_by_id[identifier]
        self.command(*self.lab, "config", "--quiet")
        self.command(*self.lab, "up", "-d")
        for _ in range(90):
            if not self.command(
                "docker",
                "exec",
                ROUTER,
                "test",
                "-f",
                "/run/wg-easy-router/ready",
                check=False,
            ).returncode:
                break
            time.sleep(1)
        else:
            raise RuntimeError("Dual-profile router did not start")
        self.router_os()
        self.docker(
            "exec",
            "wg-easy-phase0-traffic-sink",
            "ip",
            "address",
            "add",
            PUBLIC + "/32",
            "dev",
            "lo",
        )
        for container in ("wg-easy-phase0-exit-primary", "wg-easy-phase0-exit-backup"):
            device = self.route_device(container, "172.30.111.100")
            self.docker(
                "exec",
                container,
                "ip",
                "route",
                "add",
                PUBLIC + "/32",
                "via",
                "172.30.111.100",
                "dev",
                device,
            )
            self.docker(
                "exec",
                container,
                "iptables",
                "-t",
                "nat",
                "-A",
                "POSTROUTING",
                "-d",
                PUBLIC + "/32",
                "-o",
                device,
                "-j",
                "MASQUERADE",
            )
        for container in (WG, AWG):
            for _ in range(60):
                tool = "wg" if container == WG else "awg"
                fields = self.docker(
                    "exec", container, tool, "show", "client", "latest-handshakes"
                ).split()
                if len(fields) == 2 and int(fields[1]) > 0:
                    break
                time.sleep(1)
            else:
                raise RuntimeError("Independent member handshake failed")
        self.idle()
        emit(
            "lab-ready",
            routerProfilesDistinct=True,
            genericWireGuard=True,
            obfuscatedAwg=True,
        )
        return tuple(router_ids)

    def run(self) -> None:
        a, b = self.prepare()

        def exit_(identifier: int, priority: int) -> dict:
            return {"clientId": identifier, "priority": priority, "enabled": True}

        internet = {
            "name": "Phase4 internet",
            "enabled": True,
            "natEnabled": True,
            "allExitsDownPolicy": "block",
            "routedIpv4Prefixes": ["0.0.0.0/0"],
            "excludedIpv4Prefixes": ["172.30.111.100/32"],
            "memberClientIds": [1, 8],
            "exits": [exit_(4, 0), exit_(3, 1)],
        }
        # Primary b is on another output interface. Only adding backup a on
        # wg0 makes differing source scopes unrepresentable.
        lan = {
            **internet,
            "name": "Phase4 LAN",
            "routedIpv4Prefixes": ["172.30.114.0/24"],
            "excludedIpv4Prefixes": [],
            "memberClientIds": [1],
            "exits": [exit_(b, 0)],
        }
        lan_id = self.create_group(lan)
        internet_id = self.create_group(internet)
        self.selected(lan_id, "active", b)
        self.traffic(
            WG, LAN, "10.252.0.1", "differing-lan-policy-valid-cross-interface"
        )
        self.traffic(
            AWG, PUBLIC, "172.30.111.11", "differing-lan-policy-independent-internet"
        )
        self.reject(f"{GROUPS}/{lan_id}", {**lan, "exits": [exit_(b, 0), exit_(a, 1)]})
        emit("backup-only-conflict", rejectedBeforeSave=True, revisionUnchanged=True)
        lan = {**lan, "memberClientIds": [1, 8], "exits": [exit_(b, 0), exit_(a, 1)]}
        self.update(lan_id, lan)
        self.selected(internet_id, "active", 4)
        bypass = self.request(
            GROUPS + "/preview",
            {
                "groupId": lan_id,
                "group": lan,
                "memberClientId": 1,
                "destinationIpv4": "10.252.0.2",
            },
        )
        assert bypass["explanation"]["outcome"] == "managed_network_bypass"
        self.docker("exec", WG, "ping", "-c", "2", "-W", "2", "10.252.0.2")
        emit("managed-network-bypass", preview=True, realCrossInterfaceTraffic=True)
        for member in (WG, AWG):
            self.traffic(member, PUBLIC, "172.30.111.11", "aligned-internet")
            self.traffic(member, LAN, "10.252.0.1", "aligned-lan-b")
        self.profile(a, serverAllowedIps=["172.30.114.0/24", "fd42:114::/64"])
        self.traffic(self.args.server, LAN, "10.251.0.1", "unmarked-legacy")
        self.traffic(WG, "fd42:114::100", "fd42:251::2", "unchanged-ipv6-legacy")
        self.traffic(
            AWG, "fd42:114::100", "fd42:252::2", "unchanged-ipv6-cross-interface-legacy"
        )
        self.update(lan_id, {**lan, "natEnabled": False})
        self.traffic(WG, LAN, "10.251.0.2", "nat-off-b-return-ownership")
        self.traffic(AWG, LAN, "10.252.0.2", "nat-off-b-awg")
        self.update(lan_id, lan)
        self.docker(
            "exec", ROUTER, "awg-quick", "down", "/run/wg-easy-router/site-b.conf"
        )
        self.selected(lan_id, "active", a)
        for member in (WG, AWG):
            self.traffic(
                member, LAN, "10.251.0.1", "one-tunnel-loss-same-router-survives"
            )
            self.traffic(member, PUBLIC, "172.30.111.11", "internet-unaffected")
        self.docker(
            "exec", ROUTER, "awg-quick", "up", "/run/wg-easy-router/site-b.conf"
        )
        self.router_os()
        self.selected(lan_id, "active", b)
        self.docker("stop", "--time", "10", ROUTER)
        self.selected(lan_id, "blocked", None)
        for member in (WG, AWG):
            self.traffic(member, LAN, None, "whole-router-loss-blocked")
            self.traffic(
                member, PUBLIC, "172.30.111.11", "whole-router-loss-internet-survives"
            )
        self.docker("start", ROUTER)
        for _ in range(60):
            if not self.command(
                "docker",
                "exec",
                ROUTER,
                "test",
                "-f",
                "/run/wg-easy-router/ready",
                check=False,
            ).returncode:
                break
            time.sleep(1)
        self.router_os()
        self.selected(lan_id, "active", b)
        self.traffic(WG, LAN, "10.252.0.1", "whole-router-recovered")
        # A legacy owner becomes incompatible with a broader internet exit if
        # this specific policy is removed, disabled, or loses a member.
        self.reject(f"{GROUPS}/{lan_id}", method="DELETE")
        self.reject(f"{GROUPS}/{lan_id}", {**lan, "enabled": False})
        self.reject(f"{GROUPS}/{lan_id}", {**lan, "memberClientIds": [1]})
        internet["excludedIpv4Prefixes"] = [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
        ]
        self.update(internet_id, internet)
        self.update(lan_id, {**lan, "enabled": False})
        self.traffic(WG, LAN, "10.251.0.2", "disabled-lan-safe-legacy-exclusion")
        self.update(lan_id, lan)
        self.traffic(WG, LAN, "10.252.0.1", "specific-lan-over-private-exclusion")
        self.alternatives(a, b, lan_id, lan)
        self.credentials(b, lan_id)
        rank = {
            **internet,
            "name": "Phase4 original rank",
            "routedIpv4Prefixes": ["128.0.0.0/1"],
            "excludedIpv4Prefixes": list(internet["excludedIpv4Prefixes"]),
            "exits": [exit_(4, 0)],
        }
        preview = self.request(
            GROUPS + "/preview",
            {"group": rank, "memberClientId": 1, "destinationIpv4": PUBLIC},
        )
        assert preview["explanation"]["winner"]["originalPrefix"] == "128.0.0.0/1"
        self.reject(GROUPS + "/preview", {"group": internet})
        excessive = {
            **rank,
            "routedIpv4Prefixes": [
                str(ipaddress.ip_network(f"203.0.113.{i}/32")) for i in range(65)
            ],
        }
        self.reject(GROUPS + "/preview", {"group": excessive}, codes=(400, 409))
        self.reject(GROUPS, excessive, codes=(400, 409))
        emit(
            "precedence-negative-matrix",
            originalPrefixRank=True,
            tiedGroupRejected=True,
            budgetRejected=True,
            exposureDeleteDisableMemberRemovalRejected=True,
        )
        self.broader_selection(a, lan_id, lan, internet_id, internet)
        self.host_path(lan_id, lan)
        self.traffic(WG, LAN, "10.252.0.1", "restored-after-host-action")
        prefer_a = {**lan, "natEnabled": False, "exits": [exit_(a, 0), exit_(b, 1)]}
        self.update(lan_id, prefer_a)
        self.selected(lan_id, "active", a)
        self.traffic(WG, LAN, "10.251.0.2", "nat-off-a-return-ownership")
        self.traffic(AWG, LAN, "10.252.0.2", "nat-off-a-cross-interface-return")
        self.update(lan_id, lan)
        self.selected(lan_id, "active", b)
        self.docker("exec", WG, "wg-quick", "down", "/run/wg-easy-vpn/client.conf")
        self.traffic(WG, LAN, None, "member-without-tunnel-denied")
        self.docker("exec", WG, "wg-quick", "up", "/run/wg-easy-vpn/client.conf")
        self.traffic(WG, LAN, "10.252.0.1", "member-tunnel-restored")
        self.traffic(
            WG, "fd42:114::100", "fd42:251::2", "ipv6-legacy-after-all-transitions"
        )
        self.traffic(
            AWG,
            "fd42:114::100",
            "fd42:252::2",
            "ipv6-cross-interface-after-all-transitions",
        )
        counters = []
        for container, tool, device in (
            (WG, "wg", "client"),
            (AWG, "awg", "client"),
            (ROUTER, "awg", "site-a"),
            (ROUTER, "awg", "site-b"),
        ):
            fields = self.docker(
                "exec", container, tool, "show", device, "transfer"
            ).split()
            assert len(fields) == 3 and int(fields[1]) > 0 and int(fields[2]) > 0
            counters.append(
                {
                    "container": container,
                    "device": device,
                    "received": int(fields[1]),
                    "sent": int(fields[2]),
                }
            )
        emit("router-matrix-traffic-PASS", counters=counters)

    def restart_router(self) -> None:
        self.command(*self.lab, "up", "-d", "--force-recreate", "subnet-router")
        for _ in range(90):
            if not self.command(
                "docker",
                "exec",
                ROUTER,
                "test",
                "-f",
                "/run/wg-easy-router/ready",
                check=False,
            ).returncode:
                self.router_os()
                return
            time.sleep(1)
        raise RuntimeError("Router replacement did not become ready")

    def broader_selection(
        self, a: int, group: int, lan: dict, internet_id: int, internet: dict
    ) -> None:
        self.profile(a, serverAllowedIps=["fd42:114::/64"])
        self.update(
            internet_id, {**internet, "excludedIpv4Prefixes": ["172.30.111.100/32"]}
        )
        self.update(group, {**lan, "enabled": False})
        preview = self.request(
            GROUPS + "/preview",
            {
                "groupId": internet_id,
                "group": {**internet, "excludedIpv4Prefixes": ["172.30.111.100/32"]},
                "memberClientId": 1,
                "destinationIpv4": LAN,
            },
        )
        assert preview["explanation"]["winner"]["groupId"] == internet_id
        assert preview["explanation"]["winner"]["originalPrefix"] == "0.0.0.0/0"
        peer = self.request("/api/client/4")["publicKey"]
        allowed = self.docker(
            "exec", self.args.server, "awg", "show", "wg0", "allowed-ips"
        ).splitlines()
        prefixes = next(
            line.split(None, 1)[1] for line in allowed if line.split()[0] == peer
        )
        assert any(
            ipaddress.ip_address(LAN) in ipaddress.ip_network(prefix.strip())
            for prefix in re.split(r"[,\s]+", prefixes.strip())
            if prefix and ":" not in prefix
        )

        # The internet exit has no path into this isolated LAN. Prove the new
        # intended owner, without claiming a successful LAN connection.
        def sent() -> int:
            rows = self.docker(
                "exec", self.args.server, "awg", "show", "wg0", "transfer"
            ).splitlines()
            return int(
                next(line.split()[2] for line in rows if line.split()[0] == peer)
            )

        before = sent()
        self.traffic(WG, LAN, None, "disabled-lan-broader-exit-has-no-lan-route")
        assert sent() > before
        self.update(group, lan)
        self.profile(a, serverAllowedIps=["172.30.114.0/24", "fd42:114::/64"])
        self.update(internet_id, internet)
        emit(
            "disabled-specific-broader-selection-PASS",
            explicitPolicyChange=True,
            broaderOriginalPrefix="0.0.0.0/0",
            actualPeerOwnerAndTransmit=True,
            lanConnectivityClaimed=False,
        )

    def alternatives(self, a: int, b: int, group: int, lan: dict) -> None:
        saved = self.request(f"/api/client/{a}")
        exported = dict(
            line.split(" = ", 1)
            for line in (self.secrets / "router-a.conf").read_text().splitlines()
            if " = " in line
        )
        base = {
            **{k: saved[k] for k in CLIENT_FIELDS},
            "enabled": False,
            "interfaceId": "wg0",
            "privateKey": exported["PrivateKey"],
            "publicKey": saved["publicKey"],
            "preSharedKey": exported.get("PresharedKey"),
        }
        # Disabled alternatives may share keys/addresses, but legacy subnet
        # declarations retain their global uniqueness even while disabled.
        self.reject(
            "/api/client", {**base, "name": "Phase4 duplicate legacy declaration"}
        )
        base["serverAllowedIps"] = []
        alternative = self.request(
            "/api/client", {**base, "name": "Phase4 disabled same-key alternative"}
        )["clientId"]
        self.created_clients.append(alternative)
        self.reject(f"/api/client/{alternative}/enable", {})
        assert not self.request(f"/api/client/{alternative}")["enabled"]
        self.request(f"/api/client/{a}/disable", {})
        self.request(f"/api/client/{alternative}/enable", {})
        self.idle()
        peers = self.docker(
            "exec", self.args.server, "awg", "show", "wg0", "peers"
        ).split()
        assert peers.count(saved["publicKey"]) == 1
        enabled = [
            c
            for c in self.request("/api/client")
            if c["enabled"]
            and c["interfaceId"] == "wg0"
            and c["publicKey"] == saved["publicKey"]
        ]
        assert [c["id"] for c in enabled] == [alternative]
        selected = {
            **lan,
            "exits": [
                {"clientId": alternative, "priority": 0, "enabled": True},
                {"clientId": b, "priority": 1, "enabled": True},
            ],
        }
        self.update(group, selected)
        self.selected(group, "active", alternative)
        self.traffic(
            WG, LAN, "10.251.0.1", "disabled-alternative-now-sole-active-source"
        )
        self.update(group, lan)
        self.request(f"/api/client/{alternative}/disable", {})
        self.request(f"/api/client/{a}/enable", {})
        self.idle()
        self.request(f"/api/client/{alternative}", method="DELETE")
        self.created_clients.remove(alternative)
        self.selected(group, "active", b)
        emit(
            "disabled-alternative-PASS",
            simultaneousEnableRejected=True,
            disableThenEnable=True,
            sameAddressAndKeyPreserved=True,
            singleActiveRuntimePeer=True,
        )

    def credentials(self, client: int, group: int) -> None:
        saved_group = self.request(f"{GROUPS}/{group}")
        original = {
            k: saved_group[k]
            for k in [
                "name",
                "enabled",
                "natEnabled",
                "allExitsDownPolicy",
                "routedIpv4Prefixes",
                "excludedIpv4Prefixes",
            ]
        }
        original["memberClientIds"] = [m["clientId"] for m in saved_group["members"]]
        original["exits"] = [
            {k: e[k] for k in ["clientId", "priority", "enabled"]}
            for e in saved_group["exits"]
        ]
        # Keep this credential-denial test independent of healthy backup a.
        # The full matrix separately proves automatic failover through a.
        self.update(
            group,
            {
                **original,
                "exits": [{"clientId": client, "priority": 0, "enabled": True}],
            },
        )
        before = self.request(f"/api/client/{client}")
        self.request(f"/api/client/{client}/generateOneTimeLink", {})
        link = next(c for c in self.request("/api/client") if c["id"] == client)[
            "oneTimeLink"
        ]
        private = self.docker("exec", self.args.server, "awg", "genkey")
        psk = self.docker("exec", self.args.server, "awg", "genpsk")
        public = self.command(
            "docker",
            "exec",
            "-i",
            self.args.server,
            "awg",
            "pubkey",
            input=private + "\n",
        ).stdout.strip()
        self.secret_values.extend((private, psk))
        self.profile(client, privateKey=private, publicKey=public, preSharedKey=psk)
        peers = self.docker(
            "exec", self.args.server, "awg", "show", "awg-p2", "peers"
        ).split()
        assert before["publicKey"] not in peers and peers.count(public) == 1
        retired = self.command(
            "docker",
            "exec",
            ROUTER,
            "curl",
            "--noproxy",
            "*",
            "--interface",
            "site-b",
            "--fail",
            "--silent",
            "--max-time",
            "3",
            "http://10.252.0.1:51821/api/health",
            check=False,
        )
        assert retired.returncode not in (
            0,
            126,
            127,
        ), "Retired router credential unexpectedly usable"
        self.traffic(
            WG, LAN, None, "retired-router-credentials-denied-before-reconfigure"
        )
        self.traffic(
            WG, PUBLIC, "172.30.111.11", "credentials-unrelated-internet-continuity"
        )
        self.export("router-b", client)
        config = dict(
            line.split(" = ", 1)
            for line in (self.secrets / "router-b.conf").read_text().splitlines()
            if " = " in line
        )
        assert config["PrivateKey"] == private and config["PresharedKey"] == psk
        self.restart_router()
        self.selected(group, "active", client)
        self.traffic(WG, LAN, "10.252.0.1", "replaced-key-and-psk-real-traffic")
        self.profile(client, preSharedKey=None)
        self.export("router-b", client)
        assert "PresharedKey = " not in (self.secrets / "router-b.conf").read_text()
        self.restart_router()
        self.selected(group, "active", client)
        self.traffic(AWG, LAN, "10.252.0.1", "cleared-psk-real-traffic")
        after = next(c for c in self.request("/api/client") if c["id"] == client)
        assert after["oneTimeLink"]["oneTimeLink"] == link["oneTimeLink"]
        assert all(
            before[k] == after[k]
            for k in ("id", "interfaceId", "userId", "ipv4Address", "ipv6Address")
        )
        assert not self.request(f"/api/client/{client}")["hasPreSharedKey"]
        self.update(group, original)
        self.selected(group, "active", client)
        emit(
            "credential-matrix-PASS",
            independentSuppliedKey=True,
            derivedPublicKeyAndExport=True,
            replacementKeyAndPsk=True,
            retiredPeerRemovedAndDenied=True,
            clearedPsk=True,
            referencesUnchanged=True,
            unrelatedTrafficContinuous=True,
        )

    def host_path(self, group: int, lan: dict) -> None:
        # The independent host path must not be shadowed by a legacy site
        # table route through a tunnel that this test deliberately takes down.
        a = self.created_clients[0]
        self.profile(a, serverAllowedIps=["fd42:114::/64"])
        self.docker(
            "network",
            "connect",
            "--ip",
            "172.30.115.3",
            "wg-easy-subnet-host-site",
            self.args.server,
        )
        self.site_attached = True
        device = self.route_device(self.args.server, "172.30.115.2")
        self.docker(
            "exec",
            self.args.server,
            "ip",
            "route",
            "add",
            LAN + "/32",
            "via",
            "172.30.115.2",
            "dev",
            device,
            "proto",
            "static",
        )
        host_route = json.loads(
            self.docker("exec", self.args.server, "ip", "-j", "route", "get", LAN)
        )[0]
        assert (
            host_route.get("gateway") == "172.30.115.2"
            and host_route.get("prefsrc") == "172.30.115.3"
        )
        self.traffic(
            self.args.server,
            LAN,
            "172.30.115.3",
            "independently-verified-host-site-route",
        )
        for tunnel in ("site-a", "site-b"):
            self.docker(
                "exec",
                ROUTER,
                "awg-quick",
                "down",
                f"/run/wg-easy-router/{tunnel}.conf",
            )
        site = self.route_device(ROUTER, "172.30.115.3")
        for prefix in ("10.251.0.0/24", "10.252.0.0/24"):
            self.docker(
                "exec",
                ROUTER,
                "ip",
                "route",
                "replace",
                prefix,
                "via",
                "172.30.115.3",
                "dev",
                site,
            )
        self.selected(group, "blocked", None)
        self.traffic(WG, LAN, None, "block-does-not-leak-host-route")
        self.update(group, {**lan, "allExitsDownPolicy": "host"})
        self.selected(group, "host_fallback", None)
        self.traffic(WG, LAN, "10.251.0.2", "terminal-host-verified-site-route")
        self.traffic(AWG, PUBLIC, "172.30.111.11", "terminal-host-internet-unchanged")
        for tunnel in ("site-a", "site-b"):
            self.docker(
                "exec", ROUTER, "awg-quick", "up", f"/run/wg-easy-router/{tunnel}.conf"
            )
        self.router_os()
        self.update(group, lan)
        self.selected(group, "active", self.created_clients[1])
        self.docker(
            "exec",
            self.args.server,
            "ip",
            "route",
            "del",
            LAN + "/32",
            "via",
            "172.30.115.2",
            "dev",
            device,
            "proto",
            "static",
        )
        self.docker(
            "network", "disconnect", "wg-easy-subnet-host-site", self.args.server
        )
        self.site_attached = False
        self.profile(a, serverAllowedIps=["172.30.114.0/24", "fd42:114::/64"])

    def cleanup(self) -> None:
        # Remove the broad group first, so withdrawing LAN ownership is safe.
        for group in reversed(self.created_groups):
            self.request(f"{GROUPS}/{group}", method="DELETE")
        for client in reversed(self.created_clients):
            self.request(f"/api/client/{client}", method="DELETE")
        self.request("/api/admin/routing-settings", self.health)
        self.idle()
        self.command(*self.lab, "down", "--remove-orphans")
        if self.site_attached:
            self.command(
                "docker",
                "exec",
                self.args.server,
                "ip",
                "route",
                "del",
                LAN + "/32",
                "via",
                "172.30.115.2",
                "proto",
                "static",
                check=False,
            )
            self.docker(
                "network", "disconnect", "wg-easy-subnet-host-site", self.args.server
            )
        assert {c["id"] for c in self.request("/api/client")} == {
            c["id"] for c in self.original
        }
        assert {
            str(i): hashlib.sha256(
                self.request(f"/api/client/{i}/configuration", raw=True)
            ).hexdigest()
            for i in (1, 2, 3, 4, 8)
        } == self.original_hashes
        result = self.command("docker", "logs", self.args.server)
        logs = result.stdout + result.stderr
        assert not any(value in logs for value in self.secret_values)
        fields = "id name enabled natEnabled allExitsDownPolicy routedIpv4Prefixes excludedIpv4Prefixes members exits".split()
        assert [{k: g[k] for k in fields} for g in self.request(GROUPS)["groups"]] == [
            {k: g[k] for k in fields} for g in self.original_groups
        ]
        emit(
            "cleanup-PASS",
            originalProfilesPreserved=True,
            fiveOriginalExportsUnchanged=True,
            secretLogScan=True,
            managementHealthy=True,
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--server", required=True, choices=["wg-easy-subnet-p4", "wg-easy-phase0"]
    )
    parser.add_argument(
        "--server-ip", required=True, choices=["172.30.110.42", "172.30.110.2"]
    )
    parser.add_argument("--artifacts", type=Path, required=True)
    parser.add_argument("--images", type=Path, required=True)
    parser.add_argument("--server-env", type=Path, required=True)
    parser.add_argument(
        "--development-lab-images",
        action="store_true",
        help="Restored-clone iteration only; never final verification evidence",
    )
    matrix = Matrix(parser.parse_args())
    try:
        matrix.run()
    finally:
        matrix.cleanup()
    emit(
        "Phase4RouterMatrixDevelopmentPASS"
        if matrix.args.development_lab_images
        else "Phase4RouterMatrixPASS"
    )
