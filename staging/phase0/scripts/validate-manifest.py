from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any


REQUIRED_CLIENTS = {
    "phase0-wg-member",
    "phase0-awg-member",
    "phase0-exit-primary",
    "phase0-exit-backup",
    "phase0-disabled",
    "phase0-future",
}
FORBIDDEN_KEYS = {
    "privateKey",
    "preSharedKey",
    "oneTimeLinkToken",
    "password",
    "sessionPassword",
    "token",
}


def walk(value: Any, path: tuple[str, ...] = ()) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key in FORBIDDEN_KEYS:
                raise ValueError(f"forbidden secret field at {'.'.join((*path, key))}")
            walk(child, (*path, key))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            walk(child, (*path, str(index)))


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: validate-manifest.py MANIFEST.json")
    manifest = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    walk(manifest)

    if manifest.get("schemaVersion") != 1:
        raise ValueError("unexpected manifest schema version")
    if manifest.get("interface", {}).get("name") != "wg0":
        raise ValueError("baseline manifest must describe wg0")

    clients = manifest.get("clients", [])
    names = {client.get("name") for client in clients}
    missing = REQUIRED_CLIENTS - names
    if missing:
        raise ValueError(f"missing baseline clients: {sorted(missing)}")

    disabled = next(client for client in clients if client["name"] == "phase0-disabled")
    if disabled.get("enabled") is not False:
        raise ValueError("phase0-disabled fixture is not disabled")

    future = next(client for client in clients if client["name"] == "phase0-future")
    if not future.get("expiresAt"):
        raise ValueError("phase0-future fixture lacks an expiration")

    primary = next(client for client in clients if client["name"] == "phase0-exit-primary")
    backup = next(client for client in clients if client["name"] == "phase0-exit-backup")
    if primary.get("persistentKeepalive") != 25 or backup.get("persistentKeepalive") != 25:
        raise ValueError("exit fixtures must use persistent keepalive 25")
    if primary.get("serverAllowedIps") != ["172.30.111.100/32"]:
        raise ValueError("primary exit lacks the specific serverAllowedIps fixture")


if __name__ == "__main__":
    main()
