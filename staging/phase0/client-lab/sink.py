from __future__ import annotations

import ipaddress
import json
import os
import socket
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


OBSERVATIONS = Path("/run/wg-easy-lab-observations/requests.jsonl")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        address = ipaddress.ip_address(self.client_address[0])
        if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
            address = address.ipv4_mapped
        observation = {
            "observedAt": datetime.now(timezone.utc).isoformat(),
            "sourceAddress": str(address),
            "path": self.path,
        }
        OBSERVATIONS.parent.mkdir(parents=True, exist_ok=True)
        with OBSERVATIONS.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(observation, sort_keys=True) + "\n")

        body = (json.dumps(observation, sort_keys=True) + "\n").encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


class DualStackServer(ThreadingHTTPServer):
    address_family = socket.AF_INET6

    def server_bind(self) -> None:
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
        super().server_bind()


def create_server(port: int = 8080, *, ipv6: bool = False) -> ThreadingHTTPServer:
    if ipv6:
        return DualStackServer(("::", port), Handler)
    return ThreadingHTTPServer(("0.0.0.0", port), Handler)


if __name__ == "__main__":
    create_server(ipv6=os.environ.get("SINK_IPV6_LISTEN") == "true").serve_forever()
