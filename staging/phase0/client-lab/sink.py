from __future__ import annotations

import json
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


OBSERVATIONS = Path("/run/wg-easy-lab-observations/requests.jsonl")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        observation = {
            "observedAt": datetime.now(timezone.utc).isoformat(),
            "sourceAddress": self.client_address[0],
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


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
