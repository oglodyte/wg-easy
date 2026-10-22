#!/usr/bin/env python3
"""Exercise launcher failure cleanup and real IPv4/IPv6 sink requests."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import signal
import stat
import subprocess
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
import urllib.request


ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "staging/phase0/client-lab"


class RouterLauncherTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.configs = self.root / "configs"
        self.configs.mkdir()
        self.runtime = self.root / "runtime"
        for profile in ("a", "b"):
            (self.configs / f"router-{profile}.conf").write_text(
                "[Interface]\nPrivateKey = disposable-fixture-"
                + profile
                + "\nDNS = 192.0.2.53\nTable = auto\n[Peer]\nAllowedIPs = 0.0.0.0/0\n"
            )
        # Relocate only filesystem roots; execute the actual launcher unchanged.
        launcher = (LAB / "router-entrypoint.sh").read_text()
        launcher = launcher.replace("/run/wg-easy-router", str(self.runtime))
        launcher = launcher.replace("/run/wg-easy-lab", str(self.configs))
        self.launcher = self.root / "launcher.sh"
        self.launcher.write_text(launcher)
        mock = self.root / "awg-quick"
        mock.write_text(
            "#!/bin/sh\nset -eu\n"
            'printf "%s %s\\n" "$1" "$(basename "$2")" >> "$EVENTS"\n'
            'if [ "$1" = up ]; then\n'
            '  test "$(grep -c "^Table = off$" "$2")" = 1\n'
            '  ! grep -q "^DNS" "$2"\n'
            '  if [ "${FAIL_B:-false}" = true ] && [ "$(basename "$2")" = site-b.conf ]; then exit 7; fi\n'
            "fi\n"
        )
        mock.chmod(0o700)
        self.events = self.root / "events"
        self.env = {
            **os.environ,
            "PATH": str(self.root) + os.pathsep + os.environ["PATH"],
            "EVENTS": str(self.events),
        }

    def start(self, **env: str) -> subprocess.Popen:
        process = subprocess.Popen(
            ["sh", str(self.launcher)],
            env={**self.env, **env},
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        self.addCleanup(self.stop, process)
        return process

    @staticmethod
    def stop(process: subprocess.Popen) -> None:
        # Include the launcher's sleeping child; never leave fixture processes.
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            pass
        process.wait(timeout=5)

    def test_second_failure_rolls_back_first(self) -> None:
        process = self.start(FAIL_B="true")
        self.assertEqual(process.wait(timeout=5), 7)
        self.assertEqual(
            self.events.read_text().splitlines(),
            ["up site-a.conf", "up site-b.conf", "down site-a.conf"],
        )
        self.assertFalse((self.runtime / "ready").exists())

    def test_missing_profile_never_starts_a_tunnel(self) -> None:
        (self.configs / "router-b.conf").unlink()
        self.assertNotEqual(self.start().wait(timeout=5), 0)
        self.assertFalse(self.events.exists())

    def test_ready_then_signal_cleans_up_reverse_order(self) -> None:
        original = {p.name: p.read_bytes() for p in self.configs.iterdir()}
        process = self.start()
        deadline = time.monotonic() + 5
        while not (self.runtime / "ready").exists() and time.monotonic() < deadline:
            self.assertIsNone(process.poll())
            time.sleep(0.02)
        self.assertTrue((self.runtime / "ready").exists())
        for profile in ("a", "b"):
            config = self.runtime / f"site-{profile}.conf"
            self.assertEqual(stat.S_IMODE(config.stat().st_mode), 0o600)
            self.assertIn(
                "PrivateKey = disposable-fixture-" + profile, config.read_text()
            )
        self.assertEqual(
            original, {p.name: p.read_bytes() for p in self.configs.iterdir()}
        )
        self.stop(process)
        self.assertEqual(process.returncode, 0)
        self.assertFalse((self.runtime / "ready").exists())
        self.assertEqual(
            self.events.read_text().splitlines(),
            [
                "up site-a.conf",
                "up site-b.conf",
                "down site-b.conf",
                "down site-a.conf",
            ],
        )


class SinkTests(unittest.TestCase):
    def test_ipv4_default_and_opt_in_dual_stack(self) -> None:
        spec = importlib.util.spec_from_file_location("lab_sink", LAB / "sink.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as directory:
            module.OBSERVATIONS = Path(directory) / "requests.jsonl"
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            for dual_stack in (False, True):
                # HTTPServer reverse DNS is incidental to packet/source tests.
                with patch("socket.getfqdn", return_value="lab"), module.create_server(
                    0, ipv6=dual_stack
                ) as server:
                    thread = threading.Thread(target=server.serve_forever, daemon=True)
                    thread.start()
                    try:
                        for host, expected in [("127.0.0.1", "127.0.0.1")] + (
                            [("[::1]", "::1")] if dual_stack else []
                        ):
                            with opener.open(
                                f"http://{host}:{server.server_port}/new-flow",
                                timeout=5,
                            ) as response:
                                observed = json.load(response)
                            self.assertEqual(observed["sourceAddress"], expected)
                            self.assertEqual(observed["path"], "/new-flow")
                    finally:
                        server.shutdown()
                        thread.join(timeout=5)
            self.assertEqual(len(module.OBSERVATIONS.read_text().splitlines()), 3)


if __name__ == "__main__":
    unittest.main()
