#!/usr/bin/env python3
"""Exercise the reusable and one-time ticket TCP services."""

from __future__ import annotations

import socket
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SERVER = ROOT / "src" / "server.py"
SOLVER = ROOT / "for_organizer" / "solve.py"
FLAG_FILE = ROOT / "for_organizer" / "flag"


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def wait_ready(port: int) -> None:
    for _ in range(100):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                return
        except OSError:
            time.sleep(0.02)
    raise RuntimeError("server did not become ready")


def run_server(*, fixed: bool) -> None:
    port = free_port()
    command = [sys.executable, str(SERVER), "127.0.0.1", str(port), str(FLAG_FILE)]
    if fixed:
        command.append("--fixed")
    process = subprocess.Popen(
        command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
    )
    try:
        wait_ready(port)
        for _ in range(1 if fixed else 10):
            result = subprocess.run(
                [sys.executable, str(SOLVER), "127.0.0.1", str(port)],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            if fixed:
                assert result.returncode != 0
            else:
                assert result.returncode == 0, result.stderr
                assert (
                    result.stdout.strip()
                    == FLAG_FILE.read_text(encoding="ascii").strip()
                )
    finally:
        process.terminate()
        process.wait(timeout=5)


def main() -> None:
    run_server(fixed=False)
    run_server(fixed=True)
    print("PASS third_time_frost TCP x10 and fixed-negative")


if __name__ == "__main__":
    main()
