#!/usr/bin/env python3
"""Sequentially build and solve every service package in Docker."""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import time
from pathlib import Path

os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")

ROOT = Path(__file__).resolve().parents[1]
SERVICES = (
    ("second_receipt", 32441),
    ("zero_contribution", 32442),
    ("forbidden_counter", 32443),
    ("third_time_frost", 32444),
)


def run(
    command: list[str], *, env: dict[str, str] | None = None, capture: bool = False
):
    return subprocess.run(
        command,
        env=env,
        check=True,
        capture_output=capture,
        text=capture,
        timeout=600,
    )


def wait_ready(port: int) -> None:
    for _ in range(200):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"container on port {port} did not become ready")


def verify_package(challenge: str, kind: str, port: int) -> None:
    package = ROOT / challenge / f"for_{kind}"
    compose = package / "docker-compose.yml"
    project = f"kctf_crypto_{challenge}_{kind}"
    environment = os.environ.copy()
    environment["PORT"] = str(port)
    base = ["docker", "compose", "-p", project, "-f", str(compose)]
    print(f"BUILD {challenge}/{kind}", flush=True)
    run([*base, "config"], env=environment, capture=True)
    run([*base, "build"], env=environment)
    try:
        run([*base, "up", "-d"], env=environment)
        wait_ready(port)
        uid = run(
            [*base, "exec", "-T", "challenge", "id", "-u"],
            env=environment,
            capture=True,
        )
        if uid.stdout.strip() != "2001":
            raise AssertionError(f"unexpected runtime uid: {uid.stdout!r}")
        run(
            [*base, "exec", "-T", "challenge", "test", "!", "-e", "/app/flag"],
            env=environment,
        )
        run(
            [
                *base,
                "exec",
                "-T",
                "challenge",
                "test",
                "-r",
                "/run/secrets/challenge_flag",
            ],
            env=environment,
        )
        solver = ROOT / challenge / "for_organizer" / "solve.py"
        result = run(
            [sys.executable, str(solver), "127.0.0.1", str(port)],
            capture=True,
        )
        expected_path = package / "flag"
        expected = expected_path.read_text(encoding="ascii").strip()
        if result.stdout.strip() != expected:
            raise AssertionError(f"solver output mismatch for {challenge}/{kind}")
        print(f"PASS {challenge}/{kind} Docker solve as uid 2001", flush=True)
    finally:
        subprocess.run([*base, "down", "-v"], env=environment, check=False, timeout=120)


def main() -> None:
    run([str(ROOT / "common_ground" / "src" / "verify.sh")])
    for challenge, base_port in SERVICES:
        verify_package(challenge, "user", base_port)
        verify_package(challenge, "organizer", base_port + 100)
    print("PASS all user and organizer Docker packages", flush=True)


if __name__ == "__main__":
    main()
