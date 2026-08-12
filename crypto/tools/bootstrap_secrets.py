#!/usr/bin/env python3
"""Create per-challenge flags and the offline generator seed once."""

from __future__ import annotations

import hashlib
import secrets
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHALLENGES = (
    "common_ground",
    "second_receipt",
    "zero_contribution",
    "forbidden_counter",
    "third_time_frost",
)
SERVICE_CHALLENGES = CHALLENGES[1:]


def write_once(path: Path, content: bytes) -> None:
    if path.exists():
        return
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)


def main() -> None:
    for challenge in CHALLENGES:
        digest = hashlib.sha256(secrets.token_bytes(32)).hexdigest()
        write_once(
            ROOT / challenge / "for_organizer" / "flag", f"KCTF{{{digest}}}\n".encode()
        )
    write_once(
        ROOT / "common_ground" / "for_organizer" / "instance_seed.hex",
        secrets.token_hex(32).encode() + b"\n",
    )
    for challenge in SERVICE_CHALLENGES:
        write_once(ROOT / challenge / "for_user" / "flag", b"kctf{flag}\n")


if __name__ == "__main__":
    main()
