#!/usr/bin/env python3
"""Refresh organizer SHA256SUMS files for all challenge artifacts."""

from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHALLENGES = (
    "common_ground",
    "second_receipt",
    "zero_contribution",
    "forbidden_counter",
    "third_time_frost",
)


def main() -> None:
    for challenge_name in CHALLENGES:
        challenge = ROOT / challenge_name
        checksum_file = challenge / "for_organizer" / "SHA256SUMS"
        entries: list[str] = []
        for top_level in ("src", "for_user", "for_organizer"):
            for path in sorted((challenge / top_level).rglob("*")):
                if not path.is_file() or path == checksum_file:
                    continue
                if "__pycache__" in path.parts or path.suffix == ".pyc":
                    continue
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                entries.append(f"{digest}  {path.relative_to(challenge)}")
        checksum_file.write_text("\n".join(entries) + "\n", encoding="ascii")


if __name__ == "__main__":
    main()
