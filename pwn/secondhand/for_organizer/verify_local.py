#!/usr/bin/env python3
"""Organizer-only local replay helper; the official solve.py is remote-only."""

from __future__ import annotations

import argparse
from pathlib import Path

from pwn import process

import solve


def main() -> None:
    parser = argparse.ArgumentParser(description="local secondhand replay")
    parser.add_argument("package", type=Path)
    arguments = parser.parse_args()

    package = arguments.package.resolve()
    binary = package / "secondhand"
    loader = package / "ld-linux-x86-64.so.2"
    io = process(
        [str(loader), "--library-path", str(package), str(binary)],
        cwd=str(package),
    )
    print(solve.exploit(io).decode())


if __name__ == "__main__":
    main()
