#!/usr/bin/env python3
"""Organizer-only local replay helper; solve.py remains HOST/PORT-only."""

from __future__ import annotations

import argparse
from pathlib import Path

from pwn import context, process

import solve


HERE = Path(__file__).resolve().parent


def main() -> None:
    parser = argparse.ArgumentParser(description="local paperweight_vm replay")
    parser.add_argument("flag_path", type=Path)
    arguments = parser.parse_args()
    context.log_level = "error"

    loader = HERE / "ld-linux-x86-64.so.2"
    binary = HERE / "paperweight_vm"
    io = process([
        str(loader),
        "--library-path",
        str(HERE),
        str(binary),
    ])
    print(solve.exploit(io, str(arguments.flag_path.resolve()).encode()).decode())


if __name__ == "__main__":
    main()
