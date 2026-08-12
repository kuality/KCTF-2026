#!/usr/bin/env python3
"""Recover the common_ground flag using the RSA common-modulus attack."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def extended_gcd(left: int, right: int) -> tuple[int, int, int]:
    if right == 0:
        return left, 1, 0
    divisor, x1, y1 = extended_gcd(right, left % right)
    return divisor, y1, x1 - (left // right) * y1


def signed_power(value: int, exponent: int, modulus: int) -> int:
    if exponent < 0:
        value = pow(value, -1, modulus)
        exponent = -exponent
    return pow(value, exponent, modulus)


def solve(public_dir: Path) -> bytes:
    data = json.loads((public_dir / "instance.json").read_text(encoding="utf-8"))
    modulus = int(data["n"], 0)
    e1 = int(data["e1"])
    e2 = int(data["e2"])
    c1 = int(data["c1"], 0)
    c2 = int(data["c2"], 0)
    divisor, coefficient1, coefficient2 = extended_gcd(e1, e2)
    assert divisor == 1

    message = (
        signed_power(c1, coefficient1, modulus)
        * signed_power(c2, coefficient2, modulus)
    ) % modulus
    assert pow(message, e1, modulus) == c1
    assert pow(message, e2, modulus) == c2
    flag = message.to_bytes(int(data["flag_length"]), "big")
    assert flag.startswith(b"KCTF{") and flag.endswith(b"}")
    return flag


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("public_dir", type=Path)
    args = parser.parse_args()
    print(solve(args.public_dir).decode("ascii"))


if __name__ == "__main__":
    main()
