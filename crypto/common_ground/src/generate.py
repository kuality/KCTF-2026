#!/usr/bin/env python3
"""Generate the deterministic public RSA instance for common_ground."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import re
from pathlib import Path

FLAG_PATTERN = re.compile(rb"KCTF\{[0-9a-f]{64}\}\n?")
E1 = 65_537
E2 = 65_539
_SMALL_PRIMES = (
    3,
    5,
    7,
    11,
    13,
    17,
    19,
    23,
    29,
    31,
    37,
    41,
    43,
    47,
    53,
    59,
    61,
    67,
    71,
    73,
    79,
    83,
    89,
    97,
    101,
    103,
    107,
    109,
    113,
    127,
    131,
    137,
    139,
    149,
    151,
    157,
    163,
    167,
    173,
    179,
    181,
    191,
    193,
    197,
    199,
    211,
    223,
    227,
    229,
    233,
    239,
    241,
    251,
)


def _seed_bytes(path: Path) -> bytes:
    raw = path.read_text(encoding="ascii").strip()
    seed = bytes.fromhex(raw)
    if len(seed) < 32:
        raise ValueError("seed must contain at least 32 bytes")
    return seed


def _is_probable_prime(candidate: int) -> bool:
    if candidate < 2:
        return False
    for prime in _SMALL_PRIMES:
        if candidate == prime:
            return True
        if candidate % prime == 0:
            return False

    odd_part = candidate - 1
    power_of_two = 0
    while odd_part % 2 == 0:
        odd_part //= 2
        power_of_two += 1

    for base in _SMALL_PRIMES[:32]:
        witness = pow(base, odd_part, candidate)
        if witness in (1, candidate - 1):
            continue
        for _ in range(power_of_two - 1):
            witness = pow(witness, 2, candidate)
            if witness == candidate - 1:
                break
        else:
            return False
    return True


def _deterministic_prime(seed: bytes, label: bytes, bits: int) -> int:
    byte_length = (bits + 7) // 8
    counter = 0
    while True:
        material = hashlib.shake_256(seed + label + counter.to_bytes(8, "big")).digest(
            byte_length
        )
        candidate = int.from_bytes(material, "big")
        candidate |= 1
        candidate |= 1 << (bits - 1)
        candidate &= (1 << bits) - 1
        if math.gcd((candidate - 1), E1 * E2) == 1 and _is_probable_prime(candidate):
            return candidate
        counter += 1


def generate(flag: bytes, seed: bytes, bits: int = 2048) -> dict[str, int | str]:
    if not FLAG_PATTERN.fullmatch(flag):
        raise ValueError("flag must match KCTF{64 lowercase hex}")
    flag = flag.rstrip(b"\n")
    if bits < 1024 or bits % 2:
        raise ValueError("RSA modulus size must be an even value of at least 1024 bits")

    prime_bits = bits // 2
    p = _deterministic_prime(seed, b"common-ground/p", prime_bits)
    q = _deterministic_prime(seed, b"common-ground/q", prime_bits)
    if p == q:
        q = _deterministic_prime(seed, b"common-ground/q-alt", prime_bits)
    modulus = p * q
    message = int.from_bytes(flag, "big")
    if not (message < modulus and math.gcd(message, modulus) == 1):
        raise RuntimeError("generated modulus is incompatible with the message")
    if math.gcd(E1, E2) != 1:
        raise RuntimeError("public exponents must be coprime")

    return {
        "challenge": "common_ground",
        "encoding": "fixed-length big-endian",
        "flag_length": len(flag),
        "n": hex(modulus),
        "e1": E1,
        "e2": E2,
        "c1": hex(pow(message, E1, modulus)),
        "c2": hex(pow(message, E2, modulus)),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--flag-file", required=True, type=Path)
    parser.add_argument("--seed-file", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--bits", type=int, default=2048)
    args = parser.parse_args()

    instance = generate(
        args.flag_file.read_bytes(), _seed_bytes(args.seed_file), args.bits
    )
    args.output_dir.mkdir(parents=True, exist_ok=True)
    destination = args.output_dir / "instance.json"
    destination.write_text(
        json.dumps(instance, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


if __name__ == "__main__":
    main()
