#!/usr/bin/env python3
"""RFC/NIST vectors and low-order X25519 properties."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aes_gcm import self_test as aes_self_test
from x25519_ref import BASE_U, x25519
from x25519_ref import self_test as x25519_self_test


def main() -> None:
    aes_self_test()
    x25519_self_test()
    for index in range(20):
        private = hashlib.sha256(
            b"zero-contribution" + index.to_bytes(4, "big")
        ).digest()
        assert x25519(private, BASE_U) != bytes(32)
        assert x25519(private, bytes(32)) == bytes(32)
    print("PASS zero_contribution RFC/NIST vectors and 20 deterministic seeds")


if __name__ == "__main__":
    main()
