#!/usr/bin/env python3
"""RFC vector and 20-seed malleability regression tests."""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ed25519_ref import L, self_test, sign, verify


def main() -> None:
    self_test()
    for index in range(20):
        seed = hashlib.sha256(b"second-receipt" + index.to_bytes(4, "big")).digest()
        message = b"receipt-" + index.to_bytes(4, "big")
        public_key, signature = sign(seed, message)
        response = int.from_bytes(signature[32:], "little")
        altered = signature[:32] + (response + L).to_bytes(32, "little")
        assert verify(public_key, message, signature, strict=True)
        assert verify(public_key, message, altered, strict=False)
        assert not verify(public_key, message, altered, strict=True)
        assert not verify(public_key, message + b"!", altered, strict=False)
    print("PASS second_receipt RFC vector and 20 deterministic seeds")


if __name__ == "__main__":
    main()
