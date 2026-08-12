#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from aes_gcm import decrypt, encrypt, self_test


def load_solver():
    specification = importlib.util.spec_from_file_location(
        "forbidden_solver", ROOT / "for_organizer" / "solve.py"
    )
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def hello_for(key: bytes, nonces: list[bytes]) -> dict:
    aad = b"KCTF-token-service-v1"
    plaintexts = (b"role=user;id=001", b"role=guest;id=01")
    samples = []
    for plaintext, nonce in zip(plaintexts, nonces[:2], strict=True):
        ciphertext, tag = encrypt(key, nonce, plaintext, aad)
        samples.append(
            {
                "nonce": nonce.hex(),
                "plaintext": plaintext.hex(),
                "ciphertext": ciphertext.hex(),
                "tag": tag.hex(),
            }
        )
    return {
        "aad": aad.hex(),
        "samples": samples,
        "target_nonce": nonces[2].hex(),
        "target_plaintext": b"role=admin;id=01".hex(),
    }


def main() -> None:
    self_test()
    solver = load_solver()
    for index in range(20):
        material = hashlib.sha512(
            b"forbidden-counter" + index.to_bytes(4, "big")
        ).digest()
        key = material[:16]
        reused = material[16:28]
        vulnerable = hello_for(key, [reused, reused, reused])
        nonce, ciphertext, tag = solver.forge(vulnerable)
        assert decrypt(
            key,
            nonce,
            ciphertext,
            tag,
            bytes.fromhex(vulnerable["aad"]),
        ) == bytes.fromhex(vulnerable["target_plaintext"])

        unique = [material[16:24] + value.to_bytes(4, "big") for value in range(3)]
        fixed = hello_for(key, unique)
        try:
            solver.forge(fixed)
        except RuntimeError:
            pass
        else:
            raise AssertionError("fixed unique-nonce transcript was forgeable")
    print("PASS forbidden_counter NIST vector, 20 seeds, and fixed-negative")


if __name__ == "__main__":
    main()
