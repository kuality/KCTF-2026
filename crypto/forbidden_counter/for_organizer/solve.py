#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from aes_gcm import gf128_mul, ghash

FIELD_ONE = 1 << 127


def field_power(value: int, exponent: int) -> int:
    result = FIELD_ONE
    base = value
    while exponent:
        if exponent & 1:
            result = gf128_mul(result, base)
        base = gf128_mul(base, base)
        exponent >>= 1
    return result


def field_inverse(value: int) -> int:
    if value == 0:
        raise ZeroDivisionError("zero has no field inverse")
    return field_power(value, (1 << 128) - 2)


def field_square_root(value: int) -> int:
    return field_power(value, 1 << 127)


def xor_bytes(left: bytes, right: bytes) -> bytes:
    if len(left) != len(right):
        raise ValueError("length mismatch")
    return bytes(a ^ b for a, b in zip(left, right, strict=True))


def receive_json(stream) -> dict:
    line = stream.readline(8193)
    if not line:
        raise RuntimeError("server closed the connection")
    return json.loads(line)


def forge(hello: dict) -> tuple[bytes, bytes, bytes]:
    first, second = hello["samples"]
    nonce = bytes.fromhex(hello["target_nonce"])
    if first["nonce"] != second["nonce"] or first["nonce"] != hello["target_nonce"]:
        raise RuntimeError("the GCM nonces are not reused")
    aad = bytes.fromhex(hello["aad"])
    plaintext1 = bytes.fromhex(first["plaintext"])
    ciphertext1 = bytes.fromhex(first["ciphertext"])
    ciphertext2 = bytes.fromhex(second["ciphertext"])
    tag1 = bytes.fromhex(first["tag"])
    tag2 = bytes.fromhex(second["tag"])
    target = bytes.fromhex(hello["target_plaintext"])
    assert len(plaintext1) == len(ciphertext1) == len(ciphertext2) == len(target) == 16

    delta_ciphertext = int.from_bytes(xor_bytes(ciphertext1, ciphertext2), "big")
    delta_tag = int.from_bytes(xor_bytes(tag1, tag2), "big")
    assert delta_ciphertext != 0
    hash_squared = gf128_mul(delta_tag, field_inverse(delta_ciphertext))
    hash_subkey = field_square_root(hash_squared)
    assert gf128_mul(hash_subkey, hash_subkey) == hash_squared

    authentication_mask = int.from_bytes(tag1, "big") ^ ghash(
        hash_subkey, aad, ciphertext1
    )
    assert int.from_bytes(tag2, "big") == authentication_mask ^ ghash(
        hash_subkey, aad, ciphertext2
    )
    keystream = xor_bytes(plaintext1, ciphertext1)
    forged_ciphertext = xor_bytes(target, keystream)
    forged_tag = (
        authentication_mask ^ ghash(hash_subkey, aad, forged_ciphertext)
    ).to_bytes(16, "big")
    return nonce, forged_ciphertext, forged_tag


def solve(host: str, port: int) -> str:
    with socket.create_connection((host, port), timeout=10) as connection:
        stream = connection.makefile("rwb")
        hello = receive_json(stream)
        nonce, ciphertext, tag = forge(hello)
        stream.write(
            json.dumps(
                {"nonce": nonce.hex(), "ciphertext": ciphertext.hex(), "tag": tag.hex()}
            ).encode()
            + b"\n"
        )
        stream.flush()
        result = receive_json(stream)
        if not result.get("ok") or "flag" not in result:
            raise RuntimeError(f"forgery rejected: {result}")
        return str(result["flag"])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    args = parser.parse_args()
    print(solve(args.host, args.port))


if __name__ == "__main__":
    main()
