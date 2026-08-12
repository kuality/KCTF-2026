#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from aes_gcm import decrypt
from x25519_ref import hkdf_sha256

INFO = b"KCTF-zero-contribution-v1"


def receive_json(stream) -> dict:
    line = stream.readline(8193)
    if not line:
        raise RuntimeError("server closed the connection")
    return json.loads(line)


def solve(host: str, port: int) -> str:
    client_public = bytes(32)
    with socket.create_connection((host, port), timeout=10) as connection:
        stream = connection.makefile("rwb")
        hello = receive_json(stream)
        server_public = bytes.fromhex(hello["server_public"])
        salt = bytes.fromhex(hello["salt"])
        nonce = bytes.fromhex(hello["nonce"])
        aad = bytes.fromhex(hello["aad"])
        stream.write(
            json.dumps({"client_public": client_public.hex()}).encode() + b"\n"
        )
        stream.flush()
        result = receive_json(stream)
        if not result.get("ok"):
            raise RuntimeError(f"low-order input rejected: {result}")
        key = hkdf_sha256(bytes(32), salt, INFO + server_public + client_public, 16)
        plaintext = decrypt(
            key,
            nonce,
            bytes.fromhex(result["ciphertext"]),
            bytes.fromhex(result["tag"]),
            aad,
        )
        assert plaintext.startswith(b"KCTF{") or plaintext == b"kctf{flag}"
        return plaintext.decode("ascii")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    args = parser.parse_args()
    print(solve(args.host, args.port))


if __name__ == "__main__":
    main()
