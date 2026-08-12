#!/usr/bin/env python3
"""Exploit second_receipt using a non-canonical Ed25519 response scalar."""

from __future__ import annotations

import argparse
import json
import socket

L = 2**252 + 27742317777372353535851937790883648493


def receive_json(stream) -> dict:
    line = stream.readline(8193)
    if not line:
        raise RuntimeError("server closed the connection")
    return json.loads(line)


def solve(host: str, port: int) -> str:
    with socket.create_connection((host, port), timeout=10) as connection:
        stream = connection.makefile("rwb")
        hello = receive_json(stream)
        signature = bytes.fromhex(hello["signature"])
        assert len(signature) == 64
        response = int.from_bytes(signature[32:], "little")
        assert response < L and response + L < 1 << 256
        malleated = signature[:32] + (response + L).to_bytes(32, "little")
        assert malleated != signature
        stream.write(json.dumps({"signature": malleated.hex()}).encode() + b"\n")
        stream.flush()
        result = receive_json(stream)
        if not result.get("ok") or "flag" not in result:
            raise RuntimeError(f"exploit rejected: {result}")
        return str(result["flag"])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    args = parser.parse_args()
    print(solve(args.host, args.port))


if __name__ == "__main__":
    main()
