#!/usr/bin/env python3
"""TCP service for forbidden_counter."""

from __future__ import annotations

import argparse
import json
import secrets
import socketserver
from pathlib import Path
from typing import Any

from aes_gcm import decrypt, encrypt

AAD = b"KCTF-token-service-v1"
SAMPLE_PLAINTEXTS = (b"role=user;id=001", b"role=guest;id=01")
TARGET = b"role=admin;id=01"
MAX_LINE = 8192

assert all(len(value) == 16 for value in (*SAMPLE_PLAINTEXTS, TARGET))


class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address: tuple[str, int], flag: str, fixed: bool):
        super().__init__(address, TokenHandler)
        self.flag = flag
        self.fixed = fixed


class TokenHandler(socketserver.StreamRequestHandler):
    server: ThreadedServer

    def send(self, payload: dict[str, Any]) -> None:
        self.wfile.write(json.dumps(payload, sort_keys=True).encode() + b"\n")
        self.wfile.flush()

    def handle(self) -> None:
        self.request.settimeout(10)
        key = secrets.token_bytes(16)
        nonce_prefix = secrets.token_bytes(8)
        if self.server.fixed:
            nonces = [nonce_prefix + index.to_bytes(4, "big") for index in range(3)]
        else:
            # Bug: each helper simulates a restarted worker whose counter begins at zero.
            nonces = [nonce_prefix + bytes(4) for _ in range(3)]

        samples: list[dict[str, str]] = []
        for plaintext, nonce in zip(SAMPLE_PLAINTEXTS, nonces[:2], strict=True):
            ciphertext, tag = encrypt(key, nonce, plaintext, AAD)
            samples.append(
                {
                    "ciphertext": ciphertext.hex(),
                    "nonce": nonce.hex(),
                    "plaintext": plaintext.hex(),
                    "tag": tag.hex(),
                }
            )
        self.send(
            {
                "aad": AAD.hex(),
                "challenge": "forbidden_counter",
                "samples": samples,
                "target_nonce": nonces[2].hex(),
                "target_plaintext": TARGET.hex(),
            }
        )

        line = self.rfile.readline(MAX_LINE + 1)
        if not line or len(line) > MAX_LINE:
            self.send({"ok": False, "error": "invalid request length"})
            return
        try:
            request = json.loads(line)
            nonce = bytes.fromhex(request["nonce"])
            ciphertext = bytes.fromhex(request["ciphertext"])
            tag = bytes.fromhex(request["tag"])
            if len(nonce) != 12 or len(ciphertext) != 16 or len(tag) != 16:
                raise ValueError
        except (ValueError, TypeError, KeyError, json.JSONDecodeError):
            self.send({"ok": False, "error": "malformed token"})
            return
        if nonce != nonces[2]:
            self.send({"ok": False, "error": "wrong target nonce"})
            return
        try:
            plaintext = decrypt(key, nonce, ciphertext, tag, AAD)
        except ValueError:
            self.send({"ok": False, "error": "authentication failed"})
            return
        if plaintext != TARGET:
            self.send({"ok": False, "error": "admin token required"})
            return
        self.send({"ok": True, "flag": self.server.flag})


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument("flag_file", type=Path)
    parser.add_argument("--fixed", action="store_true")
    args = parser.parse_args()
    flag = args.flag_file.read_text(encoding="ascii").strip()
    with ThreadedServer((args.host, args.port), flag, args.fixed) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
