#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import secrets
import socketserver
from pathlib import Path
from typing import Any

from aes_gcm import encrypt
from x25519_ref import BASE_U, hkdf_sha256, x25519

INFO = b"KCTF-zero-contribution-v1"
AAD = b"kctf-x25519-envelope-v1"
MAX_LINE = 8192


class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address: tuple[str, int], flag: bytes, fixed: bool):
        super().__init__(address, KeyAgreementHandler)
        self.flag = flag
        self.fixed = fixed


class KeyAgreementHandler(socketserver.StreamRequestHandler):
    server: ThreadedServer

    def send(self, payload: dict[str, Any]) -> None:
        self.wfile.write(json.dumps(payload, sort_keys=True).encode() + b"\n")
        self.wfile.flush()

    def handle(self) -> None:
        self.request.settimeout(10)
        private_key = secrets.token_bytes(32)
        public_key = x25519(private_key, BASE_U)
        salt = secrets.token_bytes(16)
        nonce = secrets.token_bytes(12)
        self.send(
            {
                "aad": AAD.hex(),
                "challenge": "zero_contribution",
                "nonce": nonce.hex(),
                "salt": salt.hex(),
                "server_public": public_key.hex(),
            }
        )
        line = self.rfile.readline(MAX_LINE + 1)
        if not line or len(line) > MAX_LINE:
            self.send({"ok": False, "error": "invalid request length"})
            return
        try:
            request = json.loads(line)
            client_public = bytes.fromhex(request["client_public"])
            if len(client_public) != 32:
                raise ValueError
        except (ValueError, TypeError, KeyError, json.JSONDecodeError):
            self.send({"ok": False, "error": "malformed public key"})
            return

        shared = x25519(private_key, client_public)
        if self.server.fixed and shared == bytes(32):
            self.send({"ok": False, "error": "non-contributory public key"})
            return
        key = hkdf_sha256(shared, salt, INFO + public_key + client_public, 16)
        ciphertext, tag = encrypt(key, nonce, self.server.flag, AAD)
        self.send({"ok": True, "ciphertext": ciphertext.hex(), "tag": tag.hex()})


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    parser.add_argument("flag_file", type=Path)
    parser.add_argument("--fixed", action="store_true")
    args = parser.parse_args()
    flag = args.flag_file.read_bytes().rstrip(b"\n")
    with ThreadedServer((args.host, args.port), flag, args.fixed) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
