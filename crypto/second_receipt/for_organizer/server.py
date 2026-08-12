#!/usr/bin/env python3
"""TCP service for second_receipt."""

from __future__ import annotations

import argparse
import json
import secrets
import socketserver
from pathlib import Path
from typing import Any

from ed25519_ref import L, sign, verify

MESSAGE = b"KCTF receipt: redeem one archival token"
MAX_LINE = 8192


class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address: tuple[str, int], flag: str, fixed: bool):
        super().__init__(address, ReceiptHandler)
        self.flag = flag
        self.fixed = fixed


class ReceiptHandler(socketserver.StreamRequestHandler):
    server: ThreadedServer

    def send(self, payload: dict[str, Any]) -> None:
        self.wfile.write(json.dumps(payload, sort_keys=True).encode() + b"\n")
        self.wfile.flush()

    def handle(self) -> None:
        self.request.settimeout(10)
        public_key, signature = sign(secrets.token_bytes(32), MESSAGE)
        self.send(
            {
                "challenge": "second_receipt",
                "message": MESSAGE.hex(),
                "order": hex(L),
                "public_key": public_key.hex(),
                "signature": signature.hex(),
            }
        )
        line = self.rfile.readline(MAX_LINE + 1)
        if not line or len(line) > MAX_LINE:
            self.send({"ok": False, "error": "invalid request length"})
            return
        try:
            request = json.loads(line)
            candidate = bytes.fromhex(request["signature"])
        except (ValueError, TypeError, KeyError, json.JSONDecodeError):
            self.send({"ok": False, "error": "malformed request"})
            return
        if candidate == signature:
            self.send({"ok": False, "error": "receipt already redeemed"})
            return
        if not verify(public_key, MESSAGE, candidate, strict=self.server.fixed):
            self.send({"ok": False, "error": "invalid signature"})
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
