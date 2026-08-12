#!/usr/bin/env python3
"""Two-party FROST signer with a deliberately reusable nonce ticket."""

from __future__ import annotations

import argparse
import json
import secrets
import socketserver
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from frost import (
    L,
    binding_factors,
    challenge,
    group_commitment,
    interpolating_value,
    verify_signature,
)
from ristretto import base_mult, element_validate, random_scalar, scalar_encode

ALLOWED_MESSAGES = (b"audit:alpha", b"audit:beta", b"audit:gamma")
TARGET_MESSAGE = b"release_flag"
MAX_LINE = 16_384
MAX_REQUESTS = 8


@dataclass
class Ticket:
    client_hiding: bytes
    client_binding: bytes
    server_hiding_nonce: int
    server_binding_nonce: int
    server_hiding: bytes
    server_binding: bytes
    used_messages: set[bytes] = field(default_factory=set)
    consumed: bool = False


class ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, address: tuple[str, int], flag: str, fixed: bool):
        super().__init__(address, FrostHandler)
        self.flag = flag
        self.fixed = fixed


class FrostHandler(socketserver.StreamRequestHandler):
    server: ThreadedServer

    def send(self, payload: dict[str, Any]) -> None:
        self.wfile.write(json.dumps(payload, sort_keys=True).encode() + b"\n")
        self.wfile.flush()

    def handle(self) -> None:
        self.request.settimeout(15)
        secret = random_scalar()
        coefficient = random_scalar()
        client_share = (secret + coefficient) % L
        server_share = (secret + 2 * coefficient) % L
        group_public = base_mult(secret)
        client_public = base_mult(client_share)
        server_public = base_mult(server_share)
        tickets: dict[str, Ticket] = {}
        self.send(
            {
                "allowed_messages": [message.hex() for message in ALLOWED_MESSAGES],
                "challenge": "third_time_frost",
                "client_id": 1,
                "client_public": client_public.hex(),
                "client_share": scalar_encode(client_share).hex(),
                "group_public": group_public.hex(),
                "server_id": 2,
                "server_public": server_public.hex(),
                "target_message": TARGET_MESSAGE.hex(),
            }
        )

        for _ in range(MAX_REQUESTS):
            line = self.rfile.readline(MAX_LINE + 1)
            if not line:
                return
            if len(line) > MAX_LINE:
                self.send({"ok": False, "error": "request too large"})
                return
            try:
                request = json.loads(line)
                operation = request["op"]
            except (TypeError, KeyError, json.JSONDecodeError):
                self.send({"ok": False, "error": "malformed request"})
                continue

            if operation == "commit":
                try:
                    client_hiding = element_validate(
                        bytes.fromhex(request["hiding"])
                    ).hex()
                    client_binding = element_validate(
                        bytes.fromhex(request["binding"])
                    ).hex()
                    client_hiding_bytes = bytes.fromhex(client_hiding)
                    client_binding_bytes = bytes.fromhex(client_binding)
                except (ValueError, TypeError, KeyError):
                    self.send({"ok": False, "error": "invalid client commitment"})
                    continue
                hiding_nonce = random_scalar()
                binding_nonce = random_scalar()
                server_hiding = base_mult(hiding_nonce)
                server_binding = base_mult(binding_nonce)
                token = secrets.token_hex(16)
                tickets[token] = Ticket(
                    client_hiding_bytes,
                    client_binding_bytes,
                    hiding_nonce,
                    binding_nonce,
                    server_hiding,
                    server_binding,
                )
                self.send(
                    {
                        "ok": True,
                        "ticket": token,
                        "server_binding": server_binding.hex(),
                        "server_hiding": server_hiding.hex(),
                    }
                )
                continue

            if operation == "sign":
                try:
                    token = str(request["ticket"])
                    message = bytes.fromhex(request["message"])
                    ticket = tickets[token]
                except (ValueError, TypeError, KeyError):
                    self.send({"ok": False, "error": "invalid ticket or message"})
                    continue
                if message not in ALLOWED_MESSAGES:
                    self.send({"ok": False, "error": "message denied by policy"})
                    continue
                if self.server.fixed and ticket.consumed:
                    self.send({"ok": False, "error": "ticket already consumed"})
                    continue
                if message in ticket.used_messages:
                    self.send(
                        {"ok": False, "error": "ticket already used for this message"}
                    )
                    continue
                ticket.consumed = True
                ticket.used_messages.add(message)
                commitments = [
                    (1, ticket.client_hiding, ticket.client_binding),
                    (2, ticket.server_hiding, ticket.server_binding),
                ]
                factors = binding_factors(group_public, commitments, message)
                aggregate_r = group_commitment(commitments, factors)
                signature_challenge = challenge(aggregate_r, group_public, message)
                lambda_server = interpolating_value([1, 2], 2)
                share = (
                    ticket.server_hiding_nonce
                    + factors[2] * ticket.server_binding_nonce
                    + lambda_server * signature_challenge * server_share
                ) % L
                self.send(
                    {
                        "group_commitment": aggregate_r.hex(),
                        "ok": True,
                        "signature_share": scalar_encode(share).hex(),
                    }
                )
                continue

            if operation == "verify":
                try:
                    message = bytes.fromhex(request["message"])
                    encoded_r = bytes.fromhex(request["R"])
                    encoded_z = bytes.fromhex(request["z"])
                except (ValueError, TypeError, KeyError):
                    self.send({"ok": False, "error": "malformed signature"})
                    continue
                if message != TARGET_MESSAGE:
                    self.send(
                        {
                            "ok": False,
                            "error": "only the target message releases the flag",
                        }
                    )
                    continue
                if not verify_signature(group_public, message, encoded_r, encoded_z):
                    self.send({"ok": False, "error": "invalid group signature"})
                    continue
                self.send({"ok": True, "flag": self.server.flag})
                return

            self.send({"ok": False, "error": "unknown operation"})


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
