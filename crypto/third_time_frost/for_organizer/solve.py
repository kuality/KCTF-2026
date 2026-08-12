#!/usr/bin/env python3
"""Recover a FROST share from one reused hiding/binding nonce ticket."""

from __future__ import annotations

import argparse
import json
import socket
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from frost import (
    L,
    binding_factors,
    challenge,
    group_commitment,
    interpolating_value,
    verify_signature_share,
)
from ristretto import (
    base_mult,
    element_add,
    element_mult,
    random_scalar,
    scalar_decode,
    scalar_encode,
)


def receive_json(stream) -> dict:
    line = stream.readline(16_385)
    if not line:
        raise RuntimeError("server closed the connection")
    return json.loads(line)


def solve_linear_system(matrix: list[list[int]], vector: list[int]) -> list[int]:
    size = len(vector)
    if len(matrix) != size or any(len(row) != size for row in matrix):
        raise ValueError("matrix must be square")
    augmented = [
        [entry % L for entry in row] + [value % L]
        for row, value in zip(matrix, vector, strict=True)
    ]
    for column in range(size):
        pivot = next(
            (row for row in range(column, size) if augmented[row][column]), None
        )
        if pivot is None:
            raise ValueError("singular transcript matrix")
        augmented[column], augmented[pivot] = augmented[pivot], augmented[column]
        inverse = pow(augmented[column][column], -1, L)
        augmented[column] = [value * inverse % L for value in augmented[column]]
        for row in range(size):
            if row == column:
                continue
            factor = augmented[row][column]
            augmented[row] = [
                (left - factor * right) % L
                for left, right in zip(augmented[row], augmented[column], strict=True)
            ]
    return [augmented[index][-1] for index in range(size)]


def solve(host: str, port: int) -> str:
    with socket.create_connection((host, port), timeout=15) as connection:
        stream = connection.makefile("rwb")
        hello = receive_json(stream)
        group_public = bytes.fromhex(hello["group_public"])
        client_public = bytes.fromhex(hello["client_public"])
        server_public = bytes.fromhex(hello["server_public"])
        client_share = scalar_decode(bytes.fromhex(hello["client_share"]))
        assert base_mult(client_share) == client_public
        lambda_client = interpolating_value([1, 2], 1)
        lambda_server = interpolating_value([1, 2], 2)
        reconstructed_public = element_add(
            element_mult(client_public, lambda_client),
            element_mult(server_public, lambda_server),
        )
        assert reconstructed_public == group_public

        client_hiding_nonce = random_scalar()
        client_binding_nonce = random_scalar()
        client_hiding = base_mult(client_hiding_nonce)
        client_binding = base_mult(client_binding_nonce)
        stream.write(
            json.dumps(
                {
                    "op": "commit",
                    "hiding": client_hiding.hex(),
                    "binding": client_binding.hex(),
                }
            ).encode()
            + b"\n"
        )
        stream.flush()
        committed = receive_json(stream)
        if not committed.get("ok"):
            raise RuntimeError(f"commit failed: {committed}")
        ticket = committed["ticket"]
        server_hiding = bytes.fromhex(committed["server_hiding"])
        server_binding = bytes.fromhex(committed["server_binding"])
        commitments = [
            (1, client_hiding, client_binding),
            (2, server_hiding, server_binding),
        ]

        matrix: list[list[int]] = []
        shares: list[int] = []
        for encoded_message in hello["allowed_messages"][:3]:
            message = bytes.fromhex(encoded_message)
            stream.write(
                json.dumps(
                    {"op": "sign", "ticket": ticket, "message": message.hex()}
                ).encode()
                + b"\n"
            )
            stream.flush()
            signed = receive_json(stream)
            if not signed.get("ok"):
                raise RuntimeError(f"ticket reuse failed: {signed}")
            encoded_share = bytes.fromhex(signed["signature_share"])
            share = scalar_decode(encoded_share)
            factors = binding_factors(group_public, commitments, message)
            aggregate_r = group_commitment(commitments, factors)
            assert aggregate_r.hex() == signed["group_commitment"]
            signature_challenge = challenge(aggregate_r, group_public, message)
            assert verify_signature_share(
                server_public,
                2,
                commitments,
                group_public,
                message,
                encoded_share,
            )
            matrix.append([1, factors[2], lambda_server * signature_challenge % L])
            shares.append(share)

        hiding_nonce, binding_nonce, server_share = solve_linear_system(matrix, shares)
        assert base_mult(hiding_nonce) == server_hiding
        assert base_mult(binding_nonce) == server_binding
        assert base_mult(server_share) == server_public
        group_secret = (lambda_client * client_share + lambda_server * server_share) % L
        assert base_mult(group_secret) == group_public

        target = bytes.fromhex(hello["target_message"])
        nonce = random_scalar()
        encoded_r = base_mult(nonce)
        signature_challenge = challenge(encoded_r, group_public, target)
        response = (nonce + signature_challenge * group_secret) % L
        stream.write(
            json.dumps(
                {
                    "op": "verify",
                    "message": target.hex(),
                    "R": encoded_r.hex(),
                    "z": scalar_encode(response).hex(),
                }
            ).encode()
            + b"\n"
        )
        stream.flush()
        result = receive_json(stream)
        if not result.get("ok") or "flag" not in result:
            raise RuntimeError(f"target signature rejected: {result}")
        return str(result["flag"])


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    args = parser.parse_args()
    print(solve(args.host, args.port))


if __name__ == "__main__":
    main()
