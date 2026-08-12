#!/usr/bin/env python3
"""RFC vector and five-seed nonce-pair recovery tests."""

from __future__ import annotations

import hashlib
import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from frost import (
    L,
    binding_factors,
    challenge,
    group_commitment,
    interpolating_value,
    verify_signature,
)
from frost import self_test as frost_self_test
from ristretto import base_mult, scalar_encode
from ristretto import self_test as ristretto_self_test


def load_solver():
    specification = importlib.util.spec_from_file_location(
        "frost_solver", ROOT / "for_organizer" / "solve.py"
    )
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def deterministic_scalar(seed_index: int, label: bytes) -> int:
    digest = hashlib.sha512(
        b"third-time-frost" + seed_index.to_bytes(4, "big") + label
    ).digest()
    return int.from_bytes(digest, "little") % (L - 1) + 1


def main() -> None:
    ristretto_self_test()
    frost_self_test()
    solver = load_solver()
    messages = (b"audit:alpha", b"audit:beta", b"audit:gamma")
    for index in range(5):
        secret = deterministic_scalar(index, b"secret")
        coefficient = deterministic_scalar(index, b"coefficient")
        client_share = (secret + coefficient) % L
        server_share = (secret + 2 * coefficient) % L
        group_public = base_mult(secret)
        server_public = base_mult(server_share)
        client_hiding_nonce = deterministic_scalar(index, b"client-hiding")
        client_binding_nonce = deterministic_scalar(index, b"client-binding")
        server_hiding_nonce = deterministic_scalar(index, b"server-hiding")
        server_binding_nonce = deterministic_scalar(index, b"server-binding")
        server_hiding = base_mult(server_hiding_nonce)
        server_binding = base_mult(server_binding_nonce)
        commitments = [
            (1, base_mult(client_hiding_nonce), base_mult(client_binding_nonce)),
            (2, server_hiding, server_binding),
        ]
        lambda_server = interpolating_value([1, 2], 2)
        matrix: list[list[int]] = []
        shares: list[int] = []
        for message in messages:
            factors = binding_factors(group_public, commitments, message)
            aggregate_r = group_commitment(commitments, factors)
            signature_challenge = challenge(aggregate_r, group_public, message)
            share = (
                server_hiding_nonce
                + factors[2] * server_binding_nonce
                + lambda_server * signature_challenge * server_share
            ) % L
            matrix.append([1, factors[2], lambda_server * signature_challenge % L])
            shares.append(share)
        recovered_hiding, recovered_binding, recovered_share = (
            solver.solve_linear_system(matrix, shares)
        )
        assert recovered_hiding == server_hiding_nonce
        assert recovered_binding == server_binding_nonce
        assert recovered_share == server_share
        assert base_mult(recovered_share) == server_public

        lambda_client = interpolating_value([1, 2], 1)
        recovered_secret = (
            lambda_client * client_share + lambda_server * recovered_share
        ) % L
        assert recovered_secret == secret
        nonce = deterministic_scalar(index, b"target-nonce")
        encoded_r = base_mult(nonce)
        target = b"release_flag"
        response = (
            nonce + challenge(encoded_r, group_public, target) * recovered_secret
        ) % L
        assert verify_signature(
            group_public, target, encoded_r, scalar_encode(response)
        )
    print("PASS third_time_frost RFC vector and five deterministic seeds")


if __name__ == "__main__":
    main()
