"""RFC 9591 FROST(ristretto255, SHA-512) transcript helpers."""

from __future__ import annotations

import hashlib

from ristretto import (
    IDENTITY,
    L,
    base_mult,
    element_add,
    element_mult,
    element_validate,
    scalar_decode,
    scalar_encode,
)

CONTEXT = b"FROST-RISTRETTO255-SHA512-v1"
Commitment = tuple[int, bytes, bytes]


def _hash_scalar(label: bytes, message: bytes) -> int:
    digest = hashlib.sha512(CONTEXT + label + message).digest()
    return int.from_bytes(digest, "little") % L


def h1(message: bytes) -> int:
    return _hash_scalar(b"rho", message)


def h2(message: bytes) -> int:
    return _hash_scalar(b"chal", message)


def h4(message: bytes) -> bytes:
    return hashlib.sha512(CONTEXT + b"msg" + message).digest()


def h5(message: bytes) -> bytes:
    return hashlib.sha512(CONTEXT + b"com" + message).digest()


def encode_commitment_list(commitments: list[Commitment]) -> bytes:
    identifiers = [identifier for identifier, _, _ in commitments]
    if identifiers != sorted(identifiers) or len(identifiers) != len(set(identifiers)):
        raise ValueError("commitment list must have unique sorted identifiers")
    encoded = bytearray()
    for identifier, hiding, binding in commitments:
        if identifier <= 0:
            raise ValueError("participant identifier must be nonzero")
        element_validate(hiding)
        element_validate(binding)
        encoded.extend(scalar_encode(identifier))
        encoded.extend(hiding)
        encoded.extend(binding)
    return bytes(encoded)


def binding_factors(
    group_public_key: bytes, commitments: list[Commitment], message: bytes
) -> dict[int, int]:
    element_validate(group_public_key)
    prefix = group_public_key + h4(message) + h5(encode_commitment_list(commitments))
    return {
        identifier: h1(prefix + scalar_encode(identifier))
        for identifier, _, _ in commitments
    }


def group_commitment(commitments: list[Commitment], factors: dict[int, int]) -> bytes:
    result = IDENTITY
    for identifier, hiding, binding in commitments:
        result = element_add(result, hiding)
        result = element_add(result, element_mult(binding, factors[identifier]))
    element_validate(result)
    return result


def challenge(
    group_commitment_value: bytes, group_public_key: bytes, message: bytes
) -> int:
    element_validate(group_commitment_value)
    element_validate(group_public_key)
    return h2(group_commitment_value + group_public_key + message)


def interpolating_value(identifiers: list[int], identifier: int) -> int:
    if identifier not in identifiers or len(set(identifiers)) != len(identifiers):
        raise ValueError("invalid participant list")
    numerator = 1
    denominator = 1
    for other in identifiers:
        if other == identifier:
            continue
        numerator = numerator * other % L
        denominator = denominator * (other - identifier) % L
    return numerator * pow(denominator, -1, L) % L


def verify_signature(
    group_public_key: bytes, message: bytes, encoded_r: bytes, encoded_z: bytes
) -> bool:
    try:
        element_validate(group_public_key)
        element_validate(encoded_r)
        response = scalar_decode(encoded_z)
        signature_challenge = challenge(encoded_r, group_public_key, message)
        left = base_mult(response)
        right = element_add(
            encoded_r, element_mult(group_public_key, signature_challenge)
        )
        return left == right
    except (ValueError, RuntimeError):
        return False


def verify_signature_share(
    participant_public: bytes,
    identifier: int,
    commitments: list[Commitment],
    group_public_key: bytes,
    message: bytes,
    encoded_share: bytes,
) -> bool:
    try:
        share = scalar_decode(encoded_share)
        factors = binding_factors(group_public_key, commitments, message)
        commitment_value = group_commitment(commitments, factors)
        signature_challenge = challenge(commitment_value, group_public_key, message)
        participant_commitment = next(
            (d, e) for current, d, e in commitments if current == identifier
        )
        lambda_i = interpolating_value(
            [current for current, _, _ in commitments], identifier
        )
        right = element_add(
            participant_commitment[0],
            element_mult(participant_commitment[1], factors[identifier]),
        )
        right = element_add(
            right,
            element_mult(participant_public, signature_challenge * lambda_i % L),
        )
        return base_mult(share) == right
    except (ValueError, RuntimeError, StopIteration):
        return False


def self_test() -> None:
    group_secret = bytes.fromhex(
        "1b25a55e463cfd15cf14a5d3acc3d15053f08da49c8afcf3ab265f2ebc4f970b"
    )
    group_public = bytes.fromhex(
        "e2a62f39eede11269e3bd5a7d97554f5ca384f9f6d3dd9c3c0d05083c7254f57"
    )
    signature = bytes.fromhex(
        "fc45655fbc66bbffad654ea4ce5fdae253a49a64ace25d9adb62010dd9fb2555"
        "2164141787162e5b4cab915b4aa45d94655dbb9ed7c378a53b980a0be220a802"
    )
    assert base_mult(scalar_decode(group_secret)) == group_public
    assert verify_signature(group_public, b"test", signature[:32], signature[32:])


if __name__ == "__main__":
    self_test()
