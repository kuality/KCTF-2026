"""Compact Ed25519 implementation for the second_receipt challenge.

The group arithmetic follows RFC 8032. The vulnerable verifier differs from
the strict verifier in exactly one place: it omits the canonical ``S < L``
check before evaluating the signature equation.
"""

from __future__ import annotations

import hashlib

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)

Point = tuple[int, int, int, int]
IDENTITY: Point = (0, 1, 1, 0)


def _recover_x(y: int, sign: int) -> int:
    numerator = (y * y - 1) % P
    denominator = (D * y * y + 1) % P
    x_squared = numerator * pow(denominator, P - 2, P) % P
    x = pow(x_squared, (P + 3) // 8, P)
    if (x * x - x_squared) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - x_squared) % P != 0:
        raise ValueError("point is not on edwards25519")
    if x == 0 and sign:
        raise ValueError("non-canonical sign bit")
    if (x & 1) != sign:
        x = P - x
    return x


def point_add(left: Point, right: Point) -> Point:
    x1, y1, z1, t1 = left
    x2, y2, z2, t2 = right
    a = (y1 - x1) * (y2 - x2) % P
    b = (y1 + x1) * (y2 + x2) % P
    c = 2 * D * t1 * t2 % P
    d = 2 * z1 * z2 % P
    e = (b - a) % P
    f = (d - c) % P
    g = (d + c) % P
    h = (b + a) % P
    return e * f % P, g * h % P, f * g % P, e * h % P


def scalar_mult(point: Point, scalar: int) -> Point:
    if scalar < 0:
        raise ValueError("scalar must be nonnegative")
    result = IDENTITY
    addend = point
    value = scalar
    while value:
        if value & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        value >>= 1
    return result


def point_equal(left: Point, right: Point) -> bool:
    return (left[0] * right[2] - right[0] * left[2]) % P == 0 and (
        left[1] * right[2] - right[1] * left[2]
    ) % P == 0


def encode_point(point: Point) -> bytes:
    inverse_z = pow(point[2], P - 2, P)
    x = point[0] * inverse_z % P
    y = point[1] * inverse_z % P
    encoded = y | ((x & 1) << 255)
    return encoded.to_bytes(32, "little")


def decode_point(encoded: bytes, *, require_subgroup: bool = True) -> Point:
    if len(encoded) != 32:
        raise ValueError("point encoding must be 32 bytes")
    value = int.from_bytes(encoded, "little")
    y = value & ((1 << 255) - 1)
    sign = value >> 255
    if y >= P:
        raise ValueError("non-canonical field element")
    x = _recover_x(y, sign)
    point = (x, y, 1, x * y % P)
    if encode_point(point) != encoded:
        raise ValueError("non-canonical point encoding")
    if require_subgroup and not point_equal(scalar_mult(point, L), IDENTITY):
        raise ValueError("point is not in the prime-order subgroup")
    return point


BASE_Y = 4 * pow(5, P - 2, P) % P
BASE_X = _recover_x(BASE_Y, 0)
BASE: Point = (BASE_X, BASE_Y, 1, BASE_X * BASE_Y % P)


def public_key_from_seed(seed: bytes) -> bytes:
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    digest = hashlib.sha512(seed).digest()
    scalar_bytes = bytearray(digest[:32])
    scalar_bytes[0] &= 248
    scalar_bytes[31] &= 63
    scalar_bytes[31] |= 64
    secret_scalar = int.from_bytes(scalar_bytes, "little")
    return encode_point(scalar_mult(BASE, secret_scalar))


def sign(seed: bytes, message: bytes) -> tuple[bytes, bytes]:
    digest = hashlib.sha512(seed).digest()
    scalar_bytes = bytearray(digest[:32])
    scalar_bytes[0] &= 248
    scalar_bytes[31] &= 63
    scalar_bytes[31] |= 64
    secret_scalar = int.from_bytes(scalar_bytes, "little")
    public_key = encode_point(scalar_mult(BASE, secret_scalar))
    nonce = int.from_bytes(hashlib.sha512(digest[32:] + message).digest(), "little") % L
    encoded_r = encode_point(scalar_mult(BASE, nonce))
    challenge = (
        int.from_bytes(
            hashlib.sha512(encoded_r + public_key + message).digest(), "little"
        )
        % L
    )
    response = (nonce + challenge * secret_scalar) % L
    return public_key, encoded_r + response.to_bytes(32, "little")


def verify(
    public_key: bytes, message: bytes, signature: bytes, *, strict: bool
) -> bool:
    if len(public_key) != 32 or len(signature) != 64:
        return False
    try:
        public_point = decode_point(public_key)
        encoded_r = signature[:32]
        r_point = decode_point(encoded_r)
    except ValueError:
        return False
    response = int.from_bytes(signature[32:], "little")
    if strict and response >= L:
        return False
    challenge = (
        int.from_bytes(
            hashlib.sha512(encoded_r + public_key + message).digest(), "little"
        )
        % L
    )
    left = scalar_mult(BASE, response)
    right = point_add(r_point, scalar_mult(public_point, challenge))
    return point_equal(left, right)


def self_test() -> None:
    seed = bytes.fromhex(
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    )
    expected_public = bytes.fromhex(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    )
    expected_signature = bytes.fromhex(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
        "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    )
    public_key, signature = sign(seed, b"")
    assert public_key == expected_public
    assert signature == expected_signature
    assert verify(public_key, b"", signature, strict=True)
    malleated = signature[:32] + (
        int.from_bytes(signature[32:], "little") + L
    ).to_bytes(32, "little")
    assert verify(public_key, b"", malleated, strict=False)
    assert not verify(public_key, b"", malleated, strict=True)


if __name__ == "__main__":
    self_test()
