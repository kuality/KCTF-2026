"""RFC 7748 X25519 and HKDF-SHA256 helpers."""

from __future__ import annotations

import hashlib
import hmac

P = 2**255 - 19
A24 = 121665
BASE_U = (9).to_bytes(32, "little")


def x25519(scalar_bytes: bytes, u_bytes: bytes) -> bytes:
    if len(scalar_bytes) != 32 or len(u_bytes) != 32:
        raise ValueError("X25519 inputs must be 32 bytes")
    scalar = bytearray(scalar_bytes)
    scalar[0] &= 248
    scalar[31] &= 127
    scalar[31] |= 64
    k = int.from_bytes(scalar, "little")
    u = int.from_bytes(u_bytes, "little") & ((1 << 255) - 1)
    x1 = u
    x2, z2 = 1, 0
    x3, z3 = u, 1
    swap = 0

    for bit_index in range(254, -1, -1):
        bit = (k >> bit_index) & 1
        swap ^= bit
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = bit
        a = (x2 + z2) % P
        aa = a * a % P
        b = (x2 - z2) % P
        bb = b * b % P
        e = (aa - bb) % P
        c = (x3 + z3) % P
        d = (x3 - z3) % P
        da = d * a % P
        cb = c * b % P
        x3 = (da + cb) ** 2 % P
        z3 = x1 * (da - cb) ** 2 % P
        x2 = aa * bb % P
        z2 = e * (aa + A24 * e) % P

    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    result = x2 * pow(z2, P - 2, P) % P
    return result.to_bytes(32, "little")


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    if not 0 <= length <= 255 * hashlib.sha256().digest_size:
        raise ValueError("invalid HKDF output length")
    actual_salt = salt or bytes(hashlib.sha256().digest_size)
    pseudorandom_key = hmac.new(actual_salt, ikm, hashlib.sha256).digest()
    output = bytearray()
    previous = b""
    counter = 1
    while len(output) < length:
        previous = hmac.new(
            pseudorandom_key, previous + info + bytes([counter]), hashlib.sha256
        ).digest()
        output.extend(previous)
        counter += 1
    return bytes(output[:length])


def self_test() -> None:
    alice_private = bytes.fromhex(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
    )
    alice_public = bytes.fromhex(
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    )
    bob_public = bytes.fromhex(
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    )
    shared = bytes.fromhex(
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    )
    assert x25519(alice_private, BASE_U) == alice_public
    assert x25519(alice_private, bob_public) == shared
    assert x25519(alice_private, bytes(32)) == bytes(32)


if __name__ == "__main__":
    self_test()
