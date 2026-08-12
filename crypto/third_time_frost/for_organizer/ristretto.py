"""Minimal ctypes bindings for libsodium's ristretto255 group operations."""

from __future__ import annotations

import ctypes
import ctypes.util
import secrets

L = 2**252 + 27742317777372353535851937790883648493
ELEMENT_BYTES = 32
SCALAR_BYTES = 32
IDENTITY = bytes(ELEMENT_BYTES)

_library_path = ctypes.util.find_library("sodium")
if not _library_path:
    raise RuntimeError("libsodium is required for ristretto255")
_sodium = ctypes.cdll.LoadLibrary(_library_path)
if _sodium.sodium_init() < 0:
    raise RuntimeError("libsodium initialization failed")

_sodium.crypto_core_ristretto255_is_valid_point.argtypes = [ctypes.c_void_p]
_sodium.crypto_core_ristretto255_is_valid_point.restype = ctypes.c_int
_sodium.crypto_core_ristretto255_add.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
]
_sodium.crypto_core_ristretto255_add.restype = ctypes.c_int
_sodium.crypto_scalarmult_ristretto255_base.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
]
_sodium.crypto_scalarmult_ristretto255_base.restype = ctypes.c_int
_sodium.crypto_scalarmult_ristretto255.argtypes = [
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_void_p,
]
_sodium.crypto_scalarmult_ristretto255.restype = ctypes.c_int


def scalar_encode(value: int) -> bytes:
    if not 0 <= value < L:
        raise ValueError("non-canonical scalar")
    return value.to_bytes(SCALAR_BYTES, "little")


def scalar_decode(encoded: bytes) -> int:
    if len(encoded) != SCALAR_BYTES:
        raise ValueError("scalar encoding must be 32 bytes")
    value = int.from_bytes(encoded, "little")
    if value >= L:
        raise ValueError("non-canonical scalar")
    return value


def random_scalar() -> int:
    return secrets.randbelow(L - 1) + 1


def _input_buffer(data: bytes):
    return (ctypes.c_ubyte * len(data)).from_buffer_copy(data)


def is_valid_element(encoded: bytes, *, allow_identity: bool = False) -> bool:
    if len(encoded) != ELEMENT_BYTES:
        return False
    if encoded == IDENTITY:
        return allow_identity
    return _sodium.crypto_core_ristretto255_is_valid_point(_input_buffer(encoded)) == 1


def element_validate(encoded: bytes, *, allow_identity: bool = False) -> bytes:
    if not is_valid_element(encoded, allow_identity=allow_identity):
        raise ValueError("invalid or identity ristretto255 element")
    return encoded


def base_mult(scalar: int) -> bytes:
    scalar %= L
    if scalar == 0:
        return IDENTITY
    output = (ctypes.c_ubyte * ELEMENT_BYTES)()
    status = _sodium.crypto_scalarmult_ristretto255_base(
        output, _input_buffer(scalar_encode(scalar))
    )
    if status != 0:
        raise RuntimeError("ristretto255 base multiplication failed")
    return bytes(output)


def element_mult(element: bytes, scalar: int) -> bytes:
    element_validate(element, allow_identity=True)
    scalar %= L
    if scalar == 0 or element == IDENTITY:
        return IDENTITY
    output = (ctypes.c_ubyte * ELEMENT_BYTES)()
    status = _sodium.crypto_scalarmult_ristretto255(
        output, _input_buffer(scalar_encode(scalar)), _input_buffer(element)
    )
    if status != 0:
        raise RuntimeError("ristretto255 scalar multiplication failed")
    return bytes(output)


def element_add(left: bytes, right: bytes) -> bytes:
    element_validate(left, allow_identity=True)
    element_validate(right, allow_identity=True)
    output = (ctypes.c_ubyte * ELEMENT_BYTES)()
    status = _sodium.crypto_core_ristretto255_add(
        output, _input_buffer(left), _input_buffer(right)
    )
    if status != 0:
        raise RuntimeError("ristretto255 addition failed")
    return bytes(output)


def self_test() -> None:
    expected_base = bytes.fromhex(
        "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"
    )
    assert base_mult(1) == expected_base
    assert element_add(expected_base, IDENTITY) == expected_base
    assert element_mult(expected_base, L) == IDENTITY


if __name__ == "__main__":
    self_test()
