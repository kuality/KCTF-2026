"""Small, auditable AES-128-GCM implementation used by two KCTF challenges.

This module intentionally favors clarity over performance. It implements only
96-bit nonces and 128-bit tags, which are the only forms used by the services.
"""

from __future__ import annotations

import hmac

BLOCK_SIZE = 16
_GHASH_R = 0xE1000000000000000000000000000000


def _rotl8(value: int, count: int) -> int:
    return ((value << count) | (value >> (8 - count))) & 0xFF


def _gf8_mul(left: int, right: int) -> int:
    result = 0
    value = left
    factor = right
    for _ in range(8):
        if factor & 1:
            result ^= value
        value = ((value << 1) ^ (0x11B if value & 0x80 else 0)) & 0xFF
        factor >>= 1
    return result


def _gf8_pow(value: int, exponent: int) -> int:
    result = 1
    base = value
    while exponent:
        if exponent & 1:
            result = _gf8_mul(result, base)
        base = _gf8_mul(base, base)
        exponent >>= 1
    return result


def _make_sbox() -> tuple[int, ...]:
    entries: list[int] = []
    for value in range(256):
        inverse = 0 if value == 0 else _gf8_pow(value, 254)
        transformed = (
            inverse
            ^ _rotl8(inverse, 1)
            ^ _rotl8(inverse, 2)
            ^ _rotl8(inverse, 3)
            ^ _rotl8(inverse, 4)
            ^ 0x63
        )
        entries.append(transformed)
    return tuple(entries)


_SBOX = _make_sbox()


def _expand_key(key: bytes) -> tuple[bytes, ...]:
    if len(key) != BLOCK_SIZE:
        raise ValueError("AES-128 requires a 16-byte key")

    words = [list(key[index : index + 4]) for index in range(0, 16, 4)]
    rcon = 1
    for index in range(4, 44):
        temp = words[index - 1].copy()
        if index % 4 == 0:
            temp = [_SBOX[temp[1]], _SBOX[temp[2]], _SBOX[temp[3]], _SBOX[temp[0]]]
            temp[0] ^= rcon
            rcon = _gf8_mul(rcon, 2)
        words.append([words[index - 4][offset] ^ temp[offset] for offset in range(4)])

    return tuple(
        bytes(
            value
            for word in words[round_index * 4 : round_index * 4 + 4]
            for value in word
        )
        for round_index in range(11)
    )


def _mix_column(column: list[int]) -> list[int]:
    a0, a1, a2, a3 = column
    return [
        _gf8_mul(a0, 2) ^ _gf8_mul(a1, 3) ^ a2 ^ a3,
        a0 ^ _gf8_mul(a1, 2) ^ _gf8_mul(a2, 3) ^ a3,
        a0 ^ a1 ^ _gf8_mul(a2, 2) ^ _gf8_mul(a3, 3),
        _gf8_mul(a0, 3) ^ a1 ^ a2 ^ _gf8_mul(a3, 2),
    ]


def aes128_encrypt_block(key: bytes, block: bytes) -> bytes:
    """Encrypt one 16-byte block with AES-128."""

    if len(block) != BLOCK_SIZE:
        raise ValueError("AES block must be 16 bytes")
    round_keys = _expand_key(key)
    state = [value ^ round_keys[0][index] for index, value in enumerate(block)]

    for round_index in range(1, 11):
        state = [_SBOX[value] for value in state]
        shifted = [0] * 16
        for row in range(4):
            for column in range(4):
                shifted[4 * column + row] = state[4 * ((column + row) % 4) + row]
        state = shifted

        if round_index != 10:
            mixed: list[int] = []
            for column in range(4):
                mixed.extend(_mix_column(state[4 * column : 4 * column + 4]))
            state = mixed

        state = [
            value ^ round_keys[round_index][index] for index, value in enumerate(state)
        ]

    return bytes(state)


def gf128_mul(left: int, right: int) -> int:
    """Multiply GHASH field elements in NIST's big-endian bit convention."""

    result = 0
    value = right
    for bit_index in range(128):
        if left & (1 << (127 - bit_index)):
            result ^= value
        value = (value >> 1) ^ (_GHASH_R if value & 1 else 0)
    return result


def _blocks(data: bytes) -> list[bytes]:
    return [
        data[index : index + 16].ljust(16, b"\0") for index in range(0, len(data), 16)
    ]


def ghash(hash_subkey: int, aad: bytes, ciphertext: bytes) -> int:
    """Compute GHASH over AAD and ciphertext."""

    accumulator = 0
    for block in _blocks(aad) + _blocks(ciphertext):
        accumulator = gf128_mul(accumulator ^ int.from_bytes(block, "big"), hash_subkey)
    lengths = ((len(aad) * 8) << 64) | (len(ciphertext) * 8)
    return gf128_mul(accumulator ^ lengths, hash_subkey)


def _increment_counter(counter: bytes) -> bytes:
    prefix = counter[:12]
    value = (int.from_bytes(counter[12:], "big") + 1) & 0xFFFFFFFF
    return prefix + value.to_bytes(4, "big")


def _gctr(key: bytes, initial_counter: bytes, data: bytes) -> bytes:
    output = bytearray()
    counter = initial_counter
    for index in range(0, len(data), 16):
        stream = aes128_encrypt_block(key, counter)
        block = data[index : index + 16]
        output.extend(
            left ^ right
            for left, right in zip(block, stream[: len(block)], strict=True)
        )
        counter = _increment_counter(counter)
    return bytes(output)


def encrypt(
    key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b""
) -> tuple[bytes, bytes]:
    """Encrypt and authenticate with AES-128-GCM."""

    if len(key) != 16:
        raise ValueError("AES-128-GCM requires a 16-byte key")
    if len(nonce) != 12:
        raise ValueError("this implementation requires a 12-byte nonce")
    initial = nonce + b"\x00\x00\x00\x01"
    ciphertext = _gctr(key, _increment_counter(initial), plaintext)
    hash_subkey = int.from_bytes(aes128_encrypt_block(key, bytes(16)), "big")
    authentication_mask = int.from_bytes(aes128_encrypt_block(key, initial), "big")
    tag = (authentication_mask ^ ghash(hash_subkey, aad, ciphertext)).to_bytes(
        16, "big"
    )
    return ciphertext, tag


def decrypt(
    key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b""
) -> bytes:
    """Authenticate and decrypt an AES-128-GCM ciphertext."""

    if len(tag) != 16:
        raise ValueError("GCM tag must be 16 bytes")
    initial = nonce + b"\x00\x00\x00\x01"
    hash_subkey = int.from_bytes(aes128_encrypt_block(key, bytes(16)), "big")
    authentication_mask = int.from_bytes(aes128_encrypt_block(key, initial), "big")
    expected = (authentication_mask ^ ghash(hash_subkey, aad, ciphertext)).to_bytes(
        16, "big"
    )
    if not hmac.compare_digest(tag, expected):
        raise ValueError("authentication failed")
    return _gctr(key, _increment_counter(initial), ciphertext)


def self_test() -> None:
    """Check FIPS-197 AES and NIST SP 800-38D GCM vectors."""

    aes_key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    aes_plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
    aes_expected = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
    assert aes128_encrypt_block(aes_key, aes_plaintext) == aes_expected

    key = bytes(16)
    nonce = bytes(12)
    plaintext = bytes(16)
    ciphertext, tag = encrypt(key, nonce, plaintext)
    assert ciphertext.hex() == "0388dace60b6a392f328c2b971b2fe78"
    assert tag.hex() == "ab6e47d42cec13bdf53a67b21257bddf"
    assert decrypt(key, nonce, ciphertext, tag) == plaintext


if __name__ == "__main__":
    self_test()
