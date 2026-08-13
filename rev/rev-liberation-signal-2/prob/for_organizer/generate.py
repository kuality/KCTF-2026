#!/usr/bin/env python3
from hashlib import sha256
from pathlib import Path
import struct

FLAG = b"kctf{taegeuk_relay_reorders_the_code}"
DISPATCH = b"GATE-0815-3A7F-C29D"
RELAY = b"VOICE-1945-8B1C-77E2"
ROUNDS = 6


def shuffled_range(size: int, seed: int) -> list[int]:
    values = list(range(size))
    state = seed
    for index in range(size - 1, 0, -1):
        state = (1664525 * state + 1013904223) & 0xFFFFFFFF
        other = state % (index + 1)
        values[index], values[other] = values[other], values[index]
    return values


def rol8(value: int, shift: int) -> int:
    shift &= 7
    return ((value << shift) | (value >> (8 - shift))) & 0xFF


def round_key(index: int, round_number: int) -> int:
    return (0x35 + 0x17 * index + 0x29 * round_number) & 0xFF


def transform(flag: bytes, permutation: list[int], sbox: list[int]) -> bytes:
    current = list(flag)
    for round_number in range(ROUNDS):
        next_state = [0] * len(current)
        for index, byte in enumerate(current):
            value = sbox[byte ^ round_key(index, round_number)]
            value = rol8(value, (index + 3 * round_number) % 7 + 1)
            next_state[permutation[index]] = value
        current = next_state
    return bytes(current)


def stream_xor(passphrase: bytes, data: bytes) -> bytes:
    key = sha256(passphrase).digest()
    output = bytearray()
    for counter, offset in enumerate(range(0, len(data), 32)):
        block = sha256(key + struct.pack("<I", counter)).digest()
        chunk = data[offset : offset + 32]
        output.extend(left ^ right for left, right in zip(chunk, block))
    return bytes(output)


def c_bytes(values: bytes, width: int = 12) -> str:
    rows = []
    for offset in range(0, len(values), width):
        row = ", ".join(f"0x{value:02x}" for value in values[offset : offset + width])
        rows.append("    " + row)
    return "{ \\\n" + ", \\\n".join(rows) + " \\\n}"


permutation = bytes(shuffled_range(len(FLAG), 0xC0FFEE11))
sbox = bytes(shuffled_range(256, 0x5B0C2026))
target = transform(FLAG, list(permutation), list(sbox))
encrypted_note = stream_xor(FLAG, RELAY)

payload = (
    b"S2PLAIN1"
    + struct.pack("<III", len(FLAG), ROUNDS, len(RELAY))
    + permutation
    + sbox
    + target
    + encrypted_note
)
encrypted_payload = stream_xor(DISPATCH, payload)

header = f"""\
#ifndef GENERATED_DATA_H
#define GENERATED_DATA_H

#define ENCRYPTED_PAYLOAD_LEN {len(encrypted_payload)}U
#define ENCRYPTED_PAYLOAD {c_bytes(encrypted_payload)}

#endif
"""

Path(__file__).with_name("generated_data.h").write_text(header, encoding="utf-8")
print(
    f"generated encrypted_payload={len(encrypted_payload)}, "
    f"flag={len(FLAG)}, relay={len(RELAY)}"
)
