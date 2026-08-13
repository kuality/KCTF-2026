#!/usr/bin/env python3
from pathlib import Path

FLAG = b"kctf{dawn_courier_opens_the_route}"
DISPATCH = b"GATE-0815-3A7F-C29D"
SEED = 0x5A


def rol8(value: int, shift: int) -> int:
    shift &= 7
    return ((value << shift) | (value >> (8 - shift))) & 0xFF


def make_target(flag: bytes) -> list[int]:
    state = SEED
    target: list[int] = []
    for index, byte in enumerate(flag):
        mixed = byte ^ state ^ ((0x31 + 0x17 * index) & 0xFF)
        mixed = rol8(mixed, index % 7 + 1)
        mixed = (mixed + 7 + 13 * index) & 0xFF
        target.append(mixed)
        state = (state + byte + 0x3D) & 0xFF
    return target


def c_bytes(values: list[int]) -> str:
    return "{ " + ", ".join(f"0x{value:02x}" for value in values) + " }"


target = make_target(FLAG)
note = [
    byte ^ FLAG[index % len(FLAG)] ^ ((0xA7 + 29 * index) & 0xFF)
    for index, byte in enumerate(DISPATCH)
]
header = f"""\
#ifndef GENERATED_DATA_H
#define GENERATED_DATA_H

#define FLAG_LEN {len(FLAG)}U
#define NOTE_LEN {len(DISPATCH)}U
#define ROLLING_SEED 0x{SEED:02x}U
#define TARGET_BYTES {c_bytes(target)}
#define NOTE_BYTES {c_bytes(note)}

#endif
"""

Path(__file__).with_name("generated_data.h").write_text(header, encoding="utf-8")
print(f"generated target={len(target)}, encrypted_note={len(note)}")
