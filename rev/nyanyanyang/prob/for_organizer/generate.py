#!/usr/bin/env python3
"""냐냐냥!!! 출제 데이터 생성기.

메뉴판(MENU_TABLE) 4096바이트의 FNV-1a 해시로 stage 연결 순서를 정하고,
정답 패스프레이즈로 플래그를 봉인한 뒤 generated_data.h 를 만든다.
"""
from hashlib import sha256
from pathlib import Path
import struct

FLAG = b"KCTF{9_c4ts_0n3_0rd3r_ny4ny4ny4ng}"
PASSPHRASE = b"ny4ny4ny4ng_c4t_numb3r_9"
LEGACY_PASSPHRASE = b"ny4ny4ny4ng_c4t_numb3r_4"

STAGE_COUNT = 9
MENU_SIZE = 4096
MENU_SEED = b"kctf-2026-nyanyanyang-menu"

SBOX = [0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD,
        0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2]

MASK64 = (1 << 64) - 1


def build_menu_table() -> bytes:
    output = bytearray()
    counter = 0
    while len(output) < MENU_SIZE:
        output += sha256(MENU_SEED + struct.pack("<I", counter)).digest()
        counter += 1
    return bytes(output[:MENU_SIZE])


MENU_TABLE = build_menu_table()


def fnv1a(data: bytes) -> int:
    digest = 14695981039346656037
    for byte in data:
        digest ^= byte
        digest = (digest * 1099511628211) & MASK64
    return digest


class Xorshift64:
    def __init__(self, seed: int) -> None:
        self.state = seed & MASK64

    def next(self) -> int:
        state = self.state
        state ^= (state << 13) & MASK64
        state ^= state >> 7
        state ^= (state << 17) & MASK64
        self.state = state
        return state


def build_order() -> list[int]:
    generator = Xorshift64(fnv1a(MENU_TABLE))
    order = list(range(STAGE_COUNT))
    for index in range(STAGE_COUNT - 1, 0, -1):
        pick = generator.next() % (index + 1)
        order[index], order[pick] = order[pick], order[index]
    return order


ORDER = build_order()


def rol8(value: int, shift: int) -> int:
    shift &= 7
    return ((value << shift) | (value >> (8 - shift))) & 0xFF


def ror8(value: int, shift: int) -> int:
    shift &= 7
    return ((value >> shift) | (value << (8 - shift))) & 0xFF


def substitute(value: int) -> int:
    return (SBOX[value >> 4] << 4) | SBOX[value & 0xF]


STAGES = [
    lambda value, index: (value + 0x5A + index) & 0xFF,
    lambda value, index: value ^ (0xA5 ^ ((index * 7) & 0xFF)),
    lambda value, index: rol8(value, 3),
    lambda value, index: (((value << 4) | (value >> 4)) & 0xFF) ^ (index & 0xFF),
    lambda value, index: substitute(value),
    lambda value, index: (value - (index * index + 13)) & 0xFF,
    lambda value, index: ror8(value, 2),
    lambda value, index: rol8(value ^ 0x3C, 1),
    lambda value, index: ((value + 0x9E) & 0xFF) ^ 0x11,
]


def run_pipeline(data: bytes, order: list[int]) -> bytes:
    current = bytearray(data)
    for stage in order:
        function = STAGES[stage]
        current = bytearray(function(current[i], i) for i in range(len(current)))
    return bytes(current)


TARGET = run_pipeline(PASSPHRASE, ORDER)
LEGACY_TARGET = bytes(
    ((byte + 0x21 + index) & 0xFF) ^ 0x6D
    for index, byte in enumerate(LEGACY_PASSPHRASE)
)


def stream_xor(passphrase: bytes, data: bytes) -> bytes:
    key = sha256(passphrase).digest()
    output = bytearray()
    for counter, offset in enumerate(range(0, len(data), 32)):
        block = sha256(key + struct.pack("<I", counter)).digest()
        chunk = data[offset:offset + 32]
        output.extend(left ^ right for left, right in zip(chunk, block))
    return bytes(output)


SEALED_COURSE = stream_xor(PASSPHRASE, FLAG)
COURSE_CHECK = sha256(b"nyanyanyang-course::" + FLAG).digest()[:8]


def c_bytes(values: bytes, width: int = 12) -> str:
    rows = []
    for offset in range(0, len(values), width):
        row = ", ".join(f"0x{value:02x}" for value in values[offset:offset + width])
        rows.append("    " + row)
    return "{ \\\n" + ", \\\n".join(rows) + " \\\n}"


header = f"""\
#ifndef GENERATED_DATA_H
#define GENERATED_DATA_H

#define MENU_TABLE_LEN {len(MENU_TABLE)}U
#define MENU_TABLE {c_bytes(MENU_TABLE)}

#define TARGET_LEN {len(TARGET)}U
#define TARGET {c_bytes(TARGET)}

#define LEGACY_TARGET_LEN {len(LEGACY_TARGET)}U
#define LEGACY_TARGET {c_bytes(LEGACY_TARGET)}

#define SEALED_COURSE_LEN {len(SEALED_COURSE)}U
#define SEALED_COURSE {c_bytes(SEALED_COURSE)}

#define COURSE_CHECK_LEN {len(COURSE_CHECK)}U
#define COURSE_CHECK {c_bytes(COURSE_CHECK)}

#endif
"""

Path(__file__).with_name("generated_data.h").write_text(header, encoding="utf-8")

assert stream_xor(PASSPHRASE, SEALED_COURSE) == FLAG, "봉인 왕복 검증 실패"

print(
    f"generated order={ORDER}, target={len(TARGET)}, "
    f"sealed={len(SEALED_COURSE)}, menu={len(MENU_TABLE)}"
)
