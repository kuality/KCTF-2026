#!/usr/bin/env python3
from hashlib import sha256
from pathlib import Path
import struct

FLAG = b"kctf{1945_08_15_voice_of_liberation}"
DISPATCH = b"GATE-0815-3A7F-C29D"
RELAY = b"VOICE-1945-8B1C-77E2"

OP_XOR = 0x10
OP_ADD = 0x11
OP_SUB = 0x12
OP_ROL = 0x13
OP_COMPARE = 0x20
OP_NEXT = 0x30


def rol8(value: int, shift: int) -> int:
    shift &= 7
    return ((value << shift) | (value >> (8 - shift))) & 0xFF


def make_program(flag: bytes) -> bytes:
    state = 0x13579BDF
    program: list[int] = []
    opcodes = [OP_XOR, OP_ADD, OP_SUB, OP_ROL]

    for index, original in enumerate(flag):
        accumulator = original
        state = (1103515245 * state + 12345 + index) & 0xFFFFFFFF
        operation_count = 5 + state % 3

        for _ in range(operation_count):
            state = (1103515245 * state + 12345) & 0xFFFFFFFF
            opcode = opcodes[(state >> 29) & 3]
            if opcode == OP_ROL:
                immediate = 1 + ((state >> 8) % 7)
                accumulator = rol8(accumulator, immediate)
            else:
                immediate = (state >> 8) & 0xFF
                if opcode == OP_XOR:
                    accumulator ^= immediate
                elif opcode == OP_ADD:
                    accumulator = (accumulator + immediate) & 0xFF
                else:
                    accumulator = (accumulator - immediate) & 0xFF
            program.extend((opcode, immediate))

        program.extend((OP_COMPARE, accumulator, OP_NEXT))

    return bytes(program)


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


program = make_program(FLAG)
payload = b"S3PLAIN1" + struct.pack("<II", len(FLAG), len(program)) + program
credentials = DISPATCH + b"|" + RELAY
encrypted_payload = stream_xor(credentials, payload)

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
    f"program={len(program)}, flag={len(FLAG)}"
)
