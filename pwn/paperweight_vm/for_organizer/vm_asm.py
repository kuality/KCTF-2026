#!/usr/bin/env python3
"""Minimal assembler for paperweight_vm's fixed-width instruction ABI."""

from __future__ import annotations

import struct
from dataclasses import dataclass, field


HALT = 0x00
PUSH = 0x01
DROP = 0x02
DUP = 0x03
SWAP = 0x04
ADD = 0x05
SUB = 0x06
XOR = 0x07
LOAD = 0x08
STORE = 0x09
PRINT = 0x0A
INPUT = 0x0B
HOME = 0x0C
NOP = 0x0D
RESERVED = 0x0E
TRIGGER = 0x0F


def instruction(opcode: int, *, offset: int = 0, immediate: int = 0) -> bytes:
    if not 0 <= opcode <= 0xFF:
        raise ValueError("opcode does not fit in one byte")
    if not -(1 << 15) <= offset < (1 << 15):
        raise ValueError("offset does not fit signed int16")
    return struct.pack("<BBhIQ", opcode, 0, offset, 0, immediate & ((1 << 64) - 1))


@dataclass
class Program:
    instructions: list[bytes] = field(default_factory=list)

    def emit(self, opcode: int, *, offset: int = 0, immediate: int = 0) -> None:
        self.instructions.append(
            instruction(opcode, offset=offset, immediate=immediate)
        )

    def encode(self) -> bytes:
        return b"".join(self.instructions)
