#!/usr/bin/env python3
import struct
import sys
from pathlib import Path


PT_LOAD = 1
PF_W = 2


class SolveError(Exception):
    pass


class ElfImage:
    def __init__(self, path: Path):
        self.data = path.read_bytes()
        if len(self.data) < 64 or self.data[:4] != b"\x7fELF":
            raise SolveError("input is not an ELF file")
        if self.data[4] != 2 or self.data[5] != 1:
            raise SolveError("expected a 64-bit little-endian ELF")
        machine = struct.unpack_from("<H", self.data, 18)[0]
        if machine != 62:
            raise SolveError("expected an x86-64 ELF")
        phoff = struct.unpack_from("<Q", self.data, 32)[0]
        phentsize = struct.unpack_from("<H", self.data, 54)[0]
        phnum = struct.unpack_from("<H", self.data, 56)[0]
        if phentsize < 56 or phoff + phentsize * phnum > len(self.data):
            raise SolveError("invalid program-header table")
        self.loads = []
        for index in range(phnum):
            offset = phoff + index * phentsize
            fields = struct.unpack_from("<IIQQQQQQ", self.data, offset)
            p_type, flags, file_offset, vaddr, _, filesz, memsz, _ = fields
            if p_type == PT_LOAD and filesz:
                if file_offset + filesz > len(self.data):
                    raise SolveError("truncated load segment")
                self.loads.append((vaddr, file_offset, filesz, memsz, flags))

    def file_offset(self, vaddr: int, size: int = 1) -> int:
        for base, offset, filesz, _, _ in self.loads:
            if base <= vaddr and vaddr + size <= base + filesz:
                return offset + (vaddr - base)
        raise SolveError(f"unmapped virtual address 0x{vaddr:x}")

    def read(self, vaddr: int, size: int) -> bytes:
        offset = self.file_offset(vaddr, size)
        return self.data[offset : offset + size]

    def u64(self, vaddr: int) -> int:
        return struct.unpack("<Q", self.read(vaddr, 8))[0]

    def writable_words(self):
        for base, _, filesz, _, flags in self.loads:
            if not (flags & PF_W):
                continue
            start = (base + 7) & ~7
            end = base + filesz
            for vaddr in range(start, end - 7, 8):
                yield vaddr, self.u64(vaddr)


def header_fields(header: int):
    return header >> 10, header & 0xFF


def immediate(word: int) -> int:
    if word & 1 == 0:
        raise SolveError("expected an OCaml immediate integer")
    return word >> 1


def decode_operation(image: ElfImage, pointer: int):
    if pointer == 0 or pointer & 7:
        raise SolveError("invalid operation pointer")
    header = image.u64(pointer - 8)
    size, tag = header_fields(header)
    expected_size = {0: 2, 1: 2, 2: 2, 3: 2, 4: 3}.get(tag)
    if size != expected_size:
        raise SolveError("not a tagged-tape operation")
    values = tuple(immediate(image.u64(pointer + index * 8)) for index in range(size))
    if tag in (0, 1):
        index, key = values
        if not (0 <= index < 256 and 1 <= key <= 255):
            raise SolveError("invalid byte operation")
    elif tag == 2:
        index, amount = values
        if not (0 <= index < 256 and 1 <= amount <= 7):
            raise SolveError("invalid rotate operation")
    elif tag == 3:
        left, right = values
        if not (0 <= left < 256 and 0 <= right < 256 and left != right):
            raise SolveError("invalid swap operation")
    else:
        left, right, key = values
        if not (
            0 <= left < 256
            and 0 <= right < 256
            and left != right
            and 1 <= key <= 255
        ):
            raise SolveError("invalid Feistel operation")
    return tag, values


def decode_adjacent_string(image: ElfImage, end_vaddr: int, length: int) -> bytes:
    words = (length + 1 + 7) // 8
    header_vaddr = end_vaddr - (words + 1) * 8
    size, tag = header_fields(image.u64(header_vaddr))
    if size != words or tag != 252:
        raise SolveError("adjacent target is not an OCaml string")
    storage = image.read(header_vaddr + 8, words * 8)
    padding = storage[-1]
    actual_length = words * 8 - 1 - padding
    if actual_length != length or any(storage[length:-1]):
        raise SolveError("invalid OCaml string padding")
    return storage[:length]


def locate_capsule_data(image: ElfImage):
    candidates = []
    for header_vaddr, header in image.writable_words():
        count, tag = header_fields(header)
        if tag != 0 or not (80 <= count <= 384):
            continue
        try:
            operations = []
            tag_counts = [0] * 5
            maximum_index = -1
            for index in range(count):
                pointer = image.u64(header_vaddr + 8 + index * 8)
                operation = decode_operation(image, pointer)
                op_tag, values = operation
                tag_counts[op_tag] += 1
                maximum_index = max(maximum_index, values[0], values[1] if op_tag >= 3 else -1)
                operations.append(operation)
            if any(value < 4 for value in tag_counts):
                continue
            width = maximum_index + 1
            if not (32 <= width <= 128):
                continue
            target = decode_adjacent_string(image, header_vaddr, width)
            candidates.append((operations, target, header_vaddr, tag_counts))
        except (SolveError, struct.error):
            continue
    if len(candidates) != 1:
        raise SolveError(f"expected one instruction tape, found {len(candidates)}")
    return candidates[0]


def rol8(value: int, amount: int) -> int:
    amount &= 7
    if amount == 0:
        return value & 0xFF
    return ((value << amount) | (value >> (8 - amount))) & 0xFF


def ror8(value: int, amount: int) -> int:
    amount &= 7
    if amount == 0:
        return value & 0xFF
    return ((value >> amount) | (value << (8 - amount))) & 0xFF


def round_function(value: int, key: int) -> int:
    amount = ((key >> 5) & 7) + 1
    return rol8((value + key) & 0xFF, amount) ^ ((key * 0x5B + 0x33) & 0xFF)


def invert(operations, target: bytes) -> bytes:
    state = bytearray(target)
    for tag, values in reversed(operations):
        if tag == 0:
            index, key = values
            state[index] ^= key
        elif tag == 1:
            index, key = values
            state[index] = (state[index] - key) & 0xFF
        elif tag == 2:
            index, amount = values
            state[index] = ror8(state[index], amount)
        elif tag == 3:
            left, right = values
            state[left], state[right] = state[right], state[left]
        else:
            left, right, key = values
            encoded_left = state[left]
            encoded_right = state[right]
            state[left] = encoded_right ^ round_function(encoded_left, key)
            state[right] = encoded_left
    return bytes(state)


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {Path(sys.argv[0]).name} PUBLIC_BINARY", file=sys.stderr)
        return 2
    try:
        image = ElfImage(Path(sys.argv[1]))
        operations, target, _, _ = locate_capsule_data(image)
        payload = invert(operations, target)
        text = payload.decode("ascii")
        if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
            raise SolveError("recovered payload failed the expected format check")
        print(f"KCTF{{{text}}}")
        return 0
    except (OSError, SolveError) as error:
        print(f"solve failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
