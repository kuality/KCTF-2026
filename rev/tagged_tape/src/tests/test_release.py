#!/usr/bin/env python3
import base64
import hashlib
import importlib.util
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


sys.dont_write_bytecode = True


CHALLENGE = Path(__file__).resolve().parents[2]
PUBLIC = CHALLENGE / "for_prob"
ORGANIZER = CHALLENGE / "for_organizer"
BINARY = PUBLIC / "tagged_tape"
SOLVER = ORGANIZER / "solve.py"


def fail(message: str):
    raise AssertionError(message)


def run_binary(candidate: bytes):
    result = subprocess.run(
        [str(BINARY)],
        input=candidate,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=3,
        check=False,
    )
    if result.returncode != 0:
        fail(f"binary exited with {result.returncode}: {result.stderr!r}")
    return result.stdout


def expect_verdict(candidate: bytes, expected: bytes):
    output = run_binary(candidate)
    if output != b"flag> " + expected + b"\n":
        fail(f"unexpected verdict for {candidate[:32]!r}: {output!r}")


def assert_public_layout():
    expected = {"README.md", "SHA256SUMS", "tagged_tape"}
    actual = {path.name for path in PUBLIC.iterdir()}
    if actual != expected:
        fail(f"unexpected participant files: {sorted(actual ^ expected)}")
    for path in PUBLIC.rglob("*"):
        if path.is_symlink():
            fail(f"participant symlink is forbidden: {path}")


def assert_organizer_layout():
    expected = {
        "DESIGN.md",
        "GENERATOR_MANIFEST.txt",
        "HINTS.md",
        "README.md",
        "SHA256SUMS",
        "UNINTENDED.md",
        "WRITEUP.md",
        "flag",
        "requirements.txt",
        "seed.hex",
        "solve.py",
        "tagged_tape",
        "tagged_tape.unstripped",
    }
    actual = {path.name for path in ORGANIZER.iterdir()}
    if actual != expected:
        fail(f"unexpected organizer files: {sorted(actual ^ expected)}")
    for path in ORGANIZER.rglob("*"):
        if path.is_symlink():
            fail(f"organizer symlink is forbidden: {path}")


def assert_no_leak(flag: bytes, seed_text: bytes):
    public_blob = b"\n".join(path.read_bytes() for path in sorted(PUBLIC.iterdir()))
    body = flag[5:-1]
    forbidden = [
        flag,
        body,
        flag.decode().encode("utf-16le"),
        flag.decode().encode("utf-16be"),
        flag.hex().encode(),
        base64.b64encode(flag),
        seed_text,
        bytes.fromhex(seed_text.decode()),
    ]
    forbidden.extend(body[index : index + 16] for index in range(len(body) - 15))
    for secret in forbidden:
        if secret and secret in public_blob:
            fail(f"participant package contains a secret sequence: {secret[:24]!r}")

    binary = BINARY.read_bytes()
    source_markers = (
        b"Program_data",
        b"Tape_types",
        b"Engine.",
        b"Main.",
        b"program_data.ml",
        b"engine.ml",
        b"main.ml",
        b"Xor_at",
        b"Add_at",
        b"Rol_at",
        b"Swap",
        b"Feistel",
        b"round_function",
    )
    leaked = [marker for marker in source_markers if marker in binary]
    if leaked:
        fail(f"release binary contains semantic source markers: {leaked}")

    solver_blob = SOLVER.read_bytes()
    for index in range(len(body) - 15):
        chunk = body[index : index + 16]
        if chunk in solver_blob:
            fail("official solver embeds a long flag substring")


def assert_verifier(flag: bytes):
    expect_verdict(flag + b"\n", b"Correct.")
    expect_verdict(flag, b"Correct.")

    body = bytearray(flag[5:-1])
    for index in range(len(body)):
        mutated = bytearray(body)
        mutated[index] = ord("0") if mutated[index] != ord("0") else ord("1")
        candidate = b"KCTF{" + bytes(mutated) + b"}\n"
        expect_verdict(candidate, b"Wrong.")

    malformed = (
        b"",
        b"\n",
        b"KCTF{}\n",
        b"kctf{" + bytes(body) + b"}\n",
        b"KCTF{" + bytes(body[:-1]) + b"}\n",
        b"KCTF{" + bytes(body) + b"0}\n",
        b"KCTF{" + bytes(body).upper() + b"}\n",
        b"KCTF{" + bytes(body[:16]) + b"\x00" + bytes(body[17:]) + b"}\n",
        b"A" * 4096 + b"\n",
        b"\xff\xfe\xfd\n",
    )
    for candidate in malformed:
        expect_verdict(candidate, b"Wrong.")

    for _ in range(3):
        expect_verdict(flag + b"\n", b"Correct.")


def assert_isolated_solver(flag: bytes):
    with tempfile.TemporaryDirectory(prefix="tagged-tape-solver-") as temp_name:
        temp = Path(temp_name)
        isolated_binary = temp / "tagged_tape"
        isolated_solver = temp / "solve.py"
        shutil.copy2(BINARY, isolated_binary)
        shutil.copy2(SOLVER, isolated_solver)
        result = subprocess.run(
            [sys.executable, str(isolated_solver), str(isolated_binary)],
            cwd=temp,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
        if result.returncode != 0:
            fail(f"isolated solver failed: {result.stderr!r}")
        if result.stdout != flag + b"\n" or result.stderr:
            fail(f"unexpected isolated solver output: {result.stdout!r} {result.stderr!r}")
        replay = subprocess.run(
            [str(isolated_binary)],
            input=result.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=3,
            check=False,
        )
        if replay.returncode != 0 or replay.stdout != b"flag> Correct.\n":
            fail(f"solver re-substitution failed: {replay.stdout!r}")


def assert_transform_bijection():
    spec = importlib.util.spec_from_file_location("tagged_tape_solver", SOLVER)
    if spec is None or spec.loader is None:
        fail("could not load the official solver")
    solver = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(solver)

    operations, target, _, tag_counts = solver.locate_capsule_data(
        solver.ElfImage(BINARY)
    )
    if len(operations) != 156 or len(target) != 64:
        fail("unexpected tape or target width")
    if tag_counts != [34, 33, 33, 12, 44]:
        fail(f"unexpected constructor distribution: {tag_counts}")

    def forward(payload: bytes) -> bytes:
        state = bytearray(payload)
        for tag, values in operations:
            if tag == 0:
                index, key = values
                state[index] ^= key
            elif tag == 1:
                index, key = values
                state[index] = (state[index] + key) & 0xFF
            elif tag == 2:
                index, amount = values
                state[index] = solver.rol8(state[index], amount)
            elif tag == 3:
                left, right = values
                state[left], state[right] = state[right], state[left]
            else:
                left, right, key = values
                old_left = state[left]
                old_right = state[right]
                state[left] = old_right
                state[right] = old_left ^ solver.round_function(old_right, key)
        return bytes(state)

    for index in range(256):
        first = hashlib.sha256(f"tagged-tape:{index}:a".encode()).digest()
        second = hashlib.sha256(f"tagged-tape:{index}:b".encode()).digest()
        payload = first + second
        transformed = forward(payload)
        if solver.invert(operations, transformed) != payload:
            fail(f"inverse property failed for deterministic case {index}")


def main():
    flag = (ORGANIZER / "flag").read_bytes().rstrip(b"\r\n")
    if not re.fullmatch(rb"KCTF\{[0-9a-f]{64}\}", flag):
        fail("organizer flag has the wrong format")
    seed_text = (ORGANIZER / "seed.hex").read_bytes().strip()
    if not re.fullmatch(rb"[0-9a-f]{64}", seed_text):
        fail("generator seed has the wrong format")
    if BINARY.read_bytes() != (ORGANIZER / "tagged_tape").read_bytes():
        fail("participant and organizer binaries differ")

    assert_public_layout()
    assert_organizer_layout()
    assert_no_leak(flag, seed_text)
    assert_transform_bijection()
    assert_verifier(flag)
    assert_isolated_solver(flag)
    print("release regression tests: PASS")


if __name__ == "__main__":
    main()
