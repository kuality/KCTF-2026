#!/usr/bin/env python3
from pathlib import Path
import platform
import struct
import subprocess
import sys

EXPECTED = "kctf{dawn_courier_opens_the_route}"
EXPECTED_DISPATCH = "GATE-0815-3A7F-C29D"
HERE = Path(__file__).resolve().parent
BINARY = HERE.parent / "for_user" / "dawn_courier"
SOLVER = HERE.parents[1] / "exploit" / "solve.py"


def fail(message: str) -> None:
    raise SystemExit(f"[FAIL] {message}")


data = BINARY.read_bytes()
if data[:4] != b"\x7fELF":
    fail("배포 파일이 ELF가 아닙니다")
if data[4:6] != b"\x02\x01":
    fail("ELF64 little-endian 파일이 아닙니다")
if struct.unpack_from("<H", data, 18)[0] != 62:
    fail("x86-64(e_machine=62) 파일이 아닙니다")
for secret in (EXPECTED, EXPECTED_DISPATCH):
    if secret.encode() in data:
        fail(f"배포 바이너리에 평문 비밀값이 남아 있습니다: {secret}")

solver_output = subprocess.check_output(
    [sys.executable, str(SOLVER), str(BINARY)], text=True
)
solved = dict(line.split("=", 1) for line in solver_output.strip().splitlines())
if solved.get("flag") != EXPECTED or solved.get("dispatch") != EXPECTED_DISPATCH:
    fail(f"solver 결과 불일치: {solved!r}")

runtime_checked = platform.system() == "Linux" and platform.machine() == "x86_64"
if runtime_checked:
    result = subprocess.run(
        [str(BINARY)],
        input=EXPECTED + "\n",
        text=True,
        capture_output=True,
        check=False,
    )
    if (
        result.returncode != 0
        or EXPECTED_DISPATCH not in result.stdout
        or "Next route: 815-2" not in result.stdout
    ):
        fail("정답 입력 실행 검증에 실패했습니다")
    wrong = subprocess.run(
        [str(BINARY)],
        input="x" + EXPECTED[1:] + "\n",
        text=True,
        capture_output=True,
        check=False,
    )
    if wrong.returncode == 0 or EXPECTED_DISPATCH in wrong.stdout:
        fail("오답 입력에서 전달값이 노출됩니다")

suffix = ", runtime" if runtime_checked else ""
print(f"[PASS] ELF x86-64, secret leakage, solver handoff{suffix} checks")
