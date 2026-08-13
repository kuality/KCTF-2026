#!/usr/bin/env python3
from pathlib import Path
import platform
import struct
import subprocess
import sys

EXPECTED = "kctf{1945_08_15_voice_of_liberation}"
EXPECTED_DISPATCH = "GATE-0815-3A7F-C29D"
EXPECTED_RELAY = "VOICE-1945-8B1C-77E2"
HERE = Path(__file__).resolve().parent
BINARY = HERE.parent / "for_user" / "liberation_voice"
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
for secret in (EXPECTED, EXPECTED_DISPATCH, EXPECTED_RELAY):
    if secret.encode() in data:
        fail(f"배포 바이너리에 평문 비밀값이 남아 있습니다: {secret}")

solver_output = subprocess.check_output(
    [
        sys.executable,
        str(SOLVER),
        str(BINARY),
        EXPECTED_DISPATCH,
        EXPECTED_RELAY,
    ],
    text=True,
)
solved = dict(line.split("=", 1) for line in solver_output.strip().splitlines())
if solved.get("flag") != EXPECTED:
    fail(f"solver 결과 불일치: {solved!r}")

runtime_checked = platform.system() == "Linux" and platform.machine() == "x86_64"
if runtime_checked:
    result = subprocess.run(
        [str(BINARY)],
        input=EXPECTED_DISPATCH + "\n" + EXPECTED_RELAY + "\n" + EXPECTED + "\n",
        text=True,
        capture_output=True,
        check=False,
    )
    if result.returncode != 0 or "1945-08-15" not in result.stdout:
        fail("정답 입력 실행 검증에 실패했습니다")
    wrong_relay = subprocess.run(
        [str(BINARY)],
        input=EXPECTED_DISPATCH + "\n" + EXPECTED_RELAY[:-1] + "0\n",
        text=True,
        capture_output=True,
        check=False,
    )
    if wrong_relay.returncode == 0 or "flag>" in wrong_relay.stdout:
        fail("잘못된 2번 전달값으로 stage-3 VM이 열립니다")
    wrong_flag = subprocess.run(
        [str(BINARY)],
        input=(
            EXPECTED_DISPATCH
            + "\n"
            + EXPECTED_RELAY
            + "\n"
            + "x"
            + EXPECTED[1:]
            + "\n"
        ),
        text=True,
        capture_output=True,
        check=False,
    )
    if wrong_flag.returncode == 0:
        fail("3번 오답이 승인됩니다")

suffix = ", runtime" if runtime_checked else ""
print(f"[PASS] ELF x86-64, secret leakage, chained solver{suffix} checks")
