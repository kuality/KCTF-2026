#!/usr/bin/env python3
from pathlib import Path
import platform
import struct
import subprocess
import sys

EXPECTED = "KCTF{9_c4ts_0n3_0rd3r_ny4ny4ny4ng}"
EXPECTED_PASSPHRASE = "ny4ny4ny4ng_c4t_numb3r_9"
LEGACY_PASSPHRASE = "ny4ny4ny4ng_c4t_numb3r_4"
HERE = Path(__file__).resolve().parent
BINARY = HERE.parent / "for_user" / "nyanyanyang"
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

for secret in (EXPECTED, EXPECTED_PASSPHRASE, LEGACY_PASSPHRASE):
    if secret.encode() in data:
        fail(f"배포 바이너리에 평문 비밀값이 남아 있습니다: {secret}")

body = EXPECTED[len("KCTF{"):-1].encode()
for start in range(0, len(body) - 12 + 1):
    if body[start:start + 12] in data:
        fail("배포 바이너리에 플래그 부분 문자열이 남아 있습니다")

solver_output = subprocess.check_output(
    [sys.executable, str(SOLVER), str(BINARY)],
    text=True,
)
solved = dict(
    line.split("=", 1)
    for line in solver_output.strip().splitlines()
    if "=" in line and not line.startswith("[")
)
if solved.get("passphrase") != EXPECTED_PASSPHRASE:
    fail(f"solver 패스프레이즈 불일치: {solved!r}")
if solved.get("flag") != EXPECTED:
    fail(f"solver 플래그 불일치: {solved!r}")

runtime_checked = platform.system() == "Linux" and platform.machine() == "x86_64"
if runtime_checked:
    result = subprocess.run(
        [str(BINARY)], input=EXPECTED_PASSPHRASE + "\n",
        text=True, capture_output=True, check=False,
    )
    if result.returncode != 0 or EXPECTED not in result.stdout:
        fail("정답 입력 실행 검증에 실패했습니다")

    legacy = subprocess.run(
        [str(BINARY)], input=LEGACY_PASSPHRASE + "\n",
        text=True, capture_output=True, check=False,
    )
    if legacy.returncode == 0 or "KCTF" in legacy.stdout:
        fail("미끼 패스프레이즈가 승인됩니다")

    for bad in ("", "a" * 24, "x" + EXPECTED_PASSPHRASE[1:], "nyanyanyang"):
        wrong = subprocess.run(
            [str(BINARY)], input=bad + "\n",
            text=True, capture_output=True, check=False,
        )
        if wrong.returncode == 0 or "KCTF" in wrong.stdout:
            fail(f"오답이 승인됩니다: {bad!r}")

suffix = ", runtime" if runtime_checked else ""
print(f"[PASS] ELF x86-64, secret leakage, solver{suffix} checks")
