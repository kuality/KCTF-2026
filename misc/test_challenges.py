#!/usr/bin/env python3
"""Organizer-side end-to-end regression tests for all five MISC challenges.

Run with the project environment so OCR/PDF dependencies are available:

    .venv/bin/python test_challenges.py -v
"""

from __future__ import annotations

import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parent

CHALLENGES = [
    {
        "dir": "01-shredded",
        "zip": "shredded.zip",
        "root": "shredded",
        "solve_subdir": "fragments",
        "flag": "KCTF{0cr_p1p3l1n3_b34ts_th3_shr3dd3r}",
        "timeout": 300,
    },
    {
        "dir": "02-inbox-triage",
        "zip": "inbox-triage.zip",
        "root": "inbox-triage",
        "solve_subdir": "maildump",
        "flag": "KCTF{thr34d_h1j4ck_h1d3s_1n_th3_gr4ph}",
        "timeout": 180,
    },
    {
        "dir": "03-intel-chain",
        "zip": "intel-chain.zip",
        "root": "intel-chain",
        "flag": "KCTF{cr0ss_d0c_c0rr3l4t10n_1s_th3_j0b}",
        "timeout": 180,
    },
    {
        "dir": "04-canary-index",
        "zip": "canary-index.zip",
        "root": "canary-index",
        "flag": "KCTF{c4n4ry_m4tch_782992d2c39953d39ab94a74}",
        "timeout": 60,
    },
    {
        "dir": "05-alias-chain",
        "zip": "alias-chain.zip",
        "root": "alias-chain",
        "flag": "KCTF{4l14s_ch41n_0dff2f984c5429eeca69c499}",
        "timeout": 60,
    },
]


def zip_path(spec: dict[str, object]) -> Path:
    return ROOT / str(spec["dir"]) / "dist" / str(spec["zip"])


def load_module(name: str, path: Path):
    module_spec = importlib.util.spec_from_file_location(name, path)
    if module_spec is None or module_spec.loader is None:
        raise ImportError(path)
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    return module


class DistributionTests(unittest.TestCase):
    maxDiff = None

    def test_expected_layout_and_counts(self):
        expected_counts = {
            "01-shredded": {
                "suffix": "/fragments/",
                "extension": ".png",
                "count": 410,
            },
            "02-inbox-triage": {
                "suffix": "/maildump/",
                "extension": ".eml",
                "count": 600,
            },
            "04-canary-index": {
                "suffix": "/BRIEFINGS/",
                "extension": ".txt",
                "count": 972,
            },
        }
        for spec in CHALLENGES:
            with self.subTest(challenge=spec["dir"]):
                path = zip_path(spec)
                self.assertTrue(path.is_file(), path)
                with zipfile.ZipFile(path) as archive:
                    self.assertIsNone(archive.testzip())
                    names = archive.namelist()
                    self.assertTrue(
                        all(name.startswith(str(spec["root"]) + "/") for name in names)
                    )
                    rule = expected_counts.get(str(spec["dir"]))
                    if rule:
                        matching = [
                            name for name in names
                            if str(rule["suffix"]) in name
                            and name.endswith(str(rule["extension"]))
                        ]
                        self.assertEqual(int(rule["count"]), len(matching))

        with zipfile.ZipFile(zip_path(CHALLENGES[2])) as archive:
            self.assertEqual(
                3,
                sum(name.startswith("intel-chain/sandbox/") and name.endswith(".json")
                    for name in archive.namelist()),
            )
        with zipfile.ZipFile(zip_path(CHALLENGES[3])) as archive:
            self.assertEqual(
                12,
                sum("/LEAKS/" in name and name.endswith(".txt")
                    for name in archive.namelist()),
            )
        with zipfile.ZipFile(zip_path(CHALLENGES[4])) as archive:
            self.assertEqual(
                27,
                sum("/BLOG/" in name and name.endswith(".html")
                    for name in archive.namelist()),
            )
            self.assertEqual(
                27,
                sum("/TRAVEL/" in name and name.endswith(".txt")
                    for name in archive.namelist()),
            )
            self.assertEqual(
                27,
                sum("/SOCIAL/" in name and name.endswith(".json")
                    for name in archive.namelist()),
            )
            reviews = archive.read("alias-chain/REVIEWS.jsonl").decode("utf-8")
            market = archive.read("alias-chain/MARKET.csv").decode("utf-8")
            self.assertEqual(27, len(reviews.splitlines()))
            self.assertEqual(28, len(market.splitlines()))  # header + 27 records

    def test_flags_are_not_shipped_in_plaintext(self):
        for spec in CHALLENGES:
            needle = str(spec["flag"]).encode("ascii")
            with self.subTest(challenge=spec["dir"]), zipfile.ZipFile(
                zip_path(spec)
            ) as archive:
                for name in archive.namelist():
                    if name.endswith("/"):
                        continue
                    self.assertNotIn(needle, archive.read(name), name)

    def test_player_briefs_are_bundled(self):
        with zipfile.ZipFile(zip_path(CHALLENGES[0])) as archive:
            notes = archive.read("shredded/NOTES.txt").decode("utf-8")
            self.assertIn("KCTFENC1", notes)
            self.assertIn("SHA256(prefix)", notes)
            self.assertIn("HMAC-SHA256", notes)
            self.assertIn("ZIP CRC", notes)

        with zipfile.ZipFile(zip_path(CHALLENGES[1])) as archive:
            brief = archive.read("inbox-triage/INCIDENT_BRIEF.txt").decode("utf-8")
            self.assertIn("기존 내부 업무 대화", brief)
            self.assertIn("외부 발신자", brief)
            self.assertIn("스팸 필터까지 통과", brief)

    def test_shredded_flag_requires_exact_payload(self):
        generator = load_module(
            "shredded_generator_test", ROOT / "01-shredded" / "prob.py"
        )
        solver = load_module(
            "shredded_solver_test", ROOT / "01-shredded" / "solve.py"
        )
        payload = generator.build_payload()
        self.assertNotIn(generator.FLAG.encode("ascii"), payload)
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            self.assertIsNone(archive.testzip())
            archive.read("recovery_log.txt")
        self.assertEqual(generator.FLAG, solver.decrypt_flag(payload))

        trailer_pos = payload.rfind(generator.TRAILER_MAGIC)
        eocd_pos = payload.rfind(b"PK\x05\x06")
        self.assertGreater(trailer_pos, eocd_pos)
        # 압축 본문, 중앙 디렉터리, ZIP 뒤 padding, 암호문/tag를 포함해 모든
        # 바이트를 하나씩 뒤집는다. 어느 단일 바이트 손상도 플래그로 이어지면 안 된다.
        for position in range(len(payload)):
            damaged = bytearray(payload)
            damaged[position] ^= 1
            self.assertEqual(
                "", solver.decrypt_flag(bytes(damaged)), f"position={position}"
            )


class EndToEndTests(unittest.TestCase):
    def run_checked(self, cmd: list[str], timeout: int) -> str:
        env = dict(os.environ)
        env.setdefault("PYTHONUNBUFFERED", "1")
        proc = subprocess.run(
            cmd,
            cwd=ROOT,
            env=env,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            check=False,
        )
        self.assertEqual(0, proc.returncode, proc.stdout)
        return proc.stdout

    def test_reference_solvers_from_fresh_zip_extractions(self):
        with tempfile.TemporaryDirectory(prefix="kctf-misc-e2e-") as tmp:
            tmp_path = Path(tmp)
            for spec in CHALLENGES:
                with self.subTest(challenge=spec["dir"]):
                    extract_dir = tmp_path / str(spec["dir"])
                    with zipfile.ZipFile(zip_path(spec)) as archive:
                        archive.extractall(extract_dir)
                    challenge_root = extract_dir / str(spec["root"])
                    solver_input = challenge_root / str(spec.get("solve_subdir", ""))
                    output = self.run_checked(
                        [
                            sys.executable,
                            str(ROOT / str(spec["dir"]) / "solve.py"),
                            str(solver_input),
                        ],
                        int(spec["timeout"]),
                    )
                    self.assertIn(str(spec["flag"]), output, output)

    def test_shortcut_audits(self):
        audits = [
            ("02-inbox-triage", 60, "불리언 1~2개로는 특정되지 않는다"),
            ("04-canary-index", 60, "PASS"),
            ("05-alias-chain", 60, "PASS"),
        ]
        for directory, timeout, success_marker in audits:
            with self.subTest(challenge=directory):
                output = self.run_checked(
                    [sys.executable, str(ROOT / directory / "audit.py")], timeout
                )
                self.assertIn(success_marker, output, output)
                self.assertNotIn("지름길이 있다", output, output)


if __name__ == "__main__":
    unittest.main(verbosity=2)
