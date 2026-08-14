#!/usr/bin/env python3
from __future__ import annotations

import importlib.util
import json
import math
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def _load(name: str, path: Path):
    specification = importlib.util.spec_from_file_location(name, path)
    assert specification and specification.loader
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


generator = _load("common_prob", ROOT / "src" / "prob.py")
solver = _load("common_solve", ROOT / "for_organizer" / "solve.py")


def main() -> None:
    public_dir = ROOT / "for_user"
    assert sorted(path.name for path in public_dir.iterdir() if path.is_file()) == [
        "instance.json",
        "prob.py",
    ]
    assert (ROOT / "src" / "prob.py").read_bytes() == (
        public_dir / "prob.py"
    ).read_bytes()

    flag = b"KCTF{" + b"1" * 64 + b"}"
    for index in range(20):
        seed = index.to_bytes(32, "big")
        instance = generator.generate(flag, seed, bits=1024)
        n = int(instance["n"], 0)
        c1 = int(instance["c1"], 0)
        c2 = int(instance["c2"], 0)
        assert math.gcd(c1, n) == 1
        assert math.gcd(c2, n) == 1
        divisor, a, b = solver.extended_gcd(int(instance["e1"]), int(instance["e2"]))
        assert divisor == 1
        recovered = (solver.signed_power(c1, a, n) * solver.signed_power(c2, b, n)) % n
        assert recovered.to_bytes(len(flag), "big") == flag

    organizer_dir = ROOT / "for_organizer"
    seed = bytes.fromhex(
        (organizer_dir / "instance_seed.hex").read_text(encoding="ascii").strip()
    )
    generated = generator.generate((organizer_dir / "flag").read_bytes(), seed)
    public_instance = json.loads(
        (public_dir / "instance.json").read_text(encoding="utf-8")
    )
    organizer_instance = json.loads(
        (organizer_dir / "instance.json").read_text(encoding="utf-8")
    )
    assert generated == public_instance == organizer_instance
    print("PASS common_ground public source and 20 deterministic seeds")


if __name__ == "__main__":
    main()
