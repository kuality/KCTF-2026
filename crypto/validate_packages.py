#!/usr/bin/env python3
"""Static package, parity, checksum, and secret-leak gate for all five challenges."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CHALLENGES = (
    "common_ground",
    "second_receipt",
    "zero_contribution",
    "forbidden_counter",
    "third_time_frost",
)
SERVICES = CHALLENGES[1:]
BASE = (
    "ubuntu:26.04@sha256:"
    "7b202b0e2e0028c6250f5fcf41d04df492d145a1654c6995a6553f0c1f6f1960"
)
FLAG_RE = re.compile(rb"KCTF\{[0-9a-f]{64}\}\n")
CORE_FILES = {
    "second_receipt": ("server.py", "ed25519_ref.py"),
    "zero_contribution": ("server.py", "aes_gcm.py", "x25519_ref.py"),
    "forbidden_counter": ("server.py", "aes_gcm.py"),
    "third_time_frost": ("server.py", "frost.py", "ristretto.py"),
}
ROOT_SERVICES = (
    "common_ground",
    "second_receipt",
    "zero_contribution",
    "forbidden_counter",
    "third_time_frost",
)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def verify_checksums(challenge: Path) -> None:
    checksum_file = challenge / "for_organizer" / "SHA256SUMS"
    require(checksum_file.is_file(), f"missing {checksum_file}")
    listed: set[Path] = set()
    for line in checksum_file.read_text(encoding="ascii").splitlines():
        digest, relative = line.split("  ", 1)
        path = challenge / relative
        require(path not in listed, f"duplicate checksum target: {path}")
        listed.add(path)
        require(path.is_file(), f"checksum target missing: {path}")
        require(
            hashlib.sha256(path.read_bytes()).hexdigest() == digest,
            f"checksum mismatch: {path}",
        )
    expected = {
        path
        for top_level in ("src", "for_user", "for_organizer")
        for path in (challenge / top_level).rglob("*")
        if path.is_file()
        and path != checksum_file
        and "__pycache__" not in path.parts
        and path.suffix != ".pyc"
    }
    require(listed == expected, f"checksum manifest is incomplete: {challenge.name}")


def main() -> None:
    root_compose = ROOT / "docker-compose.yml"
    require(root_compose.is_file(), "missing root docker-compose.yml")
    root_compose_text = root_compose.read_text(encoding="utf-8")
    for service in ROOT_SERVICES:
        require(
            re.search(rf"^  {re.escape(service)}:$", root_compose_text, re.MULTILINE)
            is not None,
            f"root Compose omits {service}",
        )
    require(
        "CRYPTO_PACKAGE" not in root_compose_text,
        "root Compose must not require a mode variable",
    )
    for service in ROOT_SERVICES[1:]:
        require(
            root_compose_text.count(f"./{service}/for_organizer") == 2,
            f"root Compose does not use organizer build and flag: {service}",
        )
        require(
            f"./{service}/for_user" not in root_compose_text,
            f"root Compose accidentally uses the fake flag package: {service}",
        )

    actual_flags: list[bytes] = []
    for challenge_name in CHALLENGES:
        challenge = ROOT / challenge_name
        for directory in ("src", "for_user", "for_organizer"):
            require(
                (challenge / directory).is_dir(),
                f"missing {challenge_name}/{directory}",
            )
        organizer = challenge / "for_organizer"
        user = challenge / "for_user"
        flag = (organizer / "flag").read_bytes()
        require(
            FLAG_RE.fullmatch(flag) is not None, f"bad organizer flag: {challenge_name}"
        )
        actual_flags.append(flag)
        for document in (
            "DESIGN.md",
            "HINTS.md",
            "WRITEUP.md",
            "solve.py",
            "SHA256SUMS",
        ):
            require(
                (organizer / document).is_file(), f"missing {challenge_name}/{document}"
            )
        require(
            (challenge / "src" / "verify.sh").is_file(),
            f"missing verify.sh: {challenge_name}",
        )
        require(
            (user / "README.md").is_file(), f"missing public README: {challenge_name}"
        )
        verify_checksums(challenge)

        seed_file = organizer / "instance_seed.hex"
        if challenge_name == "common_ground":
            seed = seed_file.read_bytes().strip()
            require(len(seed) >= 64, "short private seed: common_ground")
        else:
            require(not seed_file.exists(), f"unused service seed: {challenge_name}")
            seed = b""
        for path in user.rglob("*"):
            if not path.is_file():
                continue
            content = path.read_bytes()
            require(flag.rstrip(b"\n") not in content, f"actual flag leaked to {path}")
            if seed:
                require(seed not in content, f"private seed leaked to {path}")
            require(".." not in path.parts, f"invalid public path: {path}")

        if challenge_name in SERVICES:
            require(
                (user / "flag").read_bytes() == b"kctf{flag}\n",
                f"bad fake flag: {challenge_name}",
            )
            for package in (user, organizer):
                dockerfile = package / "Dockerfile"
                compose = package / "docker-compose.yml"
                dockerignore = package / ".dockerignore"
                require(
                    dockerfile.is_file()
                    and compose.is_file()
                    and dockerignore.is_file(),
                    f"missing Docker package: {package}",
                )
                docker_text = dockerfile.read_text(encoding="utf-8")
                compose_text = compose.read_text(encoding="utf-8")
                ignore_lines = dockerignore.read_text(encoding="utf-8").splitlines()
                first_line = docker_text.splitlines()[0]
                require(first_line == f"FROM {BASE}", f"unpinned image: {dockerfile}")
                require(
                    "../" not in docker_text, f"parent Docker reference: {dockerfile}"
                )
                require(
                    "../" not in compose_text, f"parent Compose reference: {compose}"
                )
                require(
                    "/run/secrets/challenge_flag" in docker_text,
                    f"flag is not runtime-mounted: {dockerfile}",
                )
                require(
                    not re.search(r"^COPY .*\bflag\b", docker_text, re.MULTILINE),
                    f"flag copied into image: {dockerfile}",
                )
                require(
                    "challenge_flag:" in compose_text
                    and "file: ./flag" in compose_text,
                    f"missing Compose secret: {compose}",
                )
                require(
                    ignore_lines[:1] == ["*"] and "!flag" not in ignore_lines,
                    f"flag enters build context: {dockerignore}",
                )
            for filename in CORE_FILES[challenge_name]:
                source = (challenge / "src" / filename).read_bytes()
                require(
                    (user / filename).read_bytes() == source,
                    f"user source drift: {challenge_name}/{filename}",
                )
                require(
                    (organizer / filename).read_bytes() == source,
                    f"organizer source drift: {challenge_name}/{filename}",
                )
            require(
                (user / "Dockerfile").read_bytes()
                == (organizer / "Dockerfile").read_bytes(),
                f"Dockerfile drift: {challenge_name}",
            )
            require(
                (user / "docker-compose.yml").read_bytes()
                == (organizer / "docker-compose.yml").read_bytes(),
                f"Compose drift: {challenge_name}",
            )
            require(
                (user / ".dockerignore").read_bytes()
                == (organizer / ".dockerignore").read_bytes(),
                f"Docker ignore drift: {challenge_name}",
            )
        else:
            require(
                not (user / "flag").exists(),
                "offline public package must not contain a flag file",
            )
            require(
                (user / "instance.json").read_bytes()
                == (organizer / "instance.json").read_bytes(),
                "offline instance drift",
            )
            dockerfile = user / "Dockerfile"
            dockerignore = user / ".dockerignore"
            require(
                dockerfile.is_file() and dockerignore.is_file(),
                "missing common_ground attachment server",
            )
            docker_text = dockerfile.read_text(encoding="utf-8")
            ignore_lines = dockerignore.read_text(encoding="utf-8").splitlines()
            require(
                docker_text.splitlines()[0] == f"FROM {BASE}",
                "unpinned common_ground image",
            )
            require(
                "http.server" in docker_text and "flag" not in docker_text,
                "unsafe common_ground attachment server",
            )
            require(
                ignore_lines[:1] == ["*"] and "!flag" not in ignore_lines,
                "common_ground secret enters build context",
            )

    require(
        len(set(actual_flags)) == len(actual_flags), "organizer flags are not unique"
    )
    allowed_flag_paths = {
        (ROOT / challenge_name / "for_organizer" / "flag").resolve()
        for challenge_name in CHALLENGES
    }
    for path in ROOT.rglob("*"):
        if not path.is_file() or path.suffix == ".pyc":
            continue
        content = path.read_bytes()
        for flag in actual_flags:
            if flag.rstrip(b"\n") in content:
                require(
                    path.resolve() in allowed_flag_paths,
                    f"actual flag leaked outside its secret file: {path}",
                )
    forbidden = list(ROOT.rglob("__pycache__")) + list(ROOT.rglob("*.pyc"))
    require(not forbidden, f"temporary Python artifacts remain: {forbidden[:3]}")
    print("PASS static layout, parity, checksums, flags, and public leak gate")


if __name__ == "__main__":
    main()
