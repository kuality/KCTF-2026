#!/usr/bin/env bash
set -euo pipefail

src_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
challenge_dir="$(cd -- "$src_dir/.." && pwd)"

(
  cd "$challenge_dir/for_prob"
  sha256sum README.md tagged_tape > SHA256SUMS.tmp
  mv SHA256SUMS.tmp SHA256SUMS
)

(
  cd "$challenge_dir/for_organizer"
  files=(
    DESIGN.md
    GENERATOR_MANIFEST.txt
    HINTS.md
    README.md
    UNINTENDED.md
    WRITEUP.md
    flag
    requirements.txt
    seed.hex
    solve.py
    tagged_tape
    tagged_tape.unstripped
  )
  sha256sum "${files[@]}" > SHA256SUMS.tmp
  mv SHA256SUMS.tmp SHA256SUMS
)
