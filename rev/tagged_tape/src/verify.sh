#!/usr/bin/env bash
set -euo pipefail

src_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
challenge_dir="$(cd -- "$src_dir/.." && pwd)"
public_binary="$challenge_dir/for_prob/tagged_tape"
organizer_binary="$challenge_dir/for_organizer/tagged_tape"
first_hash_file="$(mktemp)"

cleanup() {
  rm -f -- "$first_hash_file"
}
trap cleanup EXIT

"$src_dir/build.sh"
sha256sum "$public_binary" | awk '{print $1}' > "$first_hash_file"
"$src_dir/build.sh"

first_hash="$(<"$first_hash_file")"
second_hash="$(sha256sum "$public_binary" | awk '{print $1}')"
if [[ "$first_hash" != "$second_hash" ]]; then
  echo "non-reproducible release binary: $first_hash != $second_hash" >&2
  exit 1
fi

cmp --silent "$public_binary" "$organizer_binary"

(
  cd "$challenge_dir/for_prob"
  sha256sum --check SHA256SUMS
)
(
  cd "$challenge_dir/for_organizer"
  sha256sum --check SHA256SUMS
)

file_output="$(file "$public_binary")"
[[ "$file_output" == *"ELF 64-bit LSB executable"* ]]
[[ "$file_output" == *"x86-64"* ]]
[[ "$file_output" == *"statically linked"* ]]
[[ "$file_output" == *"stripped"* ]]

readelf -hW "$public_binary" | grep -Eq 'Type:[[:space:]]+EXEC'
readelf -hW "$public_binary" | grep -Eq 'Machine:[[:space:]]+Advanced Micro Devices X86-64'
readelf -lW "$public_binary" | grep -q 'GNU_RELRO'
stack_line="$(readelf -lW "$public_binary" | awk '$1 == "GNU_STACK" { print; exit }')"
[[ -n "$stack_line" ]]
[[ "$stack_line" != *"RWE"* ]]

if readelf -SW "$public_binary" | grep -Eq '\.(debug|symtab|strtab)([^[:alnum:]_]|$)'; then
  echo "release binary contains debug or static symbol sections" >&2
  exit 1
fi
if readelf -Ws "$public_binary" | grep -Eq 'Program_data|Tape_types|camlEngine|camlMain'; then
  echo "release binary exports challenge source symbols" >&2
  exit 1
fi

python3 "$src_dir/tests/test_release.py"

if find "$challenge_dir/for_prob" -type l -print -quit | grep -q .; then
  echo "participant package contains a symlink" >&2
  exit 1
fi
if find "$challenge_dir/for_prob" -type f \
  \( -name '*.ml' -o -name '*.mli' -o -name '*.cmi' -o -name '*.cmx' \
     -o -name '*.cmt' -o -name '*.cmti' -o -name '*.o' -o -name 'flag' \
     -o -name 'solve.py' \) -print -quit | grep -q .; then
  echo "participant package contains a private or compilation artifact" >&2
  exit 1
fi
if [[ -e "$src_dir/.build" ]]; then
  echo "temporary build directory survived cleanup" >&2
  exit 1
fi
if find "$src_dir" -type f \
  \( -name '*.cmi' -o -name '*.cmx' -o -name '*.cmt' -o -name '*.cmti' \
     -o -name '*.o' -o -name '*.pyc' -o -name '*.tmp' \) -print -quit | grep -q .; then
  echo "source tree contains a temporary compilation artifact" >&2
  exit 1
fi
if find "$challenge_dir" -type d -name '__pycache__' -print -quit | grep -q .; then
  echo "challenge package contains a Python bytecode cache" >&2
  exit 1
fi

echo "tagged_tape release gate: PASS"
