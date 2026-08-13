#!/usr/bin/env bash
set -euo pipefail

src_dir=/work/src
challenge_dir=/work
build_dir=/work/src/.build

cleanup() {
  rm -rf -- "$build_dir"
}
trap cleanup EXIT

rm -rf -- "$build_dir"
mkdir -p "$build_dir" "$src_dir/generated"
cd "$build_dir"

cp "$src_dir/tape_types.ml" "$src_dir/engine.ml" "$src_dir/generate.ml" \
  "$src_dir/main.ml" .

ocamlopt -O2 -no-g -opaque -nodynlink -c tape_types.ml
ocamlopt -O2 -no-g -opaque -nodynlink -c engine.ml
ocamlopt -O2 -no-g -nodynlink -o generator tape_types.cmx engine.cmx generate.ml

./generator \
  --flag-file "$challenge_dir/for_organizer/flag" \
  --seed-file "$challenge_dir/for_organizer/seed.hex" \
  --output program_data.ml \
  --manifest "$challenge_dir/for_organizer/GENERATOR_MANIFEST.txt"

install -m 0644 program_data.ml "$src_dir/generated/program_data.ml"
ocamlopt -O2 -no-g -opaque -nodynlink -c program_data.ml
ocamlopt -O2 -no-g -opaque -nodynlink -c main.ml
ocamlopt -O2 -no-g -nodynlink -o tagged_tape.unstripped \
  tape_types.cmx program_data.cmx engine.cmx main.cmx \
  -ccopt -static \
  -ccopt -no-pie \
  -ccopt -Wl,--no-export-dynamic \
  -ccopt -Wl,--build-id=none \
  -ccopt -Wl,-z,relro,-z,now \
  -ccopt -Wl,-z,noexecstack

install -m 0755 tagged_tape.unstripped \
  "$challenge_dir/for_organizer/tagged_tape.unstripped"
cp tagged_tape.unstripped tagged_tape
strip --strip-all tagged_tape
perl "$src_dir/scrub_release.pl" tagged_tape
install -m 0755 tagged_tape "$challenge_dir/for_prob/tagged_tape"
install -m 0755 tagged_tape "$challenge_dir/for_organizer/tagged_tape"
