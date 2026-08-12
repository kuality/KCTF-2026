#!/usr/bin/env bash
set -euo pipefail

src_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
challenge_dir="$(cd -- "$src_dir/.." && pwd)"
image_name=kctf-tagged-tape-build:ocaml-5.5.0

docker build \
  --platform linux/amd64 \
  --file "$src_dir/Dockerfile.build" \
  --tag "$image_name" \
  "$src_dir"

docker run --rm \
  --platform linux/amd64 \
  --network none \
  --cpus 2 \
  --memory 4g \
  --pids-limit 256 \
  --tmpfs /tmp:rw,nosuid,nodev,size=256m \
  --volume "$challenge_dir:/work" \
  --workdir /work/src \
  "$image_name" \
  bash -lc ./build_inside.sh

"$src_dir/update_hashes.sh"
