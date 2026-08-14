#!/bin/sh
set -eu

challenge_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

(
    cd "$challenge_root/for_user"
    sha256sum Dockerfile docker-compose.yml flag ld-linux-x86-64.so.2 \
        libc.so.6 secondhand tcp_runner > SHA256SUMS
)
(
    cd "$challenge_root/for_organizer"
    sha256sum Dockerfile docker-compose.yml ld-linux-x86-64.so.2 \
        libc.so.6 requirements.txt secondhand secondhand.debug solve.py \
        tcp_runner verify_local.py verify_package.sh VERIFY.md WRITEUP.md > SHA256SUMS
)
