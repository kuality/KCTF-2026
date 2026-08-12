#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <Dockerfile.build export directory>" >&2
    exit 1
fi

artifacts="$(cd "$1" && pwd)"
challenge_root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"

for required in secondhand secondhand.debug tcp_runner libc.so.6 ld-linux-x86-64.so.2; do
    test -f "$artifacts/$required" || {
        echo "missing build artifact: $required" >&2
        exit 1
    }
done

for package in for_user for_organizer; do
    install -m 0555 "$artifacts/secondhand" "$challenge_root/$package/secondhand"
    install -m 0555 "$artifacts/tcp_runner" "$challenge_root/$package/tcp_runner"
    install -m 0444 "$artifacts/libc.so.6" "$challenge_root/$package/libc.so.6"
    install -m 0555 "$artifacts/ld-linux-x86-64.so.2" \
        "$challenge_root/$package/ld-linux-x86-64.so.2"
done
install -m 0555 "$artifacts/secondhand.debug" \
    "$challenge_root/for_organizer/secondhand.debug"

cmp -s "$challenge_root/for_user/secondhand" \
    "$challenge_root/for_organizer/secondhand"
cmp -s "$challenge_root/for_user/libc.so.6" \
    "$challenge_root/for_organizer/libc.so.6"
cmp -s "$challenge_root/for_user/ld-linux-x86-64.so.2" \
    "$challenge_root/for_organizer/ld-linux-x86-64.so.2"

"$challenge_root/src/update_checksums.sh"
echo "release artifacts installed without changing either flag"
