#!/bin/sh
set -eu

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
user_dir="$root_dir/for_user"
organizer_dir="$root_dir/for_organizer"
binary_name=late_checkout
listener_name=tcp_listener
flag_pattern='^KCTF\{[0-9a-f]{64}\}$'

"$root_dir/src/verify_binary.sh" "$user_dir/$binary_name" \
    "$organizer_dir/solve_constants.py"

for package_dir in "$user_dir" "$organizer_dir"; do
    test -f "$package_dir/flag"
    test -x "$package_dir/$binary_name"
    test -x "$package_dir/$listener_name"
    test -f "$package_dir/libc.so.6"
    test -x "$package_dir/ld-linux-x86-64.so.2"
    test -f "$package_dir/Dockerfile"
    test -f "$package_dir/docker-compose.yml"
done

grep -Fxq 'kctf{flag}' "$user_dir/flag"
grep -Eq "$flag_pattern" "$organizer_dir/flag"

test -f "$organizer_dir/solve_constants.py"
test ! -e "$user_dir/solve_constants.py"

cmp -s "$user_dir/$binary_name" "$organizer_dir/$binary_name"
cmp -s "$user_dir/$listener_name" "$organizer_dir/$listener_name"
cmp -s "$user_dir/libc.so.6" "$organizer_dir/libc.so.6"
cmp -s "$user_dir/ld-linux-x86-64.so.2" "$organizer_dir/ld-linux-x86-64.so.2"
cmp -s "$user_dir/libc.so.6" "$root_dir/../common/ubuntu_26_04/libc.so.6"
cmp -s "$user_dir/ld-linux-x86-64.so.2" \
    "$root_dir/../common/ubuntu_26_04/ld-linux-x86-64.so.2"

# The listener is a stripped, static PIE and therefore needs no runtime package.
if readelf -lW "$user_dir/$listener_name" | grep -q 'INTERP'; then
    echo "listener unexpectedly has a dynamic interpreter" >&2
    exit 1
fi
if readelf -SW "$user_dir/$listener_name" | grep -q '\.symtab'; then
    echo "listener is not stripped" >&2
    exit 1
fi
if cmp -s "$user_dir/flag" "$organizer_dir/flag"; then
    echo "package flags must differ" >&2
    exit 1
fi

# The public package must remain self-contained and organizer-data free.
if rg -n '(for_organizer|\.\./src|solve\.py|WRITEUP)' "$user_dir" \
    --glob 'Dockerfile' --glob 'docker-compose.yml' --glob 'README.md'; then
    echo "public package contains a forbidden reference" >&2
    exit 1
fi

echo "package structure, artifact identity, and flag separation are correct"
