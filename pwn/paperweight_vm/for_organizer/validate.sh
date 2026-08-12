#!/bin/sh
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
challenge=$(CDPATH= cd -- "$here/.." && pwd)
user="$challenge/for_user"
organizer="$challenge/for_organizer"
source_build="$challenge/src/build"

require_file() {
    test -f "$1" || { echo "missing: $1" >&2; exit 1; }
}

for package in "$user" "$organizer"; do
    require_file "$package/flag"
    require_file "$package/paperweight_vm"
    require_file "$package/listener"
    require_file "$package/libc.so.6"
    require_file "$package/ld-linux-x86-64.so.2"
    require_file "$package/Dockerfile"
    require_file "$package/docker-compose.yml"
    test -x "$package/paperweight_vm"
    test -x "$package/listener"
    test -x "$package/ld-linux-x86-64.so.2"
done

require_file "$organizer/solve.py"
require_file "$organizer/verify_local.py"

grep -Fxq 'kctf{flag}' "$user/flag"
grep -Eq '^KCTF\{[0-9a-f]{64}\}$' "$organizer/flag"

cmp -s "$user/paperweight_vm" "$organizer/paperweight_vm"
cmp -s "$user/listener" "$organizer/listener"
cmp -s "$user/paperweight_vm" "$source_build/paperweight_vm"
cmp -s "$user/listener" "$source_build/listener"
cmp -s "$organizer/offsets.json" "$source_build/offsets.json"
cmp -s "$user/libc.so.6" "$organizer/libc.so.6"
cmp -s "$user/ld-linux-x86-64.so.2" "$organizer/ld-linux-x86-64.so.2"
cmp -s "$user/Dockerfile" "$organizer/Dockerfile"
cmp -s "$user/docker-compose.yml" "$organizer/docker-compose.yml"
! cmp -s "$user/flag" "$organizer/flag"

test "$(sha256sum "$user/libc.so.6" | awk '{print $1}')" = \
    d763925433ff9b757390549e1b20c085f5e6de27ae700fe89194178d96a8a2b0
test "$(sha256sum "$user/ld-linux-x86-64.so.2" | awk '{print $1}')" = \
    223b94a42758f2434da331cc0aa62db1af5b456481762c5caceefa1a2d1eb8fb
test "$(sha256sum "$user/paperweight_vm" | awk '{print $1}')" = \
    13b3bde3df0db05c6cc7249595f729d4f9796e4dad627a6956d6d7ecd28cbbce
test "$(sha256sum "$user/listener" | awk '{print $1}')" = \
    a27266f29eece1e03bcbab330d9ad6d868007a4d2a086a15b6f135df20c21f7a
grep -q '"handler_leak_offset": 5536' "$organizer/offsets.json"
grep -q '"pivot_offset": 7712' "$organizer/offsets.json"
grep -q '"pop_rdx_offset": 7728' "$organizer/offsets.json"
grep -q '"pwn_uid": 2000' "$organizer/offsets.json"

test "$(tr -d '\n' < "$user/flag")" = 'kctf{flag}'
! grep -RFlf "$organizer/flag" "$user" >/dev/null
! find "$user" -type f \( -name 'solve*' -o -name 'offsets.json' \
    -o -name 'WRITEUP*' -o -name '*.c' -o -name '*.py' \) | grep -q .

readelf -hW "$user/paperweight_vm" | grep -q 'Type:.*DYN'
readelf -lW "$user/paperweight_vm" | grep -q 'GNU_STACK.*RW '
readelf -lW "$user/paperweight_vm" | grep -q 'GNU_RELRO'
readelf -dW "$user/paperweight_vm" | grep -q 'BIND_NOW'
readelf -sW "$user/paperweight_vm" | grep -q '__stack_chk_fail'
readelf -lW "$user/paperweight_vm" | \
    grep -q 'Requesting program interpreter: /lib64/ld-linux-x86-64.so.2'
! readelf -dW "$user/paperweight_vm" | grep -qE 'RPATH|RUNPATH'
! readelf -nW "$user/paperweight_vm" | grep -qE 'IBT|SHSTK'
file "$user/listener" | grep -q 'statically linked'

grep -q '^FROM ubuntu:26.04@sha256:7b202b0e2e0028c6250f5fcf41d04df492d145a1654c6995a6553f0c1f6f1960$' \
    "$user/Dockerfile"
grep -q '^USER user:user$' "$user/Dockerfile"
grep -q '^RUN groupadd --gid 2000 pwn' "$user/Dockerfile"
grep -q 'groupadd --gid 2001 user' "$user/Dockerfile"
grep -q 'chmod 4755 /opt/paperweight/paperweight_vm' "$user/Dockerfile"
grep -q 'chmod 0400 /home/pwn/flag' "$user/Dockerfile"
grep -q 'mem_limit: 128m' "$user/docker-compose.yml"
grep -q 'pids_limit: 64' "$user/docker-compose.yml"

if test "${1:-}" = '--local-exploit'; then
    result=$(cd "$organizer" && python3 ./verify_local.py "$user/flag")
    test "$result" = "$(tr -d '\n' < "$user/flag")"
fi

echo 'paperweight_vm package validation: OK'
