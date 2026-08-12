#!/bin/sh
set -eu

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
challenge=$(CDPATH= cd -- "$here/.." && pwd)
user="$challenge/for_user"
organizer="$challenge/for_organizer"

test -x "$user/inkspill"
test -x "$organizer/inkspill"
test -x "$user/listener"
test -x "$organizer/listener"
test "$(sha256sum "$user/inkspill" | awk '{print $1}')" = \
     "$(sha256sum "$organizer/inkspill" | awk '{print $1}')"
test "$(sha256sum "$user/listener" | awk '{print $1}')" = \
     "$(sha256sum "$organizer/listener" | awk '{print $1}')"
test "$(sha256sum "$user/libc.so.6" | awk '{print $1}')" = \
     "$(sha256sum "$organizer/libc.so.6" | awk '{print $1}')"
test "$(sha256sum "$user/ld-linux-x86-64.so.2" | awk '{print $1}')" = \
     "$(sha256sum "$organizer/ld-linux-x86-64.so.2" | awk '{print $1}')"
test "$(sha256sum "$user/libc.so.6" | awk '{print $1}')" = \
     'd763925433ff9b757390549e1b20c085f5e6de27ae700fe89194178d96a8a2b0'
test "$(sha256sum "$user/ld-linux-x86-64.so.2" | awk '{print $1}')" = \
     '223b94a42758f2434da331cc0aa62db1af5b456481762c5caceefa1a2d1eb8fb'
grep -Fxq 'kctf{flag}' "$user/flag"
grep -Eq '^KCTF\{[0-9a-f]{64}\}$' "$organizer/flag"
test "$(wc -l < "$user/flag")" -eq 1
test "$(wc -l < "$organizer/flag")" -eq 1
! cmp -s "$user/flag" "$organizer/flag"
test "$(tr -d '\n' < "$user/flag")" = 'kctf{flag}'
cmp -s "$user/Dockerfile" "$organizer/Dockerfile"
cmp -s "$user/docker-compose.yml" "$organizer/docker-compose.yml"

readelf -hW "$user/inkspill" | grep -Eq 'Type:[[:space:]]+EXEC'
readelf -lW "$user/inkspill" | grep -Eq 'GNU_STACK[[:space:]].*RW[[:space:]]'
readelf -lW "$user/inkspill" | grep -Eq 'GNU_RELRO'
readelf -dW "$user/inkspill" | grep -Eq 'BIND_NOW'
readelf -sW "$user/inkspill" | grep -Eq '__stack_chk_fail'
readelf -SW "$user/inkspill" | grep -Eq '\.approval[[:space:]]+PROGBITS[[:space:]]+0000000000405000'
! readelf -nW "$user/inkspill" | grep -Eq 'IBT|SHSTK'
file "$user/listener" | grep -Eq 'statically linked'

grep -Fxq 'FROM ubuntu:26.04@sha256:7b202b0e2e0028c6250f5fcf41d04df492d145a1654c6995a6553f0c1f6f1960' \
    "$user/Dockerfile"
! grep -Eq 'apt-get|socat' "$user/Dockerfile"
grep -Fq 'groupadd --gid 2000 pwn' "$user/Dockerfile"
grep -Fq 'useradd --uid 2000 --gid 2000' "$user/Dockerfile"
grep -Fq 'groupadd --gid 2001 user' "$user/Dockerfile"
grep -Fq 'useradd --uid 2001 --gid 2001' "$user/Dockerfile"
grep -Fq 'user: "2001:2001"' "$user/docker-compose.yml"
grep -Eq '^#define USER_UID 2001$' "$challenge/src/inkspill.c"
grep -Eq '^#define PWN_UID 2000$' "$challenge/src/inkspill.c"
grep -Eq '^#define USER_UID 2001$' "$challenge/src/listener.c"

test ! -e "$user/solve.py"
test ! -e "$user/WRITEUP.md"
test ! -e "$user/inkspill.c"
! rg -n --hidden --glob '!flag' \
    'for_organizer|solve\.py|APPROVAL_MAGIC|KCTF\{[0-9a-f]{64}\}' \
    "$user"
! rg -F --hidden --glob '!flag' "$(tr -d '\n' < "$organizer/flag")" "$user"

echo "static validation: PASS"
