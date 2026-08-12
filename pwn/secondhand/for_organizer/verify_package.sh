#!/bin/sh
set -eu

root="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
user_dir="$root/for_user"
organizer_dir="$root/for_organizer"
with_exploit="${1:-}"

free -h

for package in "$user_dir" "$organizer_dir"; do
    for file in flag secondhand tcp_runner libc.so.6 ld-linux-x86-64.so.2 \
        Dockerfile docker-compose.yml; do
        test -f "$package/$file"
    done
    grep -Fq 'FROM ubuntu:26.04@sha256:7b202b0e2e0028c6250f5fcf41d04df492d145a1654c6995a6553f0c1f6f1960' \
        "$package/Dockerfile"
    grep -Fq 'USER user:user' "$package/Dockerfile"
    grep -Fq 'groupadd --gid 2000 pwn' "$package/Dockerfile"
    grep -Fq 'useradd --no-log-init --uid 2000 --gid pwn' "$package/Dockerfile"
    grep -Fq 'groupadd --gid 2001 user' "$package/Dockerfile"
    grep -Fq 'useradd --no-log-init --uid 2001 --gid user' "$package/Dockerfile"
    grep -Fq 'chmod 0400 /home/pwn/flag' "$package/Dockerfile"
    grep -Fq 'chmod 4555 /home/user/secondhand' "$package/Dockerfile"
    if grep -Eq 'apt(-get)?[[:space:]]' "$package/Dockerfile"; then
        echo "runtime Dockerfile unexpectedly installs packages" >&2
        exit 1
    fi
done

test -f "$organizer_dir/solve.py"
test -f "$organizer_dir/verify_local.py"

fake_flag="$(sed -n '1p' "$user_dir/flag")"
organizer_flag="$(sed -n '1p' "$organizer_dir/flag")"
test "$fake_flag" = 'kctf{flag}'
grep -Eq '^KCTF\{[0-9a-f]{64}\}$' "$organizer_dir/flag"
test "$fake_flag" != "$organizer_flag"

if rg -a -l -F -- "$organizer_flag" "$user_dir" "$root/src" "$root/README.md" \
    >/dev/null; then
    echo "organizer flag leaked outside organizer-only material" >&2
    exit 1
fi

for forbidden in solve.py WRITEUP.md secondhand.c tcp_runner.c secondhand.debug; do
    if find "$user_dir" -type f -name "$forbidden" | grep -q .; then
        echo "private artifact leaked into participant package: $forbidden" >&2
        exit 1
    fi
done

cmp -s "$user_dir/secondhand" "$organizer_dir/secondhand"
cmp -s "$user_dir/tcp_runner" "$organizer_dir/tcp_runner"
cmp -s "$user_dir/libc.so.6" "$organizer_dir/libc.so.6"
cmp -s "$user_dir/ld-linux-x86-64.so.2" \
    "$organizer_dir/ld-linux-x86-64.so.2"
cmp -s "$user_dir/Dockerfile" "$organizer_dir/Dockerfile"
cmp -s "$user_dir/docker-compose.yml" "$organizer_dir/docker-compose.yml"

test "$(sha256sum "$user_dir/libc.so.6" | awk '{print $1}')" = \
    d763925433ff9b757390549e1b20c085f5e6de27ae700fe89194178d96a8a2b0
test "$(sha256sum "$user_dir/ld-linux-x86-64.so.2" | awk '{print $1}')" = \
    223b94a42758f2434da331cc0aa62db1af5b456481762c5caceefa1a2d1eb8fb
strings "$user_dir/libc.so.6" | grep -Fqm1 \
    'GNU C Library (Ubuntu GLIBC 2.43-2ubuntu2) stable release version 2.43.'

"$root/src/verify_build.sh" "$user_dir/secondhand" \
    "$organizer_dir/secondhand.debug"

if [ -f "$user_dir/SHA256SUMS" ]; then
    (cd "$user_dir" && sha256sum -c SHA256SUMS >/dev/null)
fi
if [ -f "$organizer_dir/SHA256SUMS" ]; then
    (cd "$organizer_dir" && sha256sum -c SHA256SUMS >/dev/null)
fi

if [ "$with_exploit" = "--with-exploit" ]; then
    replay_dir="$(mktemp -d)"
    trap 'rm -rf "$replay_dir"' EXIT HUP INT TERM
    iteration=1
    while [ "$iteration" -le 3 ]; do
        python3 "$organizer_dir/verify_local.py" "$user_dir" \
            >"$replay_dir/output" 2>&1
        grep -Fq "$fake_flag" "$replay_dir/output"
        iteration=$((iteration + 1))
    done
    rm -rf "$replay_dir"
    trap - EXIT HUP INT TERM
fi

free -h
echo "secondhand package verification passed${with_exploit:+ ($with_exploit)}"
