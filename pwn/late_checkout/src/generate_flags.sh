#!/bin/sh
set -eu

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
user_flag="$root_dir/for_user/flag"
organizer_flag="$root_dir/for_organizer/flag"

if [ -e "$user_flag" ]; then
    grep -Fxq 'kctf{flag}' "$user_flag"
else
    printf 'kctf{flag}\n' >"$user_flag"
    chmod 0644 "$user_flag"
fi

if [ -e "$organizer_flag" ]; then
    echo "refusing to replace the existing organizer flag" >&2
    exit 1
fi

organizer_digest=$(openssl rand 32 | sha256sum | awk '{print $1}')

umask 077
printf 'KCTF{%s}\n' "$organizer_digest" >"$organizer_flag"
chmod 0600 "$organizer_flag"

flag_pattern='^KCTF\{[0-9a-f]{64}\}$'
grep -Fxq 'kctf{flag}' "$user_flag"
grep -Eq "$flag_pattern" "$organizer_flag"
if cmp -s "$user_flag" "$organizer_flag"; then
    echo "generated flags unexpectedly match" >&2
    exit 1
fi

unset organizer_digest
echo "generated two distinct, format-valid flags without displaying them"
