#!/bin/sh
set -eu

challenge_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
user_flag="$challenge_root/for_user/flag"
organizer_flag="$challenge_root/for_organizer/flag"

if [ -e "$user_flag" ]; then
    grep -Fxq 'kctf{flag}' "$user_flag"
else
    printf 'kctf{flag}\n' > "$user_flag"
    chmod 0644 "$user_flag"
fi

if [ -e "$organizer_flag" ]; then
    echo "refusing to replace the existing organizer flag" >&2
    exit 1
fi

organizer_digest=$(openssl rand 32 | sha256sum | awk '{print $1}')
umask 077
printf 'KCTF{%s}\n' "$organizer_digest" > "$organizer_flag"
chmod 0600 "$organizer_flag"

grep -Eq '^KCTF\{[0-9a-f]{64}\}$' "$organizer_flag"
grep -Fxq 'kctf{flag}' "$user_flag"
! cmp -s "$user_flag" "$organizer_flag"
echo "generated a distinct, format-valid organizer flag without displaying it"
