#!/bin/sh
set -eu

pwn_root=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
challenges='late_checkout inkspill secondhand rle_gallery paperweight_vm'
flag_pattern='^KCTF\{[0-9a-f]{64}\}$'

command -v openssl >/dev/null
command -v sha256sum >/dev/null

for challenge in $challenges; do
    challenge_root="$pwn_root/$challenge"
    user_flag="$challenge_root/for_user/flag"
    organizer_flag="$challenge_root/for_organizer/flag"
    generator="$challenge_root/src/generate_flags.sh"

    test -x "$generator"
    if [ ! -e "$organizer_flag" ]; then
        "$generator" >/dev/null
        printf '%s\n' "$challenge: generated organizer flag"
    else
        printf '%s\n' "$challenge: kept existing organizer flag"
    fi

    grep -Fxq 'kctf{flag}' "$user_flag"
    grep -Eq "$flag_pattern" "$organizer_flag"
    test "$(wc -l < "$user_flag")" -eq 1
    test "$(wc -l < "$organizer_flag")" -eq 1
    ! cmp -s "$user_flag" "$organizer_flag"
    chmod 0600 "$organizer_flag"
done

duplicate_count=$(
    for challenge in $challenges; do
        sha256sum "$pwn_root/$challenge/for_organizer/flag"
    done |
        awk '{print $1}' |
        sort |
        uniq -d |
        wc -l
)
test "$duplicate_count" -eq 0

echo 'all organizer flags are present, private, format-valid, and distinct'
