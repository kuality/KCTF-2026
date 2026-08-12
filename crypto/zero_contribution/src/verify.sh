#!/bin/sh
set -eu
export PYTHONDONTWRITEBYTECODE=1

challenge_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
python3 "$challenge_dir/src/tests/test_crypto.py"
python3 "$challenge_dir/src/tests/integration.py"
test "$(cat "$challenge_dir/for_user/flag")" = 'kctf{flag}'
grep -Eq '^KCTF\{[0-9a-f]{64}\}$' "$challenge_dir/for_organizer/flag"
for file in server.py aes_gcm.py x25519_ref.py; do
    cmp "$challenge_dir/for_user/$file" "$challenge_dir/for_organizer/$file"
done
echo 'PASS zero_contribution package parity'
