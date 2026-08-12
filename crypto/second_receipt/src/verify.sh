#!/bin/sh
set -eu
export PYTHONDONTWRITEBYTECODE=1

challenge_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
python3 "$challenge_dir/src/tests/test_ed25519.py"
python3 "$challenge_dir/src/tests/integration.py"
test "$(cat "$challenge_dir/for_user/flag")" = 'kctf{flag}'
grep -Eq '^KCTF\{[0-9a-f]{64}\}$' "$challenge_dir/for_organizer/flag"
cmp "$challenge_dir/for_user/server.py" "$challenge_dir/for_organizer/server.py"
cmp "$challenge_dir/for_user/ed25519_ref.py" "$challenge_dir/for_organizer/ed25519_ref.py"
echo 'PASS second_receipt package parity'
