#!/bin/sh
set -eu
export PYTHONDONTWRITEBYTECODE=1

challenge_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
python3 "$challenge_dir/src/tests/test_frost.py"
python3 "$challenge_dir/src/tests/integration.py"
test "$(cat "$challenge_dir/for_user/flag")" = 'kctf{flag}'
grep -Eq '^KCTF\{[0-9a-f]{64}\}$' "$challenge_dir/for_organizer/flag"
for file in server.py frost.py ristretto.py; do
    cmp "$challenge_dir/for_user/$file" "$challenge_dir/for_organizer/$file"
done
echo 'PASS third_time_frost package parity'
