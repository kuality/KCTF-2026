#!/bin/sh
set -eu
export PYTHONDONTWRITEBYTECODE=1

challenge_dir="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
python3 "$challenge_dir/src/tests/test_properties.py"
result="$(python3 "$challenge_dir/for_organizer/solve.py" "$challenge_dir/for_user")"
expected="$(tr -d '\n' < "$challenge_dir/for_organizer/flag")"
test "$result" = "$expected"
python3 - "$challenge_dir/for_user/instance.json" <<'PY'
import json
import sys
from pathlib import Path

data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
required = {"challenge", "encoding", "flag_length", "n", "e1", "e2", "c1", "c2"}
assert set(data) == required
assert data["challenge"] == "common_ground"
print("PASS common_ground package and official solve")
PY
