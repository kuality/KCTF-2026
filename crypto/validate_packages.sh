#!/bin/sh
set -eu
export PYTHONDONTWRITEBYTECODE=1

root="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
for challenge in common_ground second_receipt zero_contribution forbidden_counter third_time_frost; do
    "$root/$challenge/src/verify.sh"
done
python3 "$root/validate_packages.py"
git -C "$root/.." diff --check -- crypto
