#!/bin/sh
set -eu

binary=${1:-./late_checkout}
constants=${2:-./solve_constants.py}

test -x "$binary"
test -f "$constants"

# ET_EXEC means no PIE.
readelf -hW "$binary" | grep -Eq 'Type:[[:space:]]+EXEC'

# GNU_STACK must exist and must not be executable.
stack_line=$(readelf -lW "$binary" | grep 'GNU_STACK')
printf '%s\n' "$stack_line" | grep -q ' RW '
if printf '%s\n' "$stack_line" | grep -q 'RWE'; then
    echo "executable stack detected" >&2
    exit 1
fi

# Full RELRO requires both a GNU_RELRO segment and eager binding.
readelf -lW "$binary" | grep -q 'GNU_RELRO'
readelf -dW "$binary" | grep -q 'BIND_NOW'

# No stack canary. Use the dynamic table because the final binary is stripped.
if nm -D -u "$binary" | grep -q '__stack_chk_fail'; then
    echo "stack canary detected" >&2
    exit 1
fi

# Final release artifacts must have no ordinary symbol table.
if readelf -SW "$binary" | grep -q '\.symtab'; then
    echo "ordinary symbol table remains; binary is not fully stripped" >&2
    exit 1
fi

# Fixed-address regression checks for the stripped ret gadget, win prologue,
# and alignment gate. The values were recorded before stripping.
ret_address=$(sed -n 's/^ALIGNMENT_RET = 0x//p' "$constants")
win_address=$(sed -n 's/^PRINT_RECEIPT_SECRET = 0x//p' "$constants")
gate_address=$(sed -n 's/^ALIGNMENT_GATE = 0x//p' "$constants")
case "$ret_address:$win_address:$gate_address" in
    *[!0-9a-f:]* | :: | :*)
        echo "invalid solver constants" >&2
        exit 1
        ;;
esac

disassembly=$(objdump -d -M intel "$binary")
printf '%s\n' "$disassembly" | grep -Eq "^[[:space:]]*$ret_address:[[:space:]]+c3[[:space:]]+ret$"
printf '%s\n' "$disassembly" | grep -Eq "^[[:space:]]*$win_address:[[:space:]]+55[[:space:]]+push[[:space:]]+rbp$"
printf '%s\n' "$disassembly" | grep -Eq "^[[:space:]]*$gate_address:[[:space:]]+0f 28 04 24[[:space:]]+movaps[[:space:]]+xmm0,XMMWORD PTR \\[rsp\\]$"

echo "binary mitigation, stripping, and fixed-address profile is correct"
