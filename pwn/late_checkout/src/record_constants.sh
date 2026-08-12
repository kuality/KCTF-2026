#!/bin/sh
set -eu

binary=${1:?usage: record_constants.sh BINARY OUTPUT}
output=${2:?usage: record_constants.sh BINARY OUTPUT}

win_address=$(nm -n "$binary" | awk '$3 == "print_receipt_secret" {
    sub(/^0+/, "", $1);
    print "0x" $1;
    exit;
}')
ret_address=$(objdump -d -M intel "$binary" | awk '$2 == "c3" && $3 == "ret" {
    sub(":", "", $1);
    print "0x" $1;
    exit;
}')
gate_address=$(objdump -d -M intel "$binary" | awk '/movaps[[:space:]]+xmm0,XMMWORD PTR \[rsp\]/ {
    sub(":", "", $1);
    print "0x" $1;
    exit;
}')

if [ -z "$win_address" ] || [ -z "$ret_address" ] ||
    [ -z "$gate_address" ]; then
    echo "failed to recover fixed solver constants" >&2
    exit 1
fi

temporary="$output.tmp"
{
    echo '# Auto-generated from the unstripped deterministic build.'
    echo 'OFFSET = 72'
    printf 'ALIGNMENT_RET = %s\n' "$ret_address"
    printf 'PRINT_RECEIPT_SECRET = %s\n' "$win_address"
    printf 'ALIGNMENT_GATE = %s\n' "$gate_address"
} >"$temporary"
mv "$temporary" "$output"

echo "recorded stripped-binary solver constants without retaining symbols"
