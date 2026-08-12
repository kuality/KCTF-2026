#!/bin/sh
set -eu

binary="${1:-build/secondhand}"
debug_binary="${2:-build/secondhand.debug}"

test -x "$binary"
test -x "$debug_binary"
readelf -hW "$binary" | grep -Eq 'Type:[[:space:]]+DYN'
readelf -lW "$binary" | grep -Eq 'GNU_STACK.*RW[[:space:]]'
readelf -lW "$binary" | grep -q 'GNU_RELRO'
readelf -dW "$binary" | grep -q 'BIND_NOW'
readelf -sW "$binary" | grep -q '__stack_chk_fail'
readelf -lW "$binary" | grep -q '/lib64/ld-linux-x86-64.so.2'
if readelf -dW "$binary" | grep -Eq '\((RPATH|RUNPATH)\)'; then
    echo "final binary unexpectedly contains RPATH/RUNPATH" >&2
    exit 1
fi
if nm -an "$binary" 2>/dev/null | grep -Eq ' print_flag$| checkout_dispatch$'; then
    echo "final binary unexpectedly retains private symbols" >&2
    exit 1
fi
nm -an "$debug_binary" | grep -Eq ' [Tt] print_flag$'
nm -an "$debug_binary" | grep -Eq ' [Dd] checkout_dispatch$'
dispatch_address="$(nm -an "$debug_binary" | awk '$3 == "checkout_dispatch" {print $1; exit}')"
case "$dispatch_address" in
    *0) ;;
    *)
        echo "checkout_dispatch is not 16-byte aligned" >&2
        exit 1
        ;;
esac
release_build_id="$(readelf -n "$binary" | awk '/Build ID:/ {print $3; exit}')"
debug_build_id="$(readelf -n "$debug_binary" | awk '/Build ID:/ {print $3; exit}')"
test -n "$release_build_id"
test "$release_build_id" = "$debug_build_id"

echo "build verification passed: PIE, NX, canary, Full RELRO, system loader, stripped release"
