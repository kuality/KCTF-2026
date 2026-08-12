# Reproducible build

The release binary must be built from the pinned Ubuntu 26.04 image in
`Dockerfile.build`, against glibc 2.43.  The build produces the challenge and a
static TCP listener. GCC 15.2.0, binutils 2.46, Make 4.4.1, and the glibc 2.43
development package revisions are pinned explicitly in that recipe.

Host build (only on the matching toolchain):

```sh
make -j1 clean all
./verify_binary.sh ./late_checkout
make -j1 package
./verify.sh
```

Pinned builder invocation:

```sh
docker build --pull=false -f Dockerfile.build -t late-checkout-build .
id="$(docker create late-checkout-build)"
docker cp "$id:/build/late_checkout" ./late_checkout
docker cp "$id:/build/tcp_listener" ./tcp_listener
docker cp "$id:/build/solve_constants.py" ./solve_constants.py
docker rm "$id"
./verify_binary.sh ./late_checkout
make -j1 package
./verify.sh
```

`SOURCE_DATE_EPOCH`, locale, optimization level, mitigations, and linker build
ID behavior are fixed in the Makefile. Both packages must receive these same
fully stripped artifacts plus the byte-identical common 26.04 libc and loader;
never compile or strip the packages separately. The setuid challenge retains
the normal system `PT_INTERP`; the packaged libc/loader are analysis copies.
`solve_constants.py` is recorded from the unstripped intermediate before its
symbol table is removed and is shipped only to the organizer.
