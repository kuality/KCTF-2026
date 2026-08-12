# Rebuilding paperweight_vm

The canonical release was built on x86-64 Linux with:

- GCC `15.2.0` (`Ubuntu 15.2.0-16ubuntu1`)
- GNU binutils `2.46-3ubuntu2`
- glibc runtime/development files `2.43-2ubuntu2`
- GNU Make `4.4.1-3`

Run:

```sh
make -j1 clean all verify
```

`build/paperweight_vm` and `build/listener` are the deployable artifacts. The
setuid challenge keeps the normal `/lib64/ld-linux-x86-64.so.2` interpreter and
has no RPATH/RUNPATH. In deployment it therefore uses the system loader and
libc from the exact pinned Ubuntu image. `runtime/` contains the same loader and
libc copied into both release bundles strictly as analysis/reproduction files.

Canonical Ubuntu 26.04 build hashes:

- `paperweight_vm`: `13b3bde3df0db05c6cc7249595f729d4f9796e4dad627a6956d6d7ecd28cbbce`
- `listener`: `a27266f29eece1e03bcbab330d9ad6d868007a4d2a086a15b6f135df20c21f7a`

The release build fixes PIE, NX, stack canaries, and Full RELRO explicitly in
the Makefile. `SOURCE_DATE_EPOCH` and prefix maps remove avoidable build-path and
timestamp variance. GCC/binutils patch-version drift can still change machine
code; use the versions above when regenerating the canonical binary.

Ubuntu's compiler enables Intel CET notes by default. The challenge explicitly
uses `-fcf-protection=none`, because an enforced shadow stack would make the
intended ROP solution depend on the deployment CPU/kernel rather than the pinned
userspace. This does not change PIE, NX, canary, or Full RELRO.
