# inkspill build

The distributed binary is built for x86-64 Ubuntu 26.04 with GCC 15.2.0,
glibc 2.43, and binutils 2.46. The exact package revisions and base-image
digest are pinned in `Dockerfile.build`.

Host build (only on the matching toolchain):

```sh
make -j1 clean all
```

Reproducible build image:

```sh
docker build --pull=false --network=default -f Dockerfile.build -t inkspill-build .
docker create --name inkspill-build-output inkspill-build
docker cp inkspill-build-output:/build/inkspill ./inkspill
docker cp inkspill-build-output:/build/listener ./listener
docker rm inkspill-build-output
```

The Makefile fixes the compiler/linker flags, locale, timestamp input, build ID,
and stripping behavior. `listener` is statically linked, so the runtime image
does not install a network daemon. Build one job at a time.
