# Toolchain

- Target: `linux/amd64`
- OCaml: `5.5.0`, native `ocamlopt`
- C compiler: GCC 13.3.0
- Linker/strip: GNU binutils 2.42
- Build image: `ocaml/opam:ubuntu-24.04-ocaml-5.5`
- Pinned amd64 manifest: `sha256:ffb34a58dda4d6620e82b7dc48427d49819b85bc88191329907185af43314bbc`
- Link mode: static non-PIE ELF, RELRO, NX, no GNU build-id, no exported executable symbols
- Release stripping: `strip --strip-all`, followed by a fixed-length scrub of challenge source/frame names

`build.sh` assumes only Docker on the host. The compiler and linker run inside the pinned image with networking disabled. Compilation is deliberately single-job. Static linking keeps the participant binary independent of the host glibc version; the unused glibc `dlopen` link warning comes from OCaml's runtime archive and is expected.
