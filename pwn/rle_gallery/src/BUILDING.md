# rle_gallery build

The release artifacts must be produced by `Dockerfile.build`, which uses the
same pinned Ubuntu 26.04 amd64 image as the runtime packages. Do not package a
host-built binary.

```sh
docker build --file Dockerfile.build --target export \
  --tag rle-gallery-builder:26.04 .
builder_container="$(docker create rle-gallery-builder:26.04)"
mkdir -p build-26
docker cp "$builder_container:/rle_gallery" build-26/rle_gallery
docker cp "$builder_container:/rle_gallery.debug" build-26/rle_gallery.debug
docker cp "$builder_container:/listener" build-26/listener
docker cp "$builder_container:/toolchain.txt" build-26/toolchain.txt
docker rm "$builder_container"
```

`build-26/toolchain.txt` records the exact GCC and binutils versions used by
that build. Copy `rle_gallery` and `listener` from this single export into both
release packages, then verify their SHA-256 hashes match byte-for-byte.
The builder pins GCC `4:15.2.0-5ubuntu1`, GCC 15
`15.2.0-16ubuntu1`, binutils `2.46-3ubuntu2`, make `4.4.1-3`, and
`libc6-dev` `2.43-2ubuntu2`.

The accepted GCC 15 export hashes are:

```text
rle_gallery  84e75773723f05a3629c2d657d68ba6f543ea5c33d79933f62643c8ce054759a
listener     e51b49a62962f10bca8984a9dd19dddcd5f513167f492cfed21b43ef6c934fb7
```

For a quick host-only development build (never package this output):

```sh
make -j1 clean all verify
```

The Makefile fixes PIE, NX, stack canary, frame pointers, and Full RELRO.
`rle_gallery` is stripped for release; `rle_gallery.debug` is only a temporary
organizer-side symbol/reference artifact used to record final offsets.
`listener` is a static, unprivileged TCP launcher so the runtime image needs no
network package install.

The packaged common Ubuntu 26.04 `libc.so.6` (glibc `2.43-2ubuntu2`) and
matching loader are copied byte-for-byte into both release packages. Their
hashes are recorded in the organizer validation notes. The final exported
binary must also be tested through that supplied loader/libc pair.
