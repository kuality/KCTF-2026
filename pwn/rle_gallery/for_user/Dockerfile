FROM ubuntu:26.04@sha256:7b202b0e2e0028c6250f5fcf41d04df492d145a1654c6995a6553f0c1f6f1960

RUN groupadd --gid 2000 pwn \
    && useradd --uid 2000 --gid pwn --create-home \
       --shell /usr/sbin/nologin pwn \
    && groupadd --gid 2001 user \
    && useradd --uid 2001 --gid user --create-home --shell /bin/sh user \
    && install -d -o root -g root -m 0755 /opt/rle_gallery

COPY listener /opt/rle_gallery/listener
COPY rle_gallery /home/pwn/rle_gallery
COPY flag /home/pwn/flag

RUN chown root:root /opt/rle_gallery/listener \
    && chmod 0555 /opt/rle_gallery/listener \
    && chown pwn:pwn /home/pwn/rle_gallery /home/pwn/flag \
    && chmod 4755 /home/pwn/rle_gallery \
    && chmod 0400 /home/pwn/flag \
    && chmod 0755 /home/pwn /home/user

ENV HOME=/home/user \
    PATH=/usr/bin:/bin \
    LANG=C
WORKDIR /home/user
USER user:user

EXPOSE 31337
ENTRYPOINT ["/opt/rle_gallery/listener", "31337", "/home/pwn/rle_gallery"]
