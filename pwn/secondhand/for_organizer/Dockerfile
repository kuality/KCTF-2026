FROM ubuntu:26.04@sha256:7b202b0e2e0028c6250f5fcf41d04df492d145a1654c6995a6553f0c1f6f1960

RUN groupadd --gid 2000 pwn \
    && useradd --no-log-init --uid 2000 --gid pwn --home-dir /home/pwn --create-home --shell /usr/sbin/nologin pwn \
    && groupadd --gid 2001 user \
    && useradd --no-log-init --uid 2001 --gid user --home-dir /home/user --create-home --shell /usr/sbin/nologin user

COPY secondhand tcp_runner libc.so.6 ld-linux-x86-64.so.2 /home/user/
COPY flag /home/pwn/flag

RUN chown root:root /home/user \
    && chmod 0555 /home/user \
    && chown pwn:pwn /home/pwn /home/pwn/flag /home/user/secondhand \
    && chmod 0500 /home/pwn \
    && chmod 0400 /home/pwn/flag \
    && chmod 4555 /home/user/secondhand \
    && chown root:root /home/user/tcp_runner /home/user/libc.so.6 /home/user/ld-linux-x86-64.so.2 \
    && chmod 0555 /home/user/tcp_runner /home/user/ld-linux-x86-64.so.2 \
    && chmod 0444 /home/user/libc.so.6

WORKDIR /home/user
USER user:user
EXPOSE 1337
ENTRYPOINT ["/home/user/tcp_runner"]
