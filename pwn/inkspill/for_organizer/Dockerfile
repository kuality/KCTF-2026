FROM ubuntu:26.04@sha256:7b202b0e2e0028c6250f5fcf41d04df492d145a1654c6995a6553f0c1f6f1960

RUN groupadd --gid 2000 pwn \
    && useradd --uid 2000 --gid 2000 --home-dir /home/pwn \
       --create-home --shell /usr/sbin/nologin pwn \
    && groupadd --gid 2001 user \
    && useradd --uid 2001 --gid 2001 --home-dir /home/user \
       --create-home --shell /usr/sbin/nologin user \
    && test "$(id -u pwn):$(id -g pwn)" = '2000:2000' \
    && test "$(id -u user):$(id -g user)" = '2001:2001'

COPY --chown=pwn:pwn flag /home/pwn/flag
COPY --chown=pwn:pwn inkspill /home/user/inkspill
COPY --chown=root:root listener /usr/local/bin/inkspill-listener
RUN chmod 0500 /home/pwn \
    && chmod 0400 /home/pwn/flag \
    && chown root:user /home/user \
    && chmod 0555 /home/user \
    && chmod 4555 /home/user/inkspill \
    && chmod 0555 /usr/local/bin/inkspill-listener \
    && test "$(stat -c '%U:%G:%a' /home/pwn/flag)" = 'pwn:pwn:400' \
    && test "$(stat -c '%U:%G:%a' /home/user/inkspill)" = 'pwn:pwn:4555'

WORKDIR /home/user
USER user:user
EXPOSE 1337
CMD ["/usr/local/bin/inkspill-listener"]
