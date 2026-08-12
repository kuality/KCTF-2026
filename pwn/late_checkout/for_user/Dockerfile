FROM ubuntu:26.04@sha256:7b202b0e2e0028c6250f5fcf41d04df492d145a1654c6995a6553f0c1f6f1960

RUN groupadd --gid 2001 user \
    && useradd --uid 2001 --gid 2001 --create-home \
        --home-dir /home/user --shell /usr/sbin/nologin user \
    && groupadd --gid 2000 pwn \
    && useradd --uid 2000 --gid 2000 --create-home \
        --home-dir /home/pwn --shell /usr/sbin/nologin pwn

COPY --chown=pwn:pwn ./late_checkout /home/pwn/late_checkout
COPY --chown=pwn:pwn ./flag /home/pwn/flag
COPY --chown=root:root ./tcp_listener /usr/local/bin/tcp_listener

RUN chown root:root /home/pwn \
    && chmod 0555 /home/pwn \
    && chmod 4555 /home/pwn/late_checkout \
    && chmod 0400 /home/pwn/flag \
    && chmod 0555 /usr/local/bin/tcp_listener \
    && chown user:user /home/user \
    && chmod 0750 /home/user

WORKDIR /home/user
USER user:user

EXPOSE 8080

CMD ["/usr/local/bin/tcp_listener"]
