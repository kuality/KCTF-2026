FROM ubuntu:26.04@sha256:7b202b0e2e0028c6250f5fcf41d04df492d145a1654c6995a6553f0c1f6f1960

RUN groupadd --gid 2000 pwn \
    && useradd --uid 2000 --gid 2000 --home-dir /home/pwn \
       --create-home --no-log-init --shell /usr/sbin/nologin pwn \
    && groupadd --gid 2001 user \
    && useradd --uid 2001 --gid 2001 --home-dir /home/user \
       --create-home --no-log-init --shell /usr/sbin/nologin user \
    && install -d -o root -g root -m 0755 /opt/paperweight \
    && echo 'd763925433ff9b757390549e1b20c085f5e6de27ae700fe89194178d96a8a2b0  /lib/x86_64-linux-gnu/libc.so.6' \
       | sha256sum -c - \
    && echo '223b94a42758f2434da331cc0aa62db1af5b456481762c5caceefa1a2d1eb8fb  /lib64/ld-linux-x86-64.so.2' \
       | sha256sum -c -

COPY paperweight_vm /opt/paperweight/paperweight_vm
COPY listener /opt/paperweight/listener
COPY flag /home/pwn/flag

RUN chown root:root /opt/paperweight/listener \
    && chmod 0555 /opt/paperweight/listener \
    && chown pwn:pwn /opt/paperweight/paperweight_vm /home/pwn/flag \
    && chmod 4755 /opt/paperweight/paperweight_vm \
    && chmod 0400 /home/pwn/flag \
    && chmod 0755 /home/pwn \
    && test "$(stat -c '%U:%G:%a' /home/pwn/flag)" = 'pwn:pwn:400' \
    && test "$(stat -c '%U:%G:%a' /opt/paperweight/paperweight_vm)" = 'pwn:pwn:4755'

USER user:user
WORKDIR /home/user
EXPOSE 8080
STOPSIGNAL SIGTERM
ENTRYPOINT ["/opt/paperweight/listener", "8080", "/opt/paperweight/paperweight_vm"]
