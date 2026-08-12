FROM ubuntu:26.04@sha256:7b202b0e2e0028c6250f5fcf41d04df492d145a1654c6995a6553f0c1f6f1960

RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 2001 ctf \
    && useradd --uid 2001 --gid 2001 --no-create-home --shell /usr/sbin/nologin ctf

WORKDIR /app
COPY server.py aes_gcm.py x25519_ref.py ./

USER 2001:2001
EXPOSE 5000
CMD ["python3", "-u", "server.py", "0.0.0.0", "5000", "/run/secrets/challenge_flag"]
