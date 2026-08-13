# zero_contribution (Low)

서버는 참가자가 제출한 32바이트 X25519 public input으로 shared secret을 계산하고, 공개된 HKDF context로 AES-128-GCM key를 만들어 flag를 암호화합니다.

첫 JSON 줄에는 `server_public`, `salt`, `nonce`, `aad`가 들어 있습니다. 다음 형식으로 public input을 한 번 보낼 수 있습니다.

```json
{"client_public":"32-byte little-endian u-coordinate in hex"}
```

KDF는 다음과 같습니다.

```text
HKDF-SHA256(shared, salt, "KCTF-zero-contribution-v1" || server_public || client_public, 16)
```

로컬 실행:

```bash
docker compose up --build
nc 127.0.0.1 30002
```
