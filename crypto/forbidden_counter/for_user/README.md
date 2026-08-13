# forbidden_counter (Mid)

AES-128-GCM token worker가 재시작될 때마다 96-bit nonce counter를 0으로 초기화합니다. 접속하면 알려진 16바이트 plaintext 두 개와 해당 `(nonce,ciphertext,tag)`, 고정 AAD, 목표 plaintext가 JSON으로 제공됩니다.

다음 형식으로 목표 token을 한 번 제출할 수 있습니다.

```json
{"nonce":"...", "ciphertext":"16 bytes in hex", "tag":"16 bytes in hex"}
```

목표 plaintext는 greeting의 `target_plaintext`와 정확히 같아야 합니다.

로컬 실행:

```bash
docker compose up --build
nc 127.0.0.1 30002
```
