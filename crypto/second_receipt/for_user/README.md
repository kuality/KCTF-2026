# second_receipt (Low)

한 번만 사용할 수 있는 Ed25519 영수증 서비스입니다. 접속하면 이미 사용 처리된 `(message, public_key, signature)`가 JSON 한 줄로 제공됩니다.

서버에는 다음 JSON을 한 번 제출할 수 있습니다.

```json
{"signature":"64-byte signature in hex"}
```

같은 메시지에 대해 유효하면서 기존 서명과 byte-for-byte 다른 signature를 제출하면 flag를 받습니다.

로컬 실행:

```bash
docker compose up --build
nc 127.0.0.1 31341
```
