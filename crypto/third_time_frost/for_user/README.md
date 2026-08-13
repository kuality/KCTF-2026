# third_time_frost (High)

이 서비스는 2-of-2 `FROST(ristretto255, SHA-512)` signer입니다. 참가자는 participant 1의 정상 share를 받고, 서버는 participant 2의 share를 보관합니다.

JSON-lines protocol은 다음 세 연산을 제공합니다.

- `commit`: 참가자의 hiding/binding commitment를 제출하고 server commitment ticket을 받습니다.
- `sign`: ticket과 허용된 message를 보내 server signature share를 받습니다.
- `verify`: `release_flag`에 대한 최종 Ristretto Schnorr signature `(R,z)`를 제출합니다.

첫 greeting에는 participant identifiers, participant 1 share/public key, server public share, group public key, 허용 message 세 개와 target message가 들어 있습니다. 자세한 transcript 구성은 함께 제공된 `frost.py`를 기준으로 합니다.

로컬 실행:

```bash
docker compose up --build
nc 127.0.0.1 30003
```
