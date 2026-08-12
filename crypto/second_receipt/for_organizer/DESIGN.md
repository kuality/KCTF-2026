# Design: second_receipt

- 난이도: Low
- 형태: TCP 서비스형
- primitive: Ed25519
- 의도 취약점: verifier가 scalar `S`의 canonical range `0 <= S < L`을 검사하지 않음

서버는 원본 signature bytes를 replay cache에 넣는다. verifier는 point와 길이는 엄격히 검사하지만 vulnerable mode에서 `S < L`만 생략한다. 따라서 `S'=S+L`은 다른 byte string인 동시에 같은 group equation을 만족한다.

정상 서명, 다른 message, malformed point, 잘못된 길이, `S+L`의 strict rejection을 테스트한다. fixed mode는 equation 전에 `S>=L`을 거부한다.
