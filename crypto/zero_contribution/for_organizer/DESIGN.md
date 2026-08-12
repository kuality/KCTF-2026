# Design: zero_contribution

- 난이도: Low
- 형태: TCP 서비스형
- primitive: X25519, HKDF-SHA256, AES-128-GCM
- 의도 취약점: X25519 output이 all-zero인지 KDF 전에 검사하지 않음

canonical `u=0`은 어떤 clamped server scalar와 곱해도 all-zero output을 만든다. salt, 양쪽 public input, info, nonce, AAD가 모두 공개되므로 참가자는 shared secret을 0으로 두고 동일한 key를 계산할 수 있다.

X25519은 RFC 7748 vector, AES-GCM은 NIST SP 800-38D vector와 외부 구현으로 검증한다. fixed mode는 shared bytes를 KDF 전에 검사해 0이면 거부한다.
