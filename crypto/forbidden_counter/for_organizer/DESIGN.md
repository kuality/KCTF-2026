# Design: forbidden_counter

- 난이도: Mid
- 형태: TCP 서비스형
- primitive: AES-128-GCM
- 의도 취약점: 같은 key와 96-bit nonce를 서로 다른 plaintext에 재사용

두 sample은 같은 AAD와 정확히 한 ciphertext block을 사용한다. tag 차분에서 공통 mask, AAD, length block이 소거되어 `ΔT=ΔC*H^2`가 된다. 참가자는 GF(2^128)에서 inverse와 square root를 계산해 `H`, authentication mask, CTR keystream 순서로 복구한다.

단순 ciphertext bit flip은 tag 검증에 실패한다. NIST vector, 외부 AESGCM differential, 20개 seed를 검증한다. fixed mode는 연결 전체에서 counter를 공유해 세 nonce를 다르게 만든다.
