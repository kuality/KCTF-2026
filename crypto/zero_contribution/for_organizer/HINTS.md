# Hints

1. X25519이 모든 32바이트 입력에서 상대방의 private scalar에 의존하는 출력을 만드는 것은 아니다.
2. RFC 7748의 all-zero output과 low-order input 설명을 확인하라.
3. `client_public=00...00`, `shared=00...00`을 KDF에 그대로 대입하라.
