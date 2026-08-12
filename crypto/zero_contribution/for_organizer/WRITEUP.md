# Writeup: zero_contribution

X25519의 Montgomery curve에는 cofactor가 있으며 작은 차수 입력은 상대 private scalar의 기여를 제거할 수 있다. `u=0`을 사용하면 출력은 32바이트 zero다.

서버는 이 값을 거부하지 않고 다음 KDF에 넣는다.

```text
key = HKDF-SHA256(
    00...00,
    salt,
    "KCTF-zero-contribution-v1" || server_public || 00...00,
    16,
)
```

나머지 nonce와 AAD도 greeting에 있으므로 AES-GCM ciphertext를 인증하며 복호화할 수 있다.

```bash
python3 solve.py HOST PORT
```

fixed implementation은 RFC 7748에서 설명하는 것처럼 all-zero output을 KDF 전에 검사하고 세션을 중단한다.
