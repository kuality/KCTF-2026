# Writeup: forbidden_counter

GCM tag는 다음 형태다.

```text
T = E_K(J0) xor GHASH_H(AAD, C)
H = E_K(0^128)
```

같은 key/nonce/AAD와 한 ciphertext block을 쓰는 두 transcript를 XOR하면 공통 항이 제거된다.

```text
T1 xor T2 = (C1 xor C2) * H^2
H^2 = (T1 xor T2) / (C1 xor C2)
```

GF(2^128)에서 inverse를 곱하고 Frobenius inverse `x -> x^(2^127)`로 square root를 구한다. 이후 `mask=T1 xor GHASH_H(AAD,C1)`을 얻는다. 알려진 `P1`으로 CTR keystream `P1 xor C1`을 구해 target ciphertext를 만들고, 복구한 `H`와 mask로 tag를 계산한다.

```bash
python3 solve.py HOST PORT
```

solver는 두 번째 sample tag를 복구한 값으로 다시 계산해 bit ordering과 `H`를 검산한다. fixed mode에서는 각 encryption이 고유 nonce를 사용하므로 차분식이 성립하지 않는다.
