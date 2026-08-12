# Writeup: second_receipt

Ed25519 signature는 `R || S`이고 정상 signer는 `0 <= S < L`인 canonical scalar를 만든다. 검증식은 다음과 같다.

```text
[S]B = R + [H(R || A || M)]A
```

취약 verifier는 32바이트 `S`를 정수로 읽지만 `S<L`을 확인하지 않는다. base point의 차수가 `L`이므로 다음이 성립한다.

```text
[S+L]B = [S]B + [L]B = [S]B
```

따라서 원본의 `R`은 유지하고 `S+L`을 little-endian 32바이트로 넣는다. signature bytes는 달라 replay cache를 통과하고, 취약 equation도 통과한다.

```bash
python3 solve.py HOST PORT
```

이 공격은 새 메시지 forgery나 private-key recovery가 아니라 signature malleability다. fixed verifier는 RFC 8032대로 equation 전에 `S>=L`을 거부한다.
