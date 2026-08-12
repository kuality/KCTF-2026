# Writeup: third_time_frost

## 공개 입력과 정상식

participant identifiers는 `[1,2]`이며 참가자는 `s_1`, 서버는 `s_2`를 보유한다. 서버의 FROST signature share는 다음과 같다.

```text
z_j = d + rho_j*e + lambda_2*c_j*s_2 mod L
```

`rho_j`는 group public key, message hash, commitment-list hash, participant id에 바인딩된다. `c_j`는 aggregate commitment, group public key, message에 대한 challenge다.

## nonce-ticket 재사용

취약 서버는 같은 message의 중복만 막고 ticket 전체를 소비하지 않는다. 따라서 같은 `(d,e)`가 서로 다른 세 message에서 사용된다. 공개 transcript로 다음 행렬을 만든다.

```text
[1 rho_1 lambda_2*c_1] [d  ]   [z_1]
[1 rho_2 lambda_2*c_2] [e  ] = [z_2]  mod L
[1 rho_3 lambda_2*c_3] [s_2]   [z_3]
```

Gaussian elimination으로 `d,e,s_2`를 복구한다. `dB=D_2`, `eB=E_2`, `s_2B=PK_2`를 모두 검산한다.

그 다음 `s=lambda_1*s_1+lambda_2*s_2`를 계산하고 `sB=PK`인지 확인한다. 임의 nonce `r`로 target Schnorr signature를 만든다.

```text
R = rB
c = H2(R || PK || "release_flag")
z = r + c*s mod L
```

```bash
python3 solve.py HOST PORT
```

fixed implementation은 첫 `sign`에서 ticket 자체를 consume한다. 하나의 식만으로는 `(d,e,s_2)` 세 값을 결정할 수 없다.
