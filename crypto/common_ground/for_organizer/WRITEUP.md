# Writeup: common_ground

## 공개 입력

`instance.json`은 같은 modulus `n` 아래의 두 ciphertext를 제공한다.

```text
c1 = m^e1 mod n
c2 = m^e2 mod n
```

## 깨진 불변식

RSA modulus를 공유한 상태에서 같은 평문을 서로소 exponent로 암호화하면 두 지수의 선형 결합으로 평문 지수 1을 만들 수 있다.

## 복구

확장 유클리드 알고리즘으로 `a*e1+b*e2=1`을 구한다. 그러면 다음이 성립한다.

```text
c1^a * c2^b = m^(a*e1+b*e2) = m mod n
```

`a` 또는 `b`가 음수면 해당 ciphertext의 modular inverse를 먼저 구한다. 복구한 정수를 `flag_length` 바이트 big-endian으로 변환한다.

```bash
python3 solve.py ../for_user
```

solver는 복구한 `m`을 두 exponent로 다시 암호화해 `c1,c2`와 같은지 assertion으로 확인한다.

## 수정안

각 수신자에 독립 modulus를 사용하고 RSA-OAEP로 randomized padding하면 위 지수 결합이 같은 `m`에 적용되지 않는다.
