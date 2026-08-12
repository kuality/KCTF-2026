# Design: common_ground

- 난이도: Low
- 형태: 오프라인 산출물형
- primitive: textbook RSA
- 의도 취약점: 같은 modulus와 같은 message를 서로소 exponent 두 개에 재사용

공개식은 `c1=m^e1 mod n`, `c2=m^e2 mod n`이다. `gcd(e1,e2)=1`이므로 Bézout 계수 `a,b`에 대해 `a*e1+b*e2=1`이고, `m=c1^a*c2^b mod n`이다. 음수 지수는 modular inverse로 처리한다.

2048-bit modulus와 70바이트 flag를 사용한다. generator는 `gcd(m,n)=1`, exponent coprimality, 정확한 재암호화를 검사한다. factor leakage, 작은 `n`, integer root는 의도한 경로가 아니다.

고친 설계는 수신자별 독립 modulus와 RSA-OAEP를 사용한다. 그 경우 같은 결합식은 성립하지 않는다.
