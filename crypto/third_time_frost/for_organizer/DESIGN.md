# Design: third_time_frost

- 난이도: High
- 형태: TCP 서비스형
- primitive: RFC 9591 FROST(ristretto255, SHA-512), 2-of-2 Shamir sharing
- 의도 취약점: 같은 hiding/binding nonce ticket을 서로 다른 message 세 개에 재사용

participant 2의 share 식은 `z_j=d+rho_j*e+lambda_2*c_j*s_2 mod L`이다. 동일 ticket에서 `(d,e,s_2)`가 고정되고 message마다 `rho_j,c_j`가 달라진다. 세 transcript는 세 미지수에 대한 3x3 선형 시스템을 만든다.

참가자는 정상적으로 자신의 `s_1`을 소유한다. 복구한 `s_2`와 Lagrange coefficients로 `s=lambda_1*s_1+lambda_2*s_2`를 계산하고 target Schnorr signature를 만든다.

Ristretto element와 scalar는 canonical하게 검증하고 identity를 거부한다. 각 반환 share는 공개 share key로 검증 가능하다. fixed mode는 message가 아니라 ticket 자체를 첫 sign에서 원자적으로 consume한다.
