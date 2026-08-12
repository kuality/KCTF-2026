# common_ground (Low)

두 발신자가 같은 RSA modulus를 공유하고 같은 비밀 메시지를 서로 다른 public exponent로 암호화했습니다.

`instance.json`에는 `n`, `(e1,c1)`, `(e2,c2)`, 평문의 정확한 바이트 길이가 들어 있습니다. 평문은 표시된 길이의 big-endian 정수이며 PKCS#1 padding은 사용하지 않았습니다.

목표는 원래 `KCTF{...}` 메시지를 복구하는 것입니다.

필요한 도구는 Python 3.11 이상의 표준 라이브러리뿐입니다.
