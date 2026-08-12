# KCTF 2026 Crypto Challenge Ideas

이 문서는 총 5문제의 난이도 분포 **High 1, Mid 1, Low 3**을 맞추기 위한 후보군이다. Low 6개, Mid 6개, High 6개를 제시하고, 마지막에 실제 제작을 권장하는 5문제 조합을 별도로 고른다.

아이디어를 고를 때 다음을 우선했다.

- 암호 primitive와 공격 원리가 서로 겹치지 않을 것
- brute force가 아니라 식의 구조를 이해하면 결정적으로 풀릴 것
- 공개 source/protocol에서 취약한 불변식을 확인할 수 있을 것
- 공식 solver가 원본 verifier에 결과를 재대입할 수 있을 것
- fixed 구현으로 명확한 negative test를 만들 수 있을 것
- 이미 제작한 `crypto-black-header-recovery`, `crypto-frozen-treasury`, `crypto-two-views-of-the-abyss`의 Coppersmith, Fiat-Shamir statement omission, truncated-hash collision과 직접 중복되지 않을 것

## 전체 후보 요약

| 난이도 | 이름 | 핵심 주제 | 형태 | 제작 위험 | 추천 |
| --- | --- | --- | --- | --- | --- |
| Low | `common_ground` | RSA common modulus attack | 오프라인 | 매우 낮음 | **선정** |
| Low | `second_receipt` | Ed25519 scalar non-canonicality | 서비스 | 낮음 | **선정** |
| Low | `zero_contribution` | X25519 all-zero shared secret | 서비스 | 낮음 | **선정** |
| Low | `three_couriers` | Håstad broadcast attack | 오프라인 | 매우 낮음 | 후보 |
| Low | `faulty_seal` | RSA-CRT Bellcore fault | 오프라인 | 매우 낮음 | 후보 |
| Low | `one_time_twice` | Lamport OTS key reuse | 오프라인 | 낮음 | 후보 |
| Mid | `forbidden_counter` | AES-GCM nonce reuse와 GHASH forgery | 서비스 | 낮음 | **선정** |
| Mid | `rogue_quorum` | BLS rogue public-key aggregate | 서비스 | 중간 | 후보 |
| Mid | `twisted_ladder` | invalid-curve ECDH와 CRT | 서비스 | 중간 | 후보 |
| Mid | `cube_in_the_padding` | lax PKCS#1 v1.5, e=3 signature forgery | 오프라인 | 중간 | 후보 |
| Mid | `biased_ballot` | ECDSA partial-nonce HNP lattice | 오프라인 | 중간 | 후보 |
| Mid | `last_round_scar` | AES differential fault analysis | 오프라인 | 중간 | 후보 |
| High | `third_time_frost` | FROST nonce-pair ticket reuse | 서비스 | 중간 | **선정** |
| High | `known_challenges` | Sumcheck Fiat-Shamir message omission | 오프라인 | 중간 | 후보 |
| High | `cancelled_openings` | KZG batch coefficient binding 누락 | 서비스 | 높음 | 후보 |
| High | `shattered_dilithium` | ML-DSA ephemeral-vector leakage | 오프라인 | 높음 | 후보 |
| High | `noisy_divisor` | approximate common divisor lattice | 오프라인 | 높음 | 후보 |
| High | `fold_before_commit` | FRI challenge-before-commit flaw | 오프라인 | 높음 | 후보 |

---

# Low 후보

Low는 하나의 결정적인 관찰과 짧은 수식으로 풀리되, 세 문제가 서로 다른 분야의 기본기를 보여 주도록 구성한다.

## L1. `common_ground` — RSA common modulus attack

### 콘셉트

같은 RSA modulus `n`과 같은 평문 `m`을 서로소인 두 exponent `e1`, `e2`로 textbook RSA 암호화한 `c1`, `c2`를 공개한다. 평문은 정확한 길이가 명시된 실제 flag다.

```text
c1 = m^e1 mod n
c2 = m^e2 mod n
gcd(e1, e2) = 1
```

### 의도한 풀이

확장 유클리드 알고리즘으로 `a*e1 + b*e2 = 1`을 구하고 다음을 계산한다.

```text
m = c1^a * c2^b mod n
```

음수 지수는 modular inverse로 처리한다. 복구한 `m`을 고정 길이 big-endian bytes로 바꾸고 두 ciphertext에 다시 거듭제곱해 검산한다.

### 난이도와 제작 통제

- Python의 `pow(x, -1, n)`과 확장 유클리드만 필요해 Low에 적합하다.
- `gcd(c1,n)=gcd(c2,n)=1`, `m<n`, `gcd(e1,e2)=1`을 generator에서 assert한다.
- `p-q`, 작은 factor, 낮은 exponent integer-root 같은 다른 RSA 공격은 모두 실패하도록 정상적인 2048-bit modulus를 쓴다.
- 공개 파일은 `n,e1,e2,c1,c2,flag_len`만 포함한다.

## L2. `second_receipt` — Ed25519 non-canonical scalar replay

### 콘셉트

사용자는 이미 사용 처리된 정상 영수증 `(message, R || S)` 하나를 받는다. 서버는 signature bytes 전체를 replay cache key로 사용하지만, 자체 Ed25519 verifier는 `S < L`을 검사하지 않고 scalar multiplication 과정에서 사실상 `S mod L`로 처리한다.

### 의도한 풀이

정상 signature의 두 번째 32바이트를 little-endian integer로 읽고 군의 차수 `L`을 더한다.

```text
S' = S + L
signature' = R || LE32(S')
```

`S'`는 다른 byte string이라 replay cache를 우회하지만, `[S']B=[S]B`이므로 취약 verifier에서는 같은 message에 유효하다.

### 난이도와 제작 통제

- RFC 8032가 요구하는 `0 <= S < L` 검사를 정확히 하나만 제거한다.
- 원래 signature는 이미 redeemed 상태라 그대로 제출해서는 flag를 얻지 못하게 한다.
- point decoding, message canonicalization, length check는 올바르게 구현해 다른 우회를 막는다.
- fixed verifier는 `S >= L`을 reject하며 변형 signature만 실패하고 정상 signature 검증은 성공해야 한다.

## L3. `zero_contribution` — X25519 all-zero shared secret

### 콘셉트

서버는 참가자가 보낸 X25519 public `u`로 shared secret을 만들고 HKDF-SHA256과 AES-GCM으로 flag를 암호화한다. 그러나 shared secret이 all-zero인지 검사하지 않는다.

### 의도한 풀이

작은 차수 입력을 나타내는 canonical `u=0`을 보내면 clamped server scalar와의 X25519 결과가 32바이트 zero가 된다. 서버 public key, client input, protocol label은 모두 공개이므로 참가자는 동일한 HKDF를 계산해 AES-GCM ciphertext를 복호화한다.

### 난이도와 제작 통제

- 참가자는 X25519 ladder를 공격할 필요 없이 all-zero output의 의미와 KDF 입력만 이해하면 된다.
- 일부 라이브러리는 zero output을 자동 reject하므로 서버에는 동작이 명확한 검증된 ladder 구현을 쓰고 RFC test vector를 통과시킨다.
- fixed 구현은 secret bytes를 OR해 zero이면 KDF 전에 종료한다.
- identity/public-key binding을 KDF에서 빼는 별도 취약점은 만들지 않는다. 공개값을 KDF에 포함해도 zero secret은 참가자가 그대로 재현할 수 있다.

## L4. `three_couriers` — Håstad broadcast

### 콘셉트

동일한 224바이트 message block `m`을 서로 다른 세 2048-bit RSA modulus에 `e=3`으로 암호화한다. block에는 nonzero sentinel, 실제 flag, 검증용 checksum, 고정 길이 filler가 들어가며 PKCS#1 padding은 사용하지 않는다.

### 의도한 풀이

CRT로 `m^3 mod N1*N2*N3`를 합치고, `m^3 < N1*N2*N3`이므로 정확한 integer cube root를 구한다. 복구한 224바이트 block의 sentinel/checksum을 확인하고 세 ciphertext에 재암호화해 검산한다.

### 난이도와 제작 통제

- 세 modulus가 pairwise coprime인지 검사한다.
- generator는 `max(N1*N2,N1*N3,N2*N3) < m^3 < N1*N2*N3`을 assert한다. 그래야 ciphertext 하나나 둘이 아니라 세 개가 모두 필요하다.
- `common_ground`와 같은 세트에는 넣지 않는다. 둘 다 textbook RSA 재사용 문제라 교육 포인트가 겹친다.

## L5. `faulty_seal` — RSA-CRT Bellcore fault

### 콘셉트

같은 message에 대한 정상 RSA public key와 한 번의 faulty CRT signature를 준다. fault는 정확히 한 CRT branch의 계산에만 들어간다.

### 의도한 풀이

공개 exponent로 faulty signature를 검증한 값과 message representative의 차이를 취해 factor를 얻는다.

```text
p 또는 q = gcd(s_fault^e - m, n)
```

factorization으로 private key를 복구해 flag ciphertext를 복호화한다.

### 난이도와 제작 통제

- PKCS#1 encoding이 있다면 message representative를 공개 source 그대로 재현하게 한다.
- fault가 양쪽 branch나 recombination 전체를 망가뜨리지 않았음을 generator test로 확인한다.
- 한 번의 gcd가 핵심이므로 Low를 유지한다.

## L6. `one_time_twice` — Lamport one-time signature reuse

### 콘셉트

서비스는 32바이트 artifact Merkle root 자체를 Lamport OTS의 256개 message bit로 취급한다. 같은 OTS key로 서로 보수 관계인 두 승인 root를 서명했고, target은 두 root의 bit를 섞어 만든 서로 다른 세 번째 root다.

### 의도한 풀이

각 bit 위치에서 두 signature가 공개한 0-side/1-side preimage를 정리해 target root가 요구하는 256개 preimage를 조립한다. 이를 정상 verifier에 제출해 flag를 받는다.

### 난이도와 제작 통제

- 두 승인 root가 정확히 bitwise complement이고 target이 둘과 모두 다른지 generator가 assert한다.
- hash preimage brute force는 전혀 필요 없어야 한다.
- API가 임의 message가 아니라 이미 hash된 32바이트 Merkle root를 서명한다는 점을 protocol에 명시해 preimage를 찾는 문제가 되지 않게 한다.

---

# Mid 후보

Mid는 취약점 식별 후 실제 key/forgery를 만드는 두 번째 계산 단계가 있어야 한다.

## M1. `forbidden_counter` — AES-GCM nonce reuse와 universal forgery

### 콘셉트

토큰 발급 서버가 process restart 때 96-bit nonce counter를 0으로 되돌린다. 참가자에게 같은 key/nonce/AAD 아래 생성된, 알려진 16바이트 plaintext 토큰 두 개와 각각의 ciphertext/tag를 준다. 목표는 같은 nonce로 `role=admin`인 16바이트 token을 위조하는 것이다.

### 의도한 풀이

AAD와 ciphertext 길이가 같으므로 두 GHASH 식을 XOR하면 공통 mask와 동일 블록이 사라진다.

```text
T1 xor T2 = (C1 xor C2) * H^2
H = sqrt((T1 xor T2) / (C1 xor C2)) in GF(2^128)
```

`H`를 복구한 뒤 한 transcript에서 `E_K(J0)` mask를 구한다. 알려진 plaintext로 CTR keystream을 얻어 admin ciphertext를 만들고, 복구한 `H`와 mask로 새 tag를 계산한다.

### 난이도와 제작 통제

- 단순 CTR bit flip만으로는 tag가 실패하고, 반드시 GHASH 복구가 필요하게 한다.
- GHASH의 bit ordering을 NIST test vector와 교차 검증한다.
- target plaintext는 sample과 정확히 같은 블록 수로 고정해 다항식 차수를 불필요하게 높이지 않는다.
- fixed 서버는 key당 nonce uniqueness를 보장하며 같은 exploit transcript를 reject한다.

## M2. `rogue_quorum` — BLS aggregate rogue key

### 콘셉트

두 명 이상의 동일-message BLS aggregate signature를 승인하는 서비스가 public key 등록 때 proof of possession을 요구하지 않는다. 피해자 public key `P_v`는 이미 등록되어 있다.

### 의도한 풀이

참가자는 임의 scalar `x`를 고르고 rogue key를 다음처럼 등록한다.

```text
P_a = xG - P_v
```

그러면 aggregate public key는 `xG`가 되므로 참가자가 혼자 만든 `x*H(message)`가 피해자와 공격자의 aggregate signature처럼 검증된다.

### 난이도와 제작 통제

- subgroup와 canonical point 검사는 모두 올바르게 두고 PoP 누락만 취약점으로 둔다.
- 서로 다른 message를 aggregate하는 API로 바뀌면 공격식이 달라지므로 반드시 same-message fast aggregate임을 문서화한다.
- fixed 구현은 등록 시 proof of possession을 검증한다.

## M3. `twisted_ladder` — invalid-curve ECDH CRT recovery

### 콘셉트

short-Weierstrass ECDH 서버가 `(x,y)`를 받아 scalar multiplication하지만 원래 curve equation membership을 검사하지 않는다. 계산식에 같은 `a`를 쓰는 여러 sibling curve의 작은-order point를 보낼 수 있다.

### 의도한 풀이

작은 서로소 order `r_i`를 가진 invalid point `P_i`를 보내고, 서버가 반환한 KDF tag를 `k=0..r_i-1` 후보와 비교해 `secret mod r_i`를 찾는다. 여러 residue를 CRT로 합쳐 private scalar를 복구하고 flag 세션을 복호화한다.

### 난이도와 제작 통제

- 적절한 invalid points와 orders를 찾는 Sage helper 또는 충분한 curve parameter anchor를 공개한다.
- 작은 order의 곱이 secret range보다 확실히 크도록 한다.
- fixed 서버는 입력 point의 canonical encoding, curve membership, non-identity, subgroup를 모두 검사한다.

## M4. `cube_in_the_padding` — lax PKCS#1 v1.5 e=3 forgery

### 콘셉트

RSA public exponent가 3이고 verifier가 decrypted signature의 시작 부분 `00 01 FF 00 || DigestInfo || hash`만 검사하며 뒤 garbage와 충분한 `FF` 길이를 확인하지 않는다.

### 의도한 풀이

admin message의 요구 prefix 뒤를 자유 비트로 채운 큰 정수를 만들고, 그 값의 정수 세제곱근을 올림해 cube가 같은 prefix를 갖도록 조절한다. 결과를 signature로 제출한다.

### 난이도와 제작 통제

- `s^3 < n`을 보장해 modular wrap이 없는 이유를 풀이자가 확인할 수 있게 한다.
- prefix 길이와 modulus 크기에 충분한 slack을 두고 여러 seed에서 forge가 결정적으로 생성되는지 테스트한다.
- fixed verifier는 전체 EMSA-PKCS1-v1_5 encoding을 정확한 길이로 비교한다.

## M5. `biased_ballot` — ECDSA partial nonce HNP

### 콘셉트

secp256k1 서명 장치가 각 nonce의 상위 일부를 진단 log에 남긴다. 참가자는 여러 `(r_i,s_i,h_i)`와 nonce MSB를 받아 Hidden Number Problem lattice로 private key를 복구한다.

### 의도한 풀이

ECDSA 식 `s_i k_i - r_i d = h_i mod q`에 알려진 nonce prefix와 작은 미지 suffix를 대입해 lattice/CVP를 구성한다. 복구한 `d`가 public key와 일치하는지 확인한 뒤 admin signature를 생성한다.

### 난이도와 제작 통제

- fpylll/Sage 한 버전에서만 우연히 풀리는 경계 parameter를 피한다.
- 최소 20개 seed에서 성공률 100%가 되도록 signature 수와 leak bit 수에 여유를 둔다.
- nonce reuse나 너무 큰 leak 때문에 선형식 두 개로 바로 풀리는 단축 경로가 없는지 검사한다.

## M6. `last_round_scar` — AES differential fault analysis

### 콘셉트

동일 plaintext에 대한 정상 AES-128 ciphertext 하나와, 9라운드 MixColumns 직전에 한 byte fault가 들어간 ciphertext 여러 개를 제공한다.

### 의도한 풀이

마지막 SubBytes/ShiftRows를 역으로 보며 네 관련 output byte의 차분 조건을 만족하는 last-round key byte 후보를 교차시킨다. 16바이트 round key를 복구한 후 key schedule을 역전해 원래 AES key와 flag를 복호화한다.

### 난이도와 제작 통제

- fault 위치와 모델이 source/설명과 정확히 일치해야 한다.
- 각 column에 충분한 독립 fault를 제공해 후보가 유일하게 줄어들도록 한다.
- 무작위 fault 위치 추측이나 수백만 후보 brute force가 필요하지 않게 한다.

---

# High 후보

High는 현대 프로토콜의 transcript 또는 여러 수학 계층을 정확히 복원해야 하지만, 연구 논문 구현을 그대로 가져오거나 불안정한 대형 계산에 기대지 않는다.

## H1. `third_time_frost` — FROST nonce-pair ticket reuse

### 콘셉트

2-of-2 `FROST(ristretto255, SHA-512)` 서명 서비스다. 참가자는 participant 1의 share를 정상적으로 소유하고 서버는 participant 2의 share를 가진다. 서버는 round-one에서 hiding/binding nonce pair `(d,e)`와 commitment ticket을 발급한다.

취약점은 ticket을 message별로 사용 처리해 **같은 ticket을 서로 다른 세 benign message에 재사용**할 수 있다는 것이다. target message `release_flag`는 signing policy가 거부한다.

### 의도한 풀이

participant 2의 각 signature share는 다음 형태다.

```text
z_j = d + rho_j * e + lambda_2 * c_j * s_2 mod L
```

세 transcript에서 `rho_j`, `lambda_2`, `c_j`, `z_j`는 모두 공개이고 `(d,e,s_2)`만 미지수다. 참가자는 3x3 선형 시스템을 `mod L`에서 풀어 서버 share `s_2`를 얻는다. 자신의 `s_1`과 Lagrange interpolation으로 group secret을 재구성하고 target Schnorr signature를 직접 만들어 flag를 받는다.

### 난이도와 제작 통제

- RFC 9591의 commitment list 정렬, binding factor, group commitment, challenge, Lagrange coefficient 직렬화를 그대로 사용한다.
- 모든 Ristretto point/scalar는 canonical하게 decode하고 identity를 거부한다. nonce-ticket reuse만 취약점이어야 한다.
- 3x3 행렬 determinant가 0이면 세션을 다시 생성하도록 테스트에서 확인하되, 실제 확률은 무시할 수 있을 정도여야 한다.
- query budget은 commit 1회, benign sign 3회, target verify 1회에 여유를 조금 더 준다.
- fixed 서버는 첫 sign 시 ticket 자체를 원자적으로 consume한다. 한 식만으로는 `(d,e,s_2)`를 복구할 수 없어야 한다.

## H2. `known_challenges` — Sumcheck Fiat-Shamir omission

### 콘셉트

다변수 multilinear polynomial의 합을 증명하는 non-interactive Sumcheck verifier가 Fiat-Shamir challenge를 `statement || round_index`로만 계산하고 prover가 보낸 round polynomial `g_i`를 transcript에 흡수하지 않는다.

### 의도한 풀이

모든 `r_i`를 proof 작성 전에 알 수 있다. 각 round에서 선형 polynomial `g_i(t)=a_i*t+b_i`는 다음 두 조건을 동시에 만족하도록 만들 수 있다.

```text
g_i(0) + g_i(1) = previous_claim
g_i(r_i) = next_claim
```

마지막 `next_claim`을 실제 `f(r_1,...,r_n)`으로 두고 역으로 또는 계획된 중간값을 통해 모든 `g_i`를 구성하면 거짓 initial sum claim도 통과한다.

### 난이도와 제작 통제

- polynomial degree와 field serialization을 공개하고 `r_i != 1/2`인 instance를 생성한다.
- verifier의 마지막 oracle evaluation은 올바르게 수행해 단순 생략 문제가 되지 않게 한다.
- fixed transcript는 각 `g_i`를 absorb한 뒤 `r_i`를 squeeze한다.
- 기존 `crypto-frozen-treasury`의 단일 Schnorr statement omission과 달리, 다라운드 IOP의 challenge causality 복원이 핵심이다.

## H3. `cancelled_openings` — KZG batch binding omission

### 콘셉트

같은 evaluation point `z`에서 두 KZG opening을 batch verify한다. batch randomizer `r`가 commitment와 proof까지만 hash하고 claimed values `y_1,y_2`는 transcript에 포함하지 않는다.

### 의도한 풀이

두 정상 tuple의 proof를 유지한 채, verifier가 이미 정한 `r`에 맞춰 false claims를 다음처럼 바꾼다.

```text
y_1' = y_1 + delta
y_2' = y_2 - delta / r
```

그러면 batch pairing 식의 value 오차 `delta + r*(-delta/r)`가 소거되어 전체 batch는 통과하지만 각 opening은 개별적으로 거짓이다. 잘못된 두 claim이 특정 vault predicate를 만족하도록 `delta`를 선택한다.

### 난이도와 제작 통제

- BLS12-381 point/subgroup/canonical 검사는 모두 정상으로 두고 batch coefficient binding만 빠뜨린다.
- 참가자가 pairing library를 빌드하는 일이 주 난이도가 되지 않도록 고정 container와 작은 client skeleton을 제공한다.
- fixed verifier는 commitment, point, value, proof 전체를 transcript에 넣은 뒤 randomizer를 만든다.
- batch 식과 단일 verify를 각각 회귀 테스트해 unintended identity-point 우회를 막는다.

## H4. `shattered_dilithium` — ML-DSA ephemeral-vector leakage

### 콘셉트

실제 ML-DSA-44 서명 transcript와 함께 잘못된 진단 장치가 accepted signature의 ephemeral polynomial `y` coefficient 하위 4비트를 여러 개 누출한다. 공개 signature의 `z=y+c*s_1`과 sparse challenge `c`를 이용해 secret polynomial `s_1`을 복구한다.

### 의도한 풀이

각 signature에서 공개 `z`, 확장한 challenge polynomial `c`, leak `y mod 16`으로 다음 convolution congruence를 얻는다.

```text
z - y = c * s_1  (mod 16)
```

여러 signature의 식을 합쳐 작은 계수 `s_1`을 유일하게 결정하고, 공개 key와의 일치 또는 organizer가 정한 KDF commitment로 검산해 flag key를 얻는다.

### 난이도와 제작 통제

- FIPS 204 encoding, challenge expansion, negacyclic convolution을 실제 parameter와 일치시킨다.
- `Z/16Z`가 field가 아니므로 공식 solver는 bit-lifting 또는 작은-domain constraint solving을 명시적으로 구현한다.
- leak 개수와 signature 수는 여러 seed에서 유일 복구가 보장되도록 사전 측정한다.
- 실제 ML-DSA private key 전체 forgery를 억지로 요구하기보다, 복구한 `s_1`을 public commitment와 KDF로 검증하는 목표가 제작 리스크가 낮다.

## H5. `noisy_divisor` — approximate common divisor lattice

### 콘셉트

숨은 큰 정수 `p`에 대해 여러 공개값 `x_i=p*q_i+r_i`를 주며 `r_i`는 작은 signed noise다. flag key는 `p`에서 HKDF로 유도한다.

### 의도한 풀이

여러 approximate multiples의 정수 관계를 lattice로 찾아 noise를 제거하고 공통 divisor `p`를 복구한다. 복구 후 모든 `x_i mod p`가 공개 bound 안인지 확인하고 AEAD ciphertext를 복호화한다.

### 난이도와 제작 통제

- lattice dimension, `p/q/r` bit 크기, sample 수를 고정하고 최소 20개 개발 seed에서 reduction 성공률을 측정한다.
- pairwise gcd, 단일값 continued fraction, noise brute force 같은 단축 경로를 검사한다.
- solver가 특정 CPU의 BKZ 운에 의존하지 않도록 LLL 수준에서 충분한 parameter margin을 둔다.

## H6. `fold_before_commit` — FRI challenge-before-commit

### 콘셉트

작은 STARK형 low-degree verifier가 각 FRI layer의 Merkle root를 transcript에 넣기 전에 folding challenge `beta_i`를 계산한다. 참가자는 challenge를 미리 알고, 높은 차수의 두 half를 골라 fold 결과만 낮은 차수가 되게 만든 뒤 root를 commit한다.

### 의도한 풀이

공개 `beta_i`에 대해 pair `(a_j,b_j)`를 조절해 `a_j + beta_i*b_j`가 선택한 낮은 차수 codeword가 되도록 한다. 각 layer의 Merkle tree와 query opening을 일관되게 만들고 마지막 constant layer까지 위조한다.

### 난이도와 제작 통제

- hash collision이나 Merkle parser bug는 없어야 한다. 취약점은 commit/challenge 순서 하나다.
- domain 크기와 round 수를 작게 해 proof generator가 수 초 안에 끝나게 한다.
- fixed verifier는 root를 absorb한 뒤 `beta_i`를 squeeze하며 동일 forged proof를 거부한다.
- Sumcheck 후보와 같은 세트에는 넣지 않는다. 둘 다 Fiat-Shamir causality 문제라 학습 포인트가 겹친다.

---

# 최종 권장 5문제 조합

| 난이도 | 문제 | 참가자가 배우는 핵심 | 공식 solver 예상 의존성 | 예상 풀이 시간 |
| --- | --- | --- | --- | --- |
| Low | `common_ground` | Bézout 계수와 RSA 지수 결합 | Python 표준 라이브러리 | 15~40분 |
| Low | `second_receipt` | canonical scalar와 signature malleability | Python + 제공된 client | 20~50분 |
| Low | `zero_contribution` | X25519 cofactor/all-zero 검증 | Python + HKDF/AES 패키지 | 20~50분 |
| Mid | `forbidden_counter` | GHASH를 GF(2^128) 다항식으로 복구 | Python, 선택적으로 PyCryptodome | 1~3시간 |
| High | `third_time_frost` | FROST binding factor와 nonce-pair 재사용 연립식 | 고정 Ristretto binding | 3~7시간 |

## 이 조합을 추천하는 이유

1. **공격 축이 겹치지 않는다.** RSA 정수론, EdDSA encoding, X25519 key agreement, AES-GCM 유한체, FROST threshold protocol을 각각 한 번씩 다룬다.
2. **난이도 곡선이 자연스럽다.** Low는 한 개의 invariant, Mid는 `H` 복구와 tag forgery 두 단계, High는 transcript 복원과 3x3 scalar system 및 최종 서명의 세 단계다.
3. **최신성과 기본기의 균형이 좋다.** textbook RSA를 입문 anchor로 두고, 표준 곡선의 canonicality/contributory behavior, 실무 AEAD misuse, 표준화된 threshold Schnorr까지 올라간다.
4. **운영 리스크가 낮다.** lattice 성공률이나 대형 pairing 빌드에 의존하지 않고 공식 solver를 결정적으로 만들 수 있다.
5. **fixed-negative가 선명하다.** 각각 modulus/key 재사용 금지, `S<L`, all-zero reject, nonce uniqueness, ticket one-time consume라는 한 줄의 보안 불변식으로 수정 가능하다.

## 최종 세트의 힌트 방향

### `common_ground`

1. 두 RSA 공개키에서 무엇이 같은지 본다.
2. 두 exponent의 gcd가 1이라는 의미를 생각한다.
3. `a*e1+b*e2=1`을 ciphertext 지수에 적용한다.

### `second_receipt`

1. 서버가 기억하는 것은 message가 아니라 signature bytes다.
2. Ed25519 scalar의 canonical range를 확인한다.
3. `S`에 subgroup order를 더해도 group equation은 바뀌지 않는다.

### `zero_contribution`

1. 모든 X25519 public input이 상대 secret에 기여하는 것은 아니다.
2. shared output 32바이트가 모두 0인 경우를 확인한다.
3. `u=0`과 공개 KDF context로 서버 key를 그대로 재현한다.

### `forbidden_counter`

1. 두 token의 nonce와 길이를 비교한다.
2. 같은 nonce에서 tag 두 개를 XOR하면 어떤 GHASH 항이 지워지는지 쓴다.
3. `delta_T=delta_C*H^2`에서 `H`를 구한 뒤 tag mask를 복원한다.

### `third_time_frost`

1. 같은 commitment ticket이 몇 번 사용되었는지 본다.
2. signature share에서 hiding nonce와 binding nonce의 계수를 분리한다.
3. 세 개의 `z_j=d+rho_j*e+lambda*c_j*s`를 행렬로 풀어 server share를 구한다.

## 제작 순서 권장

1. `common_ground`: generator/package/solver 규격의 가장 작은 기준 구현
2. `second_receipt`: canonical parsing과 서비스 공통 골격 검증
3. `zero_contribution`: key agreement/KDF와 Docker 서비스 회귀
4. `forbidden_counter`: GHASH test vector 및 유한체 solver 확정
5. `third_time_frost`: RFC test vector부터 통과시킨 뒤 ticket state bug를 마지막에 주입

## 기준 문서

- FROST: <https://www.rfc-editor.org/rfc/rfc9591.html>
- Ed25519/Ed448: <https://www.rfc-editor.org/rfc/rfc8032.html>
- X25519/X448: <https://www.rfc-editor.org/rfc/rfc7748.html>
- AES-GCM/GMAC: <https://csrc.nist.gov/pubs/sp/800/38/d/final>
- ML-KEM: <https://csrc.nist.gov/pubs/fips/203/final>
- ML-DSA: <https://csrc.nist.gov/pubs/fips/204/final>
- EIP-4844 KZG point evaluation: <https://eips.ethereum.org/EIPS/eip-4844>
- Halo 2 protocol and Fiat-Shamir background: <https://zcash.github.io/halo2/design/protocol.html>
