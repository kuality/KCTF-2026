# tagged_tape 공식 풀이

## 1. 문제의 핵심

이 파일은 stripped OCaml native x86-64 실행 파일이다. 플래그 본문 64바이트를 156개의
가역 연산으로 변환한 뒤, 바이너리에 들어 있는 64바이트 target과 비교한다. 따라서 target을
크래킹할 필요가 없고, OCaml 값 표현에서 연산 배열을 복원한 다음 연산을 역순으로 적용하면 된다.

```sh
$ file tagged_tape
tagged_tape: ELF 64-bit LSB executable, x86-64, statically linked, stripped
```

## 2. IDA에서 verifier 찾기

non-PIE 파일이므로 아래 주소는 최종 배포 바이너리에서 그대로 사용할 수 있다.

| 항목 | 가상 주소 | 참고 |
| --- | ---: | --- |
| main 로직 | `0x402af0` | prompt 출력, 입력, verifier 호출, verdict 출력 |
| verifier | `0x402a70` | `0x402b9c`에서 호출 |
| 연산 dispatch | `0x402d80` | tag별 jump table은 `0x526450` |
| 데이터 초기화 | `0x4034a0` | tape와 target 정적 값 구성 |
| `Wrong.` | `0x5a5618` | code xref `0x402bf0` |
| `Correct.` | `0x5a5628` | code xref `0x402be7` |
| `KCTF{` | `0x5a5650` | code xref `0x402b02` |

IDA에서는 먼저 Strings 창에서 `Correct.`를 찾아 xref를 타면 `0x402af0`에 도착한다.
같은 함수의 `KCTF{` 비교와 verifier call을 보면 입력이 `KCTF{` + 64바이트 + `}` 형식임을
알 수 있다. OCaml native code는 일반 C decompiler 출력보다 allocation/tag 검사 때문에
복잡해 보이므로, control flow 전체를 정리하기보다 `0x402d80`의 tag dispatch와 정적 데이터
표현을 함께 보는 것이 빠르다.

## 3. OCaml 값 표현 복구

64비트 OCaml에서 작은 정수는 하위 비트가 1인 immediate다.

```text
encoded_int = (value << 1) | 1
value       = encoded_int >> 1
```

반대로 하위 비트가 0인 값은 보통 block의 field를 가리키는 포인터다. 포인터가 `p`라면
header는 `p - 8`에 있으며 이 문제에서 필요한 두 값은 다음과 같다.

```text
wosize = header >> 10        # field 개수
tag    = header & 0xff        # variant/string tag
```

정적 데이터에서 다음 두 block을 확인할 수 있다.

| 데이터 | header 주소 | field/data 주소 | header | 해석 |
| --- | ---: | ---: | ---: | --- |
| target string | `0x5a65c0` | `0x5a65c8` | `0x27fc` | wosize 9, string tag 252, 실제 길이 64 |
| instruction array | `0x5a6610` | `0x5a6618` | `0x27300` | wosize 156, tag 0 |

배열의 156개 field는 다시 variant block을 가리킨다. OCaml의 인자가 있는 variant constructor는
선언 순서대로 tag 0, 1, 2, ...를 받는다. 이 바이너리에는 크기 2인 tag 0~3 block과 크기
3인 tag 4 block이 있으며, field는 모두 위의 immediate integer다. 최종 분포는
`[34, 33, 33, 12, 44]`이다.

공식 솔버는 주소를 하드코딩하지 않는다. writable `PT_LOAD`를 8바이트 단위로 훑으며
`80 <= wosize <= 384`, tag 0인 후보 배열을 찾고, 모든 field가 위 구조의 tag 0~4 block인지
검사한다. 최대 인덱스로 폭 64를 구한 뒤 배열 바로 앞의 OCaml string을 target으로 읽는다.
조건을 만족하는 후보가 정확히 하나가 아니면 실패한다.

## 4. 다섯 연산의 의미

`0x402d80`의 jump table 각 case를 따라가거나, 한 연산 전후의 두 바이트를 debugger에서
비교하면 다음 순방향 연산을 얻는다. 모든 산술은 8비트 modulo 256이다.

```python
tag 0: x[i] ^= key
tag 1: x[i] = (x[i] + key) & 0xff
tag 2: x[i] = rol8(x[i], amount)
tag 3: x[left], x[right] = x[right], x[left]

F(v, key) = rol8((v + key) & 0xff, ((key >> 5) & 7) + 1) \
            ^ ((key * 0x5b + 0x33) & 0xff)

tag 4: (L, R) -> (R, L ^ F(R, key))
```

tag 4는 1-round Feistel이므로 `F` 자체가 역함수를 가질 필요는 없다. 출력이 `(L', R')`이면
이전 값은 다음처럼 유일하게 복구된다.

```text
old_R = L'
old_L = R' XOR F(L', key)
```

나머지 역연산은 XOR과 swap은 자기 자신, add는 subtract, ROL은 ROR이다. target에서 시작해
instruction array를 뒤에서 앞으로 순회하면 원래 64바이트가 나온다.

최종 target은 다음과 같다.

```text
1f3c145bf1339d2365e0e6da7285c55eb41ea1216b999414576db39e6e26161a
7a603d5e41d73812590c076a3936eb4c5f9112335982357904aa97804e41f60b
```

## 5. 공식 솔버와 결과

`solve.py`는 Python 표준 라이브러리만 사용해 ELF program header와 OCaml block을 직접
파싱한다.

```sh
$ python3 solve.py ../for_prob/tagged_tape
KCTF{90d233fab0f60bd0c3796f9d5eabf71984eb84a891a0923aa7433abd041aa695}

$ python3 solve.py ../for_prob/tagged_tape | ../for_prob/tagged_tape
flag> Correct.
```

전체 알고리즘은 `locate_capsule_data()`로 tape/target을 찾고, `decode_operation()`에서
tag와 immediate field를 해석한 뒤, `invert()`에서 연산을 역순 적용하는 세 단계다. seed,
소스, organizer symbol 또는 정답 파일은 사용하지 않는다.
