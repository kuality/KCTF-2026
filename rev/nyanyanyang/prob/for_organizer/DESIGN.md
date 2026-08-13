# nyanyanyang Design

## Goal

ELF/IDA는 알지만 "의사코드를 그대로 읽어 역함수를 짜면 된다"는 습관에 기대는
풀이를 걸러내는 중간 난이도 리버싱 문제다. 의도한 단계는 두 개다.

1. 9개 stage 변환의 의미를 읽어낸다. 각각은 3초면 이해되는 전단사 바이트 연산이다.
2. stage가 **어떤 순서로** 연결되는지 알아낸다. 이 순서는 소스 어디에도 상수로
   적혀 있지 않고, 바이너리 안의 데이터 블록에서 런타임에 유도된다.

안티디버깅, 패커, 심볼릭 실행, 무차별 대입은 필요하지 않다.

## Data model

| 상수 | 크기 | 역할 |
| --- | --- | --- |
| `MENU` | 4096 | stage 순서를 정하는 시드 원본 |
| `TARGET_DIGEST` | 24 | 정답 패스프레이즈의 파이프라인 통과 결과 |
| `LEGACY_DIGEST` | 24 | 도달 불가능한 미끼 검증 루틴의 목표값 |
| `SEALED` | 34 | 봉인된 플래그 |
| `CHECK` | 8 | 복호화 결과 확인용 |

순서 유도는 다음과 같다.

    seed  = FNV-1a(MENU[0..4096])
    rng   = xorshift64(seed)
    order = Fisher-Yates shuffle([0..8], rng)

실제 값은 `[2, 1, 5, 6, 0, 7, 8, 4, 3]`이다.

## Transform

각 stage는 `(byte, index) -> byte` 전단사 변환이다.

| stage | 연산 |
| --- | --- |
| 0 | `v + 0x5A + i` |
| 1 | `v ^ (0xA5 ^ (i * 7))` |
| 2 | `rol8(v, 3)` |
| 3 | `nibbleswap(v) ^ i` |
| 4 | 4bit S-box 치환 |
| 5 | `v - (i * i + 13)` |
| 6 | `ror8(v, 2)` |
| 7 | `rol8(v ^ 0x3C, 1)` |
| 8 | `(v + 0x9E) ^ 0x11` |

stage 2와 6, stage 3과 4는 초기 설계에서 서로 상쇄되거나 교환법칙이 성립해
해가 4개로 갈라졌다. stage 3에 인덱스 의존성을 넣고 stage 6의 회전량을
바꿔 유일해를 확보했다.

## Flag sealing

플래그는 평문으로 존재하지 않는다.

    key       = sha256(passphrase)
    keystream = sha256(key || counter_le32) 이어붙임
    SEALED    = FLAG xor keystream
    CHECK     = sha256("nyanyanyang-course::" || FLAG)[:8]

검증을 통과한 입력으로만 복호화가 성립하므로, 성공 분기를 패치해도
키가 틀리면 쓰레기 바이트가 나온다.

## Difficulty controls

- non-PIE로 IDA 주소와 ELF 파싱을 안정시킨다.
- 심볼은 제거하되 문자열 앵커는 남겨 진입점을 찾을 수 있게 한다.
- stage 연산 자체는 단순하다. 난이도는 전적으로 "순서"에 집중된다.
- 공식 풀이는 직접 역산이며, 메뉴판을 못 찾아도 9! = 362880 경로가 남는다.
- 길이가 맞지 않는 입력은 즉시 거절해 브루트포스 경로를 열어둔다.
