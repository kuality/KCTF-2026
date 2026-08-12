# KCTF 2026 Crypto Challenge Authoring Rules

이 파일의 규칙은 `crypto/` 아래의 모든 문제와 하위 디렉터리에 적용된다. 목표는 수학적 약점이나 암호 프로토콜의 잘못된 결합을 논리적으로 찾아내고, 작은 재현 가능한 solver로 검증하는 **총 5개의 crypto 문제**를 만드는 것이다.

## 1. 필수 문제 수와 난이도

- 이번 세트는 총 5문제로 구성한다.
- 난이도 분포는 **하 3문제, 중 1문제, 상 1문제**로 고정한다.
- 각 문제는 `crypto/<challenge_name>/`이라는 독립 디렉터리를 사용한다.
- `<challenge_name>`은 영문 소문자, 숫자, 밑줄만 사용하고 다른 문제와 중복하지 않는다.
- 구현 전에 `CHALLENGE_IDEAS.md`를 읽고 최종 조합을 확인한다. 요청이 없는 한 한 문제에 서로 독립적인 공격을 여러 개 겹치지 않는다.
- 다섯 문제의 주 공격 축은 가능한 한 겹치지 않아야 한다. 권장 구성은 정수론 1개, 곡선/서명 1개, 키 합의 1개, 대칭키/AEAD 1개, 현대 다자간 프로토콜 1개다.

## 2. 난이도 기준

난이도는 긴 brute force, 불안정한 lattice parameter, 거대한 출력, 숨겨진 parser 동작으로 만들지 않는다. 의도한 암호학적 관찰과 유도 단계의 수로 조절한다.

- **하:** 하나의 명확한 약점을 식별하고 1~2개의 표준 수식으로 복구한다. Python 표준 라이브러리 또는 짧은 보조 코드로 통상 5초 안에 끝나야 한다.
- **중:** 두 개의 연결된 단계가 필요하다. 예를 들어 nonce 재사용 식 유도 후 유한체 연산으로 위조하는 구조다. 통상 30초 안에 결정적으로 끝나야 한다.
- **상:** 현대 프로토콜의 transcript/state를 정확히 복원하고 3개 이상의 식을 결합해야 한다. 공식 solver는 일반적인 대회 머신에서 원칙적으로 3분 안에 끝나야 하며, 성공률은 사실상 100%여야 한다.
- 확률적 성공, 네트워크 운, wall-clock timing, 외부 API 상태, 2^32 이상의 완전 탐색을 의도 풀이로 두지 않는다.
- SageMath, fpylll, Z3가 필요하면 그 필요성이 문제의 수학에서 나와야 한다. 단순 정수 연산으로 풀 문제에 무거운 도구를 요구해 난이도를 부풀리지 않는다.

## 3. 문제별 필수 구조

모든 문제는 최소한 다음 구조를 사용한다.

```text
crypto/<challenge_name>/
├── src/
│   ├── generate.py 또는 동등한 생성기
│   ├── verify.sh
│   ├── tests/
│   └── ...                         # 서버, verifier, 빌드 파일, 공개 소스 원본
├── for_user/
│   ├── README.md
│   └── ...                         # 공개 instance/source/binary 또는 로컬 서비스 패키지
└── for_organizer/
    ├── flag
    ├── solve.py                    # 공식 풀이 진입점
    ├── WRITEUP.md
    ├── DESIGN.md
    ├── HINTS.md
    ├── SHA256SUMS
    └── ...                         # seed, fixed 구현, requirements, 배포 파일
```

- 실제 소스, 생성기, 빌드 파일, 회귀 테스트는 모두 `src/`에 둔다.
- `for_user/`만 별도 디렉터리에 복사해도 문제 설명대로 실행하거나 풀 수 있어야 한다. `../src`, `../for_organizer`, 호스트 절대 경로를 참조하면 안 된다.
- `for_user/`에는 실제 flag 평문, 생성 seed, private key, factor, nonce, solver, writeup, 출제자 로그를 넣지 않는다.
- `for_organizer/DESIGN.md`에는 threat model, 의도한 식, 공격 단계, 난이도 근거, query budget, 우회 풀이, fixed 구현의 차이를 기록한다.
- `for_organizer/HINTS.md`에는 약한 관찰 힌트부터 거의 직접적인 수식 힌트까지 최소 3단계를 둔다.
- 의존성이 있으면 `requirements.txt`, `Cargo.lock`, Sage 버전 등으로 정확히 고정한다.

## 4. 오프라인형과 서비스형

문제는 처음부터 다음 둘 중 하나로 분류하고 `DESIGN.md`에 기록한다.

### 4.1 오프라인 산출물형

- `for_user/`에는 `instance.json`, `output.txt`, public key, ciphertext, protocol 문서처럼 풀이에 필요한 공개 자료만 둔다.
- 공개 instance는 실제 organizer flag에서 생성한다. pwn 문제처럼 가짜 flag로 만든 별도 instance를 배포해서는 안 된다.
- 공개 instance에 `flag` 파일을 넣지 않는다. flag는 의도한 cryptanalysis를 통해서만 복구되어야 한다.
- 공식 solver는 `python3 solve.py ../for_user`처럼 **참가자 디렉터리 하나만** 인자로 받고, 그 안의 공개 자료만 읽는다. Sage가 필요하면 `sage solve.sage ../for_user`와 같은 단일 디렉터리 인터페이스를 사용한다.

### 4.2 상호작용 서비스형

- `for_user/`와 `for_organizer/`에 각각 자체 완결적인 `Dockerfile`과 `docker-compose.yml`을 둔다.
- 두 패키지의 서버 코드, 프로토콜, 포트, query limit, timeout은 같아야 한다. flag와 운영상 필요한 secret만 달라야 한다.
- `for_user/flag`는 정확히 `kctf{flag}` 한 줄이고, 실제 서버 flag는 `for_organizer/flag`에만 둔다.
- 공식 solver 이름은 `solve.py`이며 `python3 solve.py HOST PORT` 두 위치 인자만 받는다. 한 연결에서 state가 유지되어야 하는 문제는 solver도 같은 연결을 사용한다.
- TCP listener와 세션은 비특권 사용자로 실행하고, 정상 요청이나 에러 메시지로 flag 파일을 직접 읽을 수 없어야 한다.

## 5. Flag와 secret 생성

- 모든 실제 flag는 `^KCTF\{[0-9a-f]{64}\}$` 형식을 사용한다.
- 문제마다 최소 32바이트의 독립적인 암호학적 난수를 생성하고 SHA-256으로 해시해 flag 본문을 만든다. 값을 직접 고르거나 다른 문제와 재사용하지 않는다.
- 오프라인 문제의 instance seed와 crypto key seed는 flag와 분리한다. 재현 가능한 생성에는 organizer 전용 고정 seed를 쓰되, 그 seed에서 flag 자체를 유도하지 않는다.
- 생성기는 명시적인 `--flag-file`, `--seed-file`, `--output-dir` 인자를 받고 같은 입력에서 byte-for-byte 같은 공개 instance를 만들어야 한다.
- 서비스가 세션별 key나 nonce를 생성할 수는 있지만, 공식 풀이 성공률과 query 수가 난수에 좌우되지 않게 한다.
- 실제 flag, seed, private material이 로그, Docker layer, Git diff, exception, core dump, `for_user/`에 남지 않았는지 검사한다.

## 6. Crypto 문제로 인정되는 기준

다음 조건을 모두 만족해야 한다.

1. 공격자가 보는 공개값 또는 oracle을 명확히 정의할 수 있다.
2. 암호학적 불변식, 잘못된 nonce/state, transcript binding, canonical encoding, parameter 선택 중 하나가 실제 약점이다.
3. 공개 입력에서 약점을 거쳐 secret 복구 또는 유효한 forgery까지 이어지는 식을 적을 수 있다.
4. solver 결과를 원래 verifier나 서비스에 다시 넣어 flag 획득을 검증할 수 있다.
5. 올바르게 고친 구현에서는 같은 exploit이 실패한다.

다음은 crypto 문제의 주 풀이로 허용하지 않는다.

- 소스나 JSON에 key/flag를 실수로 남긴 단순 정보 노출
- parser crash, command injection, path traversal, unsafe deserialization처럼 본질이 web/pwn인 취약점
- 라이브러리 함수 이름 하나를 검색하면 정답이 바로 나오는 wrapper
- 이유 없는 작은 key, 작은 prime, 32비트 seed의 완전 탐색
- 첫 flag byte부터 순서대로 맞히는 응답 차이 또는 원격 timing oracle
- 논문 코드를 그대로 실행하는 것 외에 문제 고유의 유도나 검산이 없는 구성

## 7. 수학 및 구현 정확성

- 군의 차수, 유한체 다항식, byte order, hash domain separator, transcript 직렬화, padding 규칙을 `DESIGN.md`와 `WRITEUP.md`에 정확히 적는다.
- 정수와 scalar를 자동으로 modulo reduction하는 parser를 쓴다면 canonicality 검사 여부를 명시한다.
- elliptic-curve 입력은 의도한 취약점이 아닌 한 canonical encoding, curve membership, identity/small-order point를 검증한다.
- nonce 재사용이나 bias 문제는 실제로 동일하거나 편향된 값이 사용되었음을 테스트에서 확인한다. 단지 seed가 비슷하다는 이유로 취약하다고 가정하지 않는다.
- lattice/Coppersmith 문제는 단일 seed 성공으로 완료하지 않는다. 여러 독립 seed에서 root bound, lattice dimension, runtime, 성공률을 측정하고 공개 parameter에 충분한 여유를 둔다.
- 유한체 표기는 구현의 bit ordering과 일치해야 한다. 특히 GHASH의 128비트 표현은 테스트 벡터로 교차 검증한다.
- 자체 구현한 primitive는 의도한 취약점 외에 잘못된 산술이나 비표준 검증이 추가되지 않았는지 공식 test vector와 비교한다.

## 8. 공정성과 관찰 가능한 단서

- 참가자에게 공격 표면을 재구성할 수 있는 protocol 문서, verifier/server source, 또는 충분한 입출력 자료 중 적어도 하나를 준다.
- 취약점이 직렬화 순서나 transcript 구성에 있으면 해당 코드가 공개되어야 한다. black-box에서 hash preimage를 추측하게 하지 않는다.
- 문제 설명은 사용된 primitive와 입출력 형식을 숨겨 난이도를 만들지 않는다. 약점 자체는 밝히지 않되 분석 출발점은 제공한다.
- Low는 생소한 라이브러리 빌드가 장벽이 되지 않게 한다. High라도 수학 외의 대형 프레임워크 빌드는 피한다.
- 모든 문제에는 결정적인 정상 예제 또는 짧은 public test vector를 제공한다.
- 힌트는 1단계에서 primitive/관찰점, 2단계에서 취약한 invariant, 3단계에서 세워야 할 핵심 식을 가리킨다.

## 9. 공식 solver와 writeup

- solver는 `for_organizer/flag`, seed, private key, generator의 secret output, writeup을 읽지 않는다.
- 정답 flag나 그에 준하는 secret을 hard-code하지 않는다. 공개 protocol 상수와 표준 domain separator는 허용한다.
- solver는 최종 flag만 출력하는 데 그치지 않고 핵심 중간 검산을 assertion으로 확인한다. 예: `pow(m,e,n)==c`, signature equation, AEAD tag, public key 일치.
- `WRITEUP.md`는 다음을 포함한다.
  1. 공개 입력과 threat model
  2. 정상 알고리즘의 핵심 식
  3. 취약 구현에서 깨지는 불변식
  4. secret 복구 또는 forgery의 단계별 유도
  5. solver 실행 명령과 예상 출력
  6. 원본 verifier/service에 재제출한 성공 증거
  7. fixed 구현에서 같은 공격이 실패하는 이유
- 공식 solver의 외부 패키지는 최소화하고 정확한 버전을 고정한다. 인터넷이 없는 clean container에서 설치 또는 실행 가능해야 한다.

## 10. 컨테이너와 리소스

- 모든 Dockerfile의 base image는 tag만 쓰지 말고 digest까지 고정한다. Python, Rust, Sage 이미지가 다를 수 있으나 문제별로 정확한 digest와 아키텍처를 기록한다.
- Docker build와 무거운 Sage/lattice 검증은 한 문제씩 순차 실행하고 빌드 병렬도는 `-j1` 또는 이에 준하게 제한한다.
- Compose에는 문제 동작을 해치지 않는 범위에서 memory, CPU, PID, connection 제한을 둔다.
- 서비스형 문제는 연결 종료, malformed JSON/hex, 너무 긴 입력, query limit 초과에서 crash나 hang 없이 종료해야 한다.
- 이번 작업에서 시작한 container/process만 정리하며 다른 분야나 사용자의 기존 변경을 건드리지 않는다.

## 11. 완료 전 필수 검증

문제 하나를 완료했다고 표시하기 전에 다음을 모두 통과한다.

1. `src/verify.sh`가 clean generation/build/package/solve/fixed-negative 검증을 완주한다.
2. `for_user/`만 격리된 임시 디렉터리에 복사해 참가자 README대로 실행하거나 분석할 수 있다.
3. 공식 solver가 organizer secret 없이 공개 자료 또는 실제 TCP protocol만으로 flag를 획득한다.
4. solver가 복구한 평문, key, signature, proof를 원래 공개식이나 서비스에 다시 넣어 검산한다.
5. fixed 구현에서는 동일한 exploit이 실패하고 정상 입력은 계속 성공한다.
6. Low/Mid는 최소 20개 seed, 무거운 High는 최소 5개 seed에서 solver 성공률 100%와 제한 내 runtime을 확인한다.
7. 공개 package에 flag 평문, 긴 flag 부분 문자열, seed, key, factor, nonce, organizer path, solver 상수가 없다.
8. invalid/canonicality/identity/zero/length/boundary 입력에 대한 negative test가 있다.
9. 서비스형은 query limit보다 적은 요청으로 같은 연결에서 최소 10회 연속 성공한다.
10. 오프라인 instance와 organizer 기준 instance의 SHA-256이 일치하고 생성기 재실행도 같은 hash를 낸다.
11. 모든 이미지와 dependency가 고정되어 있고 네트워크 없는 검증 환경에서 solver가 실행된다.
12. `WRITEUP.md`의 식, byte order, modulus/order, domain separator가 최종 코드와 일치한다.
13. `git diff --check`와 package allowlist 검사를 통과하고 임시 산출물이 남지 않는다.
