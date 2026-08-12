# KCTF 2026 Crypto Challenge Set

KCTF 2026용 Crypto 문제 5종의 완성 패키지다. 난이도 구성은 Low 3개, Mid 1개,
High 1개이며, 각 문제는 참가자 배포본과 운영자 전용 자료를 분리한다.

| 난이도 | 문제 | 핵심 주제 | 형태 | 기본 포트 |
| --- | --- | --- | --- | ---: |
| Low | `common_ground` | RSA common modulus attack | 오프라인 자료 HTTP 배포 | 31340 |
| Low | `second_receipt` | Ed25519 non-canonical `S` malleability | TCP | 31341 |
| Low | `zero_contribution` | X25519 all-zero shared secret | TCP | 31342 |
| Mid | `forbidden_counter` | AES-GCM nonce reuse와 tag forgery | TCP | 31343 |
| High | `third_time_frost` | FROST/Ristretto255 nonce-pair 재사용 | TCP | 31344 |

## 디렉터리 계약

- `for_user/`: 참가자에게 공개할 파일만 들어 있다.
- `for_organizer/`: 실제 플래그, 공식 solver, writeup, 힌트, 설계 문서와 체크섬이다.
- `src/`: 정본 구현, 생성기와 회귀 테스트다.
- `CHALLENGE_IDEAS.md`: 후보 아이디어 18개와 최종 선정 근거다.
- `AGENTS.md`: 이후 수정·검수 시 지켜야 할 Crypto 전용 규칙이다.

운영자 디렉터리는 절대 참가자에게 배포하지 않는다. 서비스형 문제의 공개 패키지에는
`kctf{flag}`만 들어 있으며, 실제 플래그는 운영자 Compose 패키지에서 런타임 secret으로
주입된다. 따라서 플래그가 Docker 이미지 레이어나 빌드 컨텍스트에 포함되지 않는다.

## 전체 스택 부팅

루트에서 다음 명령을 실행하면 실제 출제 플래그가 적용된 5문제가 한 번에 빌드·부팅된다.
루트 Compose는 출제 서버 전용이며 항상 `for_organizer`를 사용한다.

```bash
docker compose up --build -d
docker compose ps
```

| 문제 | 기본 접속점 |
| --- | --- |
| `common_ground` | <http://127.0.0.1:31340/instance.json> |
| `second_receipt` | `nc 127.0.0.1 31341` |
| `zero_contribution` | `nc 127.0.0.1 31342` |
| `forbidden_counter` | `nc 127.0.0.1 31343` |
| `third_time_frost` | `nc 127.0.0.1 31344` |

각 호스트 포트는 `COMMON_GROUND_PORT`, `SECOND_RECEIPT_PORT`,
`ZERO_CONTRIBUTION_PORT`, `FORBIDDEN_COUNTER_PORT`, `THIRD_TIME_FROST_PORT`로
변경할 수 있다. 이는 포트 충돌을 피하기 위한 선택 사항이며 배포 모드를 고르는 변수가
아니다. 전체 종료는 `docker compose down -v`다.

참가자에게는 각 문제의 `for_user/`만 배포한다. 그 안의 서비스 플래그는 정확히
`kctf{flag}`이며, 루트 Compose나 `for_organizer/`는 배포 파일에 포함하지 않는다.

## 검증

전체 로컬 회귀 테스트와 패키지 무결성 검사는 다음 한 줄로 실행한다.

```bash
./validate_packages.sh
```

소스나 문서를 의도적으로 수정한 경우에만 먼저 `python3 tools/update_checksums.py`로
운영자 manifest를 갱신한다. 일반 검증은 manifest를 자동 갱신하지 않으므로 예기치 않은
변경을 그대로 탐지한다.

오프라인 문제와 사용자·운영자 Docker 패키지 전체를 실제 공식 solver로 검증하려면 다음을
실행한다. 서비스는 서로 겹치지 않는 임시 포트에서 하나씩 기동되고 자동으로 정리된다.

```bash
python3 tools/docker_verify.py
```

개별 서비스는 해당 패키지 안에서 실행한다.

```bash
cd second_receipt/for_organizer
docker compose up --build -d
```

배포 전에는 `for_organizer/SHA256SUMS`와 `FINAL_VALIDATION.md`도 함께 확인한다.
