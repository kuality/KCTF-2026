# Final Validation Record

- 검증일: 2026-08-12 (Asia/Seoul)
- 대상: Low 3개, Mid 1개, High 1개
- 결과: 전체 통과

## 로컬 회귀 검증

`./validate_packages.sh`로 다음 항목을 확인했다.

| 문제 | 검증 내용 | 결과 |
| --- | --- | --- |
| `common_ground` | 결정적 seed 20개, 2048-bit 실전 instance, 재암호화 검산 | PASS |
| `second_receipt` | RFC 8032 vector, seed 20개, TCP 10회, strict-mode 공격 실패 | PASS |
| `zero_contribution` | RFC 7748 및 NIST GCM vector, seed 20개, TCP 10회, fixed-mode 공격 실패 | PASS |
| `forbidden_counter` | NIST GCM vector, seed 20개, TCP 10회, unique-nonce 모드 공격 실패 | PASS |
| `third_time_frost` | RFC 9591 Appendix E.3 vector, seed 5개, TCP 10회, one-use ticket 모드 공격 실패 | PASS |

추가로 사용자·운영자 소스 parity, 플래그 형식과 고유성, 공개본 secret 누출,
`SHA256SUMS`, 고정된 Docker base digest, 임시 Python 산출물 부재를 검사했다.

`uvx ruff check`와 `uvx ruff format` 기준도 통과했다.

## Docker 실전 검증

`python3 tools/docker_verify.py`로 서비스형 문제 4개의 `for_user`와
`for_organizer`, 총 8개 패키지를 순차적으로 빌드·기동했다.

각 컨테이너에서 다음 조건을 확인했다.

- 공식 solver가 해당 패키지의 플래그를 정확히 복구한다.
- 프로세스가 비루트 UID 2001로 실행된다.
- `/app/flag`가 이미지에 존재하지 않는다.
- `/run/secrets/challenge_flag`가 런타임에만 주입되고 UID 2001에서 읽힌다.
- 종료 후 Compose 컨테이너와 네트워크가 정리된다.

8개 패키지 모두 PASS다. 호스트에 이미 실행 중이던 다른 분야 컨테이너에는 손대지 않았다.

## 루트 Compose 통합 검증

루트 `docker-compose.yml`에서 실제 출제 플래그가 적용된 5개 문제를 동시에 부팅해
검증했다. 루트 스택은 환경변수로 배포 모드를 선택하지 않고 항상 `for_organizer`를 쓴다.

| 구성 | 검증 결과 |
| --- | --- |
| `docker compose up --build -d` | 5개 컨테이너 기동, 공개 RSA instance 바이트 일치, TCP solver 4개가 서로 다른 실제 플래그 획득 |

기본 포트 31340~31344, 비루트 UID 2001, 서비스별 런타임 secret의 가독성,
이미지 내부 `/app/flag` 부재를 확인했다. 각 `for_user/flag`는 별도로
`kctf{flag}`인지 검사한다. 검증 후 루트 Compose 컨테이너와
네트워크만 `down -v`로 정리했으며 기존 pwn 스택은 유지했다.

## 배포 안전장치

- Ubuntu 26.04 base image는 SHA-256 digest로 고정했다.
- 컨테이너 root filesystem은 read-only다.
- Linux capabilities를 전부 제거하고 `no-new-privileges`를 적용했다.
- CPU, 메모리, PID 한도를 지정했다.
- `.dockerignore` allowlist로 실제 플래그와 운영자 문서가 빌드 컨텍스트에 들어가지 않는다.
- 실제 플래그 5개는 서로 다르며 `KCTF{64-lowercase-hex}` 형식이다.
- 참가자 서비스 패키지에는 정확히 `kctf{flag}`만 사용한다.

Docker Compose가 buildx 부재에 관한 Bake 경고를 출력할 수 있으나, 기본 Docker builder로
정상 빌드되며 검증 결과에는 영향을 주지 않았다.
