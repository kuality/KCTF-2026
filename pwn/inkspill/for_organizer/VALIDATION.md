# inkspill 검증 기록

이 파일은 출제자 전용이며 공개 패키지에 포함하지 않는다.

## 정적/호스트 검증

- 고정 Ubuntu 26.04 builder의 `make -j1 clean all`: PASS
- compiler: GCC `15.2.0-16ubuntu1`, binutils `2.46-3ubuntu2`
- challenge SHA-256: `4b65b3c8c429c7958e62432d1fc4ee527f4caa259836f10e02e3300249b637d6`
- static listener SHA-256: `60336bfc1c7a8d5f20fe9a35aef051855249726bf12924df785e5f03e7f767b3`
- 두 패키지 challenge/listener 해시: 각각 일치
- `checksec`: Full RELRO, Canary, NX, No PIE
- 고정 `.approval` section: `0x405000`, 초기값 0
- 현재 제보문 시작 위치: 8번 인자, payload 주소: 10번 인자
- 승인 전 메뉴 2 거부: PASS
- 폭 4097, `%s`, 복수 `%hn` 거부: PASS
- 최종 바이너리로 공식 solver의 로컬 쓰기 체인: PASS
- `for_organizer/validate_static.sh`: PASS

최종 배포 바이너리는 아래 고정된 Ubuntu 26.04 builder에서 빌드한 단일 산출물을
양쪽 패키지에 복사했다. `approval` 주소는 linker option으로 고정되어 있고 solver가
포맷 인자 위치를 자동 탐색하므로 컨테이너에서도 같은 체인이 동작한다.

## 권한 모델

- listener: Compose와 Dockerfile의 `user` UID/GID `2001:2001` 아래에서 실행
- listener 구현: 정적 링크된 전용 C listener, runtime apt/socat 없음
- challenge 설치: `pwn:pwn` (`2000:2000`), mode `4555`
- flag 설치: `/home/pwn/flag`, `pwn:pwn` (`2000:2000`), mode `0400`
- 프로그램 진입 직후 UID: `(real=user:2001, effective=user:2001, saved=pwn:2000)`
- 승인되지 않은 메뉴 2: UID 복원이나 flag open 없이 거부
- 승인된 메뉴 2만: effective UID를 saved `pwn`으로 잠시 복원하여 flag 읽기
- runtime/build base: 동일하게 고정된 Ubuntu 26.04 amd64 digest
- 분석용 libc/loader: 공통 Ubuntu 26.04 아티팩트와 SHA-256 일치

공통 아티팩트 해시:

- `libc.so.6`: `d763925433ff9b757390549e1b20c085f5e6de27ae700fe89194178d96a8a2b0`
- `ld-linux-x86-64.so.2`: `223b94a42758f2434da331cc0aa62db1af5b456481762c5caceefa1a2d1eb8fb`

## Docker 검증

2026-08-11에 WSL 자원 상태를 확인하며 두 패키지를 한 번에 하나씩 검증했다.

- [x] `for_user/` 단독 `docker compose up --build`
- [x] `for_organizer/` 단독 `docker compose up --build`
- [x] listener UID/GID `2001:2001`, 정상 자식 UID 상태 `2001/2001/2000`
  (real/effective/saved) 확인
- [x] flag `pwn:pwn` mode `0400`, challenge `pwn:pwn` mode `4555` 확인
- [x] `user`의 `/home/pwn/flag` 직접 읽기 거부 확인
- [x] 공식 solver가 참가자 환경의 `kctf{flag}`와 출제자 환경의 실제 flag를 각각
  3회 획득; 실제 값은 로그에서 억제
- [x] 두 컨테이너 모두 재시작 후 새 연결에서 exploit 재현
