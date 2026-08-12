# rle_gallery 검증 기록

검증 기준일: 2026-08-11

## 최종 산출물 식별

최종 바이너리는 공통 Ubuntu 26.04 builder에서 GCC 15로 한 번 빌드한 뒤
두 패키지에 동일하게 복사했다.

| 파일 | SHA-256 |
| --- | --- |
| `rle_gallery` | `84e75773723f05a3629c2d657d68ba6f543ea5c33d79933f62643c8ce054759a` |
| `listener` | `e51b49a62962f10bca8984a9dd19dddcd5f513167f492cfed21b43ef6c934fb7` |
| `libc.so.6` | `d763925433ff9b757390549e1b20c085f5e6de27ae700fe89194178d96a8a2b0` |
| `ld-linux-x86-64.so.2` | `223b94a42758f2434da331cc0aa62db1af5b456481762c5caceefa1a2d1eb8fb` |

- Builder base: `ubuntu:26.04@sha256:7b202b0e2e0028c6250f5fcf41d04df492d145a1654c6995a6553f0c1f6f1960`
- Compiler: `gcc (Ubuntu 15.2.0-16ubuntu1) 15.2.0`
- Linker: `GNU ld (GNU Binutils for Ubuntu) 2.46`
- 사용자/출제자 바이너리, listener, libc, loader 각각 `cmp` 성공

## 정적 구조와 보호 기법

`checksec --file=for_user/rle_gallery` 결과는 다음과 같다.

```text
RELRO: Full RELRO
Stack: Canary found
NX: NX enabled
PIE: PIE enabled
```

GCC 15 debug 산출물과 `objdump -d -M intel`로 확인한 최종 offset은 다음과
같다.

| 항목 | 값 |
| --- | ---: |
| `preview_title` | `0x133c` |
| `decode_picture` | `0x1440` |
| `restore_gallery_owner` | `0x153b` |
| `main` | `0x1590` |
| canvas → canary | `104` bytes |
| canvas → saved RIP | `120` bytes |

`decode_picture`에서 canvas는 `[rbp-0x70]`, canary는 `[rbp-0x8]`에 있다.
따라서 두 주소의 차이는 `0x68`(104)이고, saved RBP 8바이트를 지나
saved RIP는 offset 120이다. 복구 함수의 prologue에는 `and rsp, -16`이
있어 saved RIP에서 직접 진입해도 내부 호출의 ABI stack alignment가
유지된다.

## 선행 비-Docker 동적 검증 완료

공통 loader에 `--library-path for_organizer`를 지정한 authoring-time replay로
다음 전체 체인을 확인했다. 최종 공식 `solve.py`는 인터페이스 통일을 위해
`HOST PORT` 두 위치 인자만 받는다.

1. `%11$p|%12$p|%13$p`로 canary, PIE, libc 주소를 한 연결에서 유출
2. RLE 복원 overflow로 유출 canary 보존
3. 첫 saved RIP를 `restore_gallery_owner`로 설정
4. 제공 libc의 `system("/bin/sh")` 실행
5. 명령 출력 확인 후 `_exit(0)`으로 worker 정상 종료

결과에서 `__RLE_GCC15_OK__`와 `id` 출력이 확인됐고 프로세스 종료 코드는
0이었다. setuid 권한과 최종 공식 solver는 아래 Docker E2E에서 검증한다.

입력 회귀 결과:

| 사례 | 결과 |
| --- | --- |
| 정상 3중 leak + 짧은 RLE | 종료 코드 0, leak 3개 확인 |
| `%11$n` | 종료 코드 1, format 단계에서 거부 |
| `%11$s` | 종료 코드 1, format 단계에서 거부 |
| 홀수 RLE 입력 길이 | 종료 코드 1, 길이 단계에서 거부 |
| count 0 | 종료 코드 1, decoder에서 거부 |
| canary까지 덮는 잘못된 payload | SIGABRT, stack protector 작동 |

## 플래그와 공개 패키지 검사

- 참가자 flag는 정확히 `kctf{flag}`이고, 출제자 flag는
  `^KCTF\{[0-9a-f]{64}\}$` 형식이다.
- 두 flag는 서로 다르다.
- 사용자 flag는 공통 더미 값 `kctf{flag}`와 일치한다.
- 실제 flag 바이트를 `for_user/` 전체에서 검색한 결과는 0건이다.
- `for_user/`에는 solver, writeup, validation 문서 또는 source가 없다.
- 배포 바이너리와 listener 문자열에는 flag 값, flag 경로, 정답 함수명이
  없다.

실제 flag 값은 이 문서와 검증 로그에 출력하지 않았다.

## Docker 순차 E2E 완료

2026-08-11에 두 패키지를 한 번에 하나씩 독립 빌드해 다음을 확인했다.

1. `for_user/`와 `for_organizer/` 각각의 컨텍스트에서
   `docker compose up --build` 성공
2. listener UID/GID `2001:2001`; 정상 challenge의 UID 상태
   `2001/2001/2000` (real/effective/saved)
3. challenge `pwn:pwn` mode `4755`, flag `pwn:pwn` mode `0400`
4. 일반 `user`의 `/home/pwn/flag` 직접 읽기 거부
5. 공식 solver가 참가자 환경의 `kctf{flag}`와 출제자 환경의 실제 flag를 각각
   3회 획득; 실제 값은 로그에서 억제
6. 각 컨테이너 재시작 뒤 새 연결에서도 같은 exploit 성공
7. 검증 컨테이너와 로컬 Compose 이미지를 제거한 뒤 가용 메모리 약 18 GiB 유지

Dockerfile은 listener를 `USER user:user`로 시작하고, 문제 바이너리만
`pwn:pwn` mode `4755`, flag는 `pwn:pwn` mode `0400`으로 설치한다.
Compose는 `cap_drop: ALL`, 128 MiB, 0.5 CPU, PID 64 제한을 둔다.
setuid 전환에 필요한 의미를 파괴하므로 `no-new-privileges`는 의도적으로
설정하지 않았다.
