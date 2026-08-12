# Validation record

## 완료된 비-Docker 검증

- `make -j1 clean all verify`: 성공
- authoring host의 사전 빌드에서 같은 toolchain clean rebuild 전후 hash 일치:
  성공
- pinned Ubuntu 26.04 GCC 15 builder의 최종 산출물을 `src/build`와 양 패키지에
  byte-identical하게 설치: 성공
- 최종 challenge SHA-256:
  `13b3bde3df0db05c6cc7249595f729d4f9796e4dad627a6956d6d7ecd28cbbce`
- 최종 static listener SHA-256:
  `a27266f29eece1e03bcbab330d9ad6d868007a4d2a086a15b6f135df20c21f7a`
- 최종 metadata: handler `0x15a0`, pivot `0x1e20`, pop-rdx `0x1e30`,
  pwn UID 2000
- compiler 경고를 `-Werror`로 처리: 성공
- stripped user/organizer challenge binary SHA-256 동일: 성공
- static listener SHA-256 동일: 성공
- 양쪽 libc/loader SHA-256이 공통 Ubuntu 26.04 추출본과 동일: 성공
- user flag가 정확히 `kctf{flag}`, organizer flag가
  `^KCTF\{[0-9a-f]{64}\}$` 형식이고 서로 다름: 성공
- `for_user`에서 실제 flag, solver, offset metadata, C/Python source 부재: 성공
- PIE, NX, canary, Full RELRO, 표준 `/lib64` interpreter, RPATH 부재: 성공
- 배포 호스트에 따른 ROP 차이를 막기 위해 ELF IBT/SHSTK property 부재: 성공
- raw BPF source audit: read/write/openat/exit/exit_group 및
  `setuid(2000)` exact-argument gate 외 syscall kill
- 최종 GCC 15 ELF와 공통 glibc 2.43을 명시적으로 로드한 공식 exploit로
  참가자용 `kctf{flag}` ORW: 10/10 성공

재실행 명령:

```sh
./validate.sh
./validate.sh --local-exploit
```

## 직렬 Docker 검증 완료

2026-08-11에 두 패키지를 한 컨테이너씩 검증해 다음을 확인했다.

1. `for_user`와 `for_organizer` 단독 컨텍스트의 독립 빌드 성공
2. listener UID/GID `2001:2001`; 정상 challenge UID 상태
   `2001/2001/2000` (real/effective/saved)
3. challenge `pwn:pwn` mode `4755`, flag `pwn:pwn` mode `0400`
4. 일반 `user`의 `/home/pwn/flag` 직접 읽기 거부
5. 참가자/출제자 환경에서 공식 remote solver 각각 5/5 성공; 두 환경 모두
   재시작 뒤 추가 성공, 실제 flag 값은 로그에서 억제
6. `setuid(2000)` syscall을 제거한 변형 체인은 flag 획득 실패
7. `execve` syscall ROP probe는 `SIGSYS`로 종료
8. 컨테이너 system libc/loader가 공통 26.04 SHA-256과 일치
9. 검증 컨테이너와 로컬 Compose 이미지를 제거한 뒤 가용 메모리 약 18 GiB 유지

실제 flag 값은 검증 로그에 출력하지 말고 정규식 일치와 expected-file 비교만
기록한다.
