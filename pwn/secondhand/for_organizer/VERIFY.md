# secondhand 검증 절차

## 저비용/호스트 검증

Docker 없이 artifact, flag, 보호기법, 공개물 누출과 `kctf{flag}` exploit 3회 재생을
검사한다.

```sh
cd for_organizer
./verify_package.sh --with-exploit
```

스크립트는 다음을 확인한다.

- 두 release ELF와 listener의 byte identity
- 양쪽 libc/loader의 byte identity 및 공통 glibc 2.43 SHA-256
- release의 PIE/NX/canary/Full RELRO, 일반 system interpreter, RPATH 부재, strip
- organizer debug ELF와 release ELF의 Build ID 일치
- flag 형식/상이성/결정론적 fake 값과 공개물의 실제 flag 누출 부재
- 참가자 패키지에 source, solver, writeup, debug ELF가 없음
- glibc 2.43에서 동일 exploit의 `kctf{flag}` 획득 3회

## 직렬 Docker 검증

다른 문제의 빌드/컨테이너 검증이 끝난 뒤 아래 절차를 한 패키지씩 실행한다.
각 빌드 전후에 메모리와 남은 컨테이너를 확인한다.

```sh
free -h
docker ps
cd for_user
docker compose up --build -d
docker compose ps
```

listener와 정상 세션 권한, 설치 mode를 확인한다.

```sh
cid="$(docker compose ps -q secondhand)"
docker inspect --format '{{.Config.User}}' "$cid"
docker top "$cid" -eo pid,user,group,args
docker exec --user 0 "$cid" stat -c '%U:%G %a %n' \
  /home/user/secondhand /home/pwn /home/pwn/flag
! docker exec --user user "$cid" cat /home/pwn/flag
```

기대값은 image user `user:user`(UID/GID 2001), listener/정상 challenge 프로세스
`user`, binary `pwn:pwn`(UID/GID 2000) `4555`, `/home/pwn` `pwn:pwn 500`, flag
`pwn:pwn 400`이다. user의 직접
`cat`은 permission denied여야 한다.

`kctf{flag}` exploit과 재접속 안정성은 출력 내용을 로그에 남기지 않고 exit status로
확인한다.

```sh
cd ../for_organizer
for run in 1 2 3 4 5; do
  ./solve.py 127.0.0.1 31337 >/dev/null 2>&1
done
```

재시작 뒤 한 번 더 확인한다.

```sh
cd ../for_user
docker compose restart
cd ../for_organizer
./solve.py 127.0.0.1 31337 >/dev/null 2>&1
```

마지막으로 user 컨테이너를 내리고 동일 절차를 `for_organizer/`에서 반복한다.
실제 flag가 터미널 기록에 남지 않도록 solver 출력은 계속 `/dev/null`로 보낸다.

```sh
cd ../for_user
docker compose down --remove-orphans
free -h
docker ps
cd ../for_organizer
docker compose up --build -d
./solve.py 127.0.0.1 31337 >/dev/null 2>&1
docker compose down --remove-orphans
free -h
docker ps
```

`no-new-privileges`는 file setuid 전환 자체를 막으므로 이 문제의 Compose에 추가하면
안 된다. 대신 runtime root filesystem read-only, all capability drop, 96 MiB memory,
0.5 CPU, 64 PID, listener 최대 16 children과 세션 alarm을 적용했다.

## 최종 직렬 Docker 결과

2026-08-11에 고정 Ubuntu 26.04 GCC 15 산출물로 두 패키지를 각각 독립
빌드했다. listener UID/GID `2001:2001`, 정상 challenge UID 상태
`2001/2001/2000`, challenge `pwn:pwn` mode `4555`, `/home/pwn` mode `0500`,
flag `pwn:pwn` mode `0400`을 확인했다. 일반 `user`의 직접 읽기는 거부됐고,
공식 solver는 참가자/출제자 환경에서 각각 3회 연속 성공한 뒤 재시작 후에도
다시 성공했다. 실제 flag 값은 검증 로그에서 억제했다.

최종 challenge SHA-256은
`755da6e439841fe8f69ccb7b506eccb427068ed84b01e333e9a9b7be58bf0c7e`,
listener SHA-256은
`daf8935a4c9a4d59d80b5358b78e938fff689f2ecc2f9034dcac506aa9ef0e92`이다.
