# 검증 메모

정적/호스트 검증:

```sh
cd ../src
make -j1 clean all
make -j1 package
./verify.sh
sha256sum ../for_user/late_checkout ../for_organizer/late_checkout
sha256sum ../for_user/tcp_listener ../for_organizer/tcp_listener
sha256sum ../for_user/libc.so.6 ../for_organizer/libc.so.6
sha256sum ../for_user/ld-linux-x86-64.so.2 \
  ../for_organizer/ld-linux-x86-64.so.2
readelf -SW ../for_user/late_checkout | grep '\.symtab' && exit 1 || true
test -f ../for_organizer/solve_constants.py
test ! -e ../for_user/solve_constants.py
```

Docker 검증은 WSL 자원 상태를 확인하고 다른 빌드가 끝난 뒤 한 패키지씩
수행한다.

```sh
free -h
cd ../for_user
docker compose up --build -d
docker compose exec -T late_checkout sh -c \
  'test "$(id -u)" = 2001 && ! cat /home/pwn/flag'
python3 ../for_organizer/solve.py 127.0.0.1 10001
docker compose down --remove-orphans

free -h
cd ../for_organizer
docker compose up --build -d
docker compose exec -T late_checkout sh -c \
  'test "$(id -u)" = 2001 && ! cat /home/pwn/flag'
python3 solve.py 127.0.0.1 10001
docker compose down --remove-orphans
```

각 환경에서 solver를 여러 번 반복하고 컨테이너 재시작 후에도 같은 결과가
나오는지 확인한다. 참가자 환경은 `kctf{flag}`, 출제자 환경은 실제 flag를
반환해야 한다. 이미지 내부에서 다음 조건도 확인한다.

```sh
stat -c '%U:%G %a %n' /home/pwn/flag /home/pwn/late_checkout
# pwn:pwn 400 /home/pwn/flag
# pwn:pwn 4555 /home/pwn/late_checkout
```

## 최종 직렬 Docker 결과

2026-08-11에 고정 Ubuntu 26.04 GCC 15 산출물로 `for_user/`와
`for_organizer/`를 각각 독립 빌드했다. 두 환경 모두 listener UID/GID
`2001:2001`, 정상 challenge UID 상태 `2001/2001/2000`, flag `pwn:pwn`
mode `0400`, challenge `pwn:pwn` mode `4555`를 확인했다. 일반 `user`의 직접
flag 읽기는 거부됐고, 공식 solver는 각 환경에서 3회 연속 성공한 뒤 컨테이너
재시작 후에도 다시 성공했다. 실제 flag 값은 검증 로그에서 억제했다.

최종 challenge SHA-256은
`d36aaf39918e728e3ba474a44f6a226494f8a869c4d78a7bd1adbc622ed163b2`,
listener SHA-256은
`b150b677b6e0fd93a35446ae63b7d250047b1dcdbffdc3b1cb586236417f9c6b`이다.
