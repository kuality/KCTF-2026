# rle_gallery 출제자 풀이

## 취약점 구성

서비스는 한 연결에서 제목 미리보기와 그림 저장을 차례로 처리한다. 제목은
최대 48바이트이며, 검증기는 리터럴·`%%`·`%N$p`만 허용한다. 따라서
`%n`, `%s`, 폭 지정자 같은 쓰기/역참조 우회는 사용할 수 없지만 제목이
그대로 `printf(title, ...)`의 포맷이므로 위치 지정자 정보 유출은 남는다.

다음 제목으로 세 값을 한 번에 얻는다.

```text
%11$p|%12$p|%13$p
```

- 11번: 현재 스레드의 stack canary
- 12번: PIE 내부 `preview_title` 주소 (`base + 0x133c`)
- 13번: 제공된 libc의 `printf` 주소

제목 처리 뒤에도 같은 프로세스가 RLE 입력을 받으므로 세 ASLR 값이 그대로
유효하다. 포맷 문법은 포인터 읽기만 허용하고 바이너리는 Full RELRO이므로
`%n` 또는 GOT overwrite가 더 짧은 경로가 되지 않는다.

RLE 스트림은 `(count, byte)`의 2바이트 쌍이다. 압축 입력은 512바이트로
제한하고 count 0도 거부하지만, 96바이트 `canvas`에 쓸 때 복원 길이의
상한을 검사하지 않는다. 최종 바이너리의 프레임 배치는 다음과 같다.

```text
canvas 시작       +0
stack canary      +104
saved RBP         +112
saved RIP         +120
```

그러므로 `A * 104 + canary + B * 8 + ROP`를 만든 뒤, 동일 바이트의 연속
구간을 최대 255까지 묶어 RLE로 인코딩하면 된다. 임의 바이트는 `(1, byte)`
쌍으로 항상 표현할 수 있다.

## 권한 전환과 ROP

컨테이너의 TCP listener는 UID 2001 `user`로 실행된다. 문제 바이너리는
UID 2000 `pwn` 소유의 setuid 파일이지만, `main`의 첫 단계에서
`setresuid(user, user, pwn)`을 실행한다. 정상 처리 중 real/effective UID는
모두 `user`이고 saved UID에만 `pwn`이 남는다. `/home/pwn/flag`는
`pwn:pwn`, mode `0400`이라 이 상태에서는 읽을 수 없다.

따라서 단순 `system("/bin/sh")`은 권한 모델을 만족하지 않는다. 첫 ROP
호출은 반드시 PIE의 `restore_gallery_owner` (`base + 0x153b`)로 보내야
한다. 이 함수가 보존된 UID로 `setresuid(pwn, pwn, pwn)`을 수행한 뒤,
제공 libc에서 구한 `pop rdi; ret`, `"/bin/sh"`, `system`을 사용한다.

복구 함수는 ROP의 `ret`으로 직접 진입해도 ABI 정렬을 복구하도록
`force_align_arg_pointer`로 빌드했다. 따라서 saved RIP부터 시작하는 체인은
다음 순서다.

```text
restore_gallery_owner
pop rdi ; ret
주소("/bin/sh")
system
pop rdi ; ret
0
_exit
```

셸에 `cat /home/pwn/flag`를 보내면 플래그를 얻는다. 셸이 끝나면 체인의
`_exit`가 해당 연결의 worker만 정상 종료하며 TCP listener는 계속 남는다.

## 재현

출제자 패키지에서 다음처럼 실행한다.

```sh
docker compose up --build -d
python3 solve.py 127.0.0.1 20003
docker compose down
```

`solve.py`는 바이너리/제공 libc base를 유출값으로 재설정하고 libc에서
가젯을 직접 검색하므로 ASLR과 컨테이너 재시작에 독립적으로 동작한다.
