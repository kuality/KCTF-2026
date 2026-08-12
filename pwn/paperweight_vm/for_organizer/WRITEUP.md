# paperweight_vm 공식 풀이

## 1. 보호 기법과 권한 모델

배포 바이너리는 PIE, NX, stack canary, Full RELRO가 모두 켜져 있다. 컨테이너의
listener는 UID 2001인 `user`로 실행되고, challenge ELF만 `pwn:pwn`, mode
`4755`이다. ELF가 시작할 때의 자격 증명은 다음과 같다.

```text
real=user, effective=pwn, saved=pwn
```

프로그램은 즉시 `setresuid(user, user, pwn)`을 실행한다. 따라서 VM 정상 실행
중 real/effective UID는 모두 `user`이고 `/home/pwn/flag`는 읽을 수 없다.
saved UID만 마지막 ROP에서 복구할 수 있도록 남는다.

seccomp는 `read`, `write`, `openat`, `exit`, `exit_group`을 허용한다. 이 권한
모델과 ORW를 함께 성립시키기 위해 딱 하나의 예외가 있다. `setuid`는 인자가
정확히 2000이고 상위 32비트가 0일 때만 허용된다. 다른 `setuid` 인자와
`execve`, `execveat`, `open`, `mprotect`, `mmap` 등은 프로세스를 종료한다.

## 2. 명령 형식과 취약점

각 명령은 16바이트이다.

```c
struct instruction {
    uint8_t opcode;
    uint8_t flags;
    int16_t offset;
    uint32_t reserved;
    uint64_t immediate;
};
```

`LOAD`와 `STORE`의 핵심 검사는 다음과 같은 형태다.

```c
int16_t index = instruction->offset;
if (index >= 256)
    abort_vm();
address = tape_base + index * 8;
```

상한만 있고 `index < 0` 검사가 없다. tape는 같은 heap 객체의 마지막에 있고,
그 앞에는 아래 context가 있다.

```text
tape[-85]  tape_base
tape[-84]  tape_origin (heap leak)
tape[-83]  output_count
tape[-82]  handlers[HALT] (PIE leak)
...
tape[-67]  handlers[TRIGGER]
tape[0]    정상 tape 시작
```

따라서 `LOAD -82; PRINT`로 handler 주소를, `LOAD -84; PRINT`로 heap tape
주소를 얻는다. 실제 빌드의 정확한 handler/pivot offset은 organizer 전용
`offsets.json`에 있다. 최종 Ubuntu 26.04/GCC 15 release에서는 handler leak
offset이 `0x15a0`, pivot이 `0x1e20`, `pop rdx; ret`이 `0x1e30`이다.
solver는 바이너리 SHA-256
`13b3bde3df0db05c6cc7249595f729d4f9796e4dad627a6956d6d7ecd28cbbce`를
먼저 확인해 stale offset 파일을 잘못 사용하는 일을 막는다.

## 3. tape_base를 이용한 임의 읽기

`INPUT`은 실행 중 stdin에서 8바이트를 읽어 VM stack에 push한다. PIE base를
계산한 뒤 `write@GOT`의 절대 주소를 보낸다.

```text
INPUT
STORE -85        # tape_base = &write@GOT
LOAD 0
PRINT            # resolved libc write
HOME             # tape_base = tape_origin
```

Full RELRO 때문에 GOT 쓰기는 불가능하지만 읽기는 가능하고, BIND_NOW라서
`write@GOT`는 이미 resolve되어 있다. 유출값에서 제공된 `libc.so.6`의
`write` offset을 빼면 libc base가 나온다. `HOME`이 원래 tape로 돌아오므로
이후에도 정상 양수 `STORE`로 fake stack을 만들 수 있다. 같은 패턴을 반복하면
필요한 주소로 제한적 read/write window를 옮길 수 있다.

## 4. fake stack과 ROP

공식 solver는 tape word 0부터 36까지 다음 raw-syscall ROP를 쓴다.

```text
setuid(2000)
openat(AT_FDCWD, "/home/pwn/flag", O_RDONLY)
read(3, tape_buffer, 0x80)
write(1, tape_buffer, 0x80)
exit(0)
```

`pop rax`, `pop rdi`, `pop rsi`, `syscall; ret`은 제공 libc에서 찾는다. 이
때문에 libc leak 단계가 필수다. `pop rdx; ret`과 stack pivot은 바이너리의
정상 context 복구 코드에서 남긴 두 안정 gadget을 사용한다. flag 경로는
tape word 96, 읽기 버퍼는 word 128에 둔다.

listener child는 accepted socket을 0/1/2에 복제하고 나머지 descriptor를
닫은 뒤 exec한다. 따라서 첫 `openat` 결과가 항상 fd 3이다.

마지막으로 `handlers[TRIGGER]`를 PIE base 기반 pivot 주소로 바꾼다.

```text
INPUT
STORE -67
TRIGGER
```

pivot은 `mov rsp, [rdi+0x10]; ret`이다. handler 호출 시 `rdi`가 VM context이고
`[rdi+0x10]`이 변경 불가능한 `tape_origin`이므로 RSP가 fake stack으로
안정적으로 이동한다.

첫 syscall인 `setuid(2000)`이 saved UID를 effective UID로 되돌린 뒤에만
`openat`가 mode 0400, `pwn:pwn` flag를 열 수 있다. `system`, `execve`,
`win` 또는 flag 출력 함수는 체인 어디에도 없다.

## 5. 실행

운영 서버:

```sh
python3 solve.py 127.0.0.1 15005
```

Docker 없이 개발용 가짜 flag를 대상으로 검증하려면 다음처럼 경로를
명시한다. 이 모드에서는 `setuid(2000)`이 실패하더라도 읽을 파일 자체가
현재 개발 사용자에게 허용되어 있으므로 나머지 VM escape/ORW 체인을 확인할
수 있다. 실제 권한 상승 성공 여부는 반드시 컨테이너에서 별도로 확인한다.

```sh
python3 verify_local.py ../for_user/flag
```

공식 `solve.py`는 `HOST PORT` 두 위치 인자만 받는다. 매 실행 ASLR leak을 새로
얻으며 주소를 하드코딩하지 않는다.
