# paperweight_vm

영수증 규칙을 검사하는 작은 64비트 스택 VM입니다. 프로그램은 다음
프레임으로 전송합니다.

```text
u32le byte_count
byte_count bytes of instructions
```

각 명령은 16바이트 little-endian `<opcode:u8, flags:u8, offset:i16,
reserved:u32, immediate:u64>`입니다. `flags`와 `reserved`는 0이어야 하며,
최대 192개 명령을 보낼 수 있습니다.

| opcode | mnemonic | 동작 |
| ---: | --- | --- |
| 0x00 | HALT | 실행 종료 |
| 0x01 | PUSH | `immediate` push |
| 0x02 | DROP | top 제거 |
| 0x03 | DUP | top 복제 |
| 0x04 | SWAP | top 두 개 교환 |
| 0x05 | ADD | 두 값을 더함 |
| 0x06 | SUB | `second - top` |
| 0x07 | XOR | 두 값 XOR |
| 0x08 | LOAD | tape의 `offset` qword를 push |
| 0x09 | STORE | top을 tape의 `offset` qword에 저장 |
| 0x0a | PRINT | top을 16자리 16진수로 출력 |
| 0x0b | INPUT | stdin에서 정확히 8바이트를 읽어 push |
| 0x0c | HOME | tape window를 원점으로 복귀 |
| 0x0d | NOP | 아무 동작 없음 |
| 0x0e | RESERVED | 실행 중단 |
| 0x0f | TRIGGER | 봉인된 dispatch slot |

컨테이너 실행:

```sh
docker compose up --build
nc 127.0.0.1 20004
```

`libc.so.6`와 `ld-linux-x86-64.so.2`는 서버와 동일한 Ubuntu 26.04
glibc 2.43 분석용 파일입니다. 서버의 setuid 실행은 고정 이미지의 시스템
loader/libc를 사용합니다.
