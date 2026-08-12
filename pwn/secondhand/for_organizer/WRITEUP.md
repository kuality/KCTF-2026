# secondhand 출제자 풀이

## 1. 환경과 보호 기법

서비스와 빌드는 동일한 pinned Ubuntu 26.04 amd64 이미지에서 동작하며 allocator는
glibc `2.43-2ubuntu2`이다. release ELF에는 PIE, NX, stack canary, Full RELRO가
적용되어 있고 심볼은 제거되어 있다. 함께 배포한 `libc.so.6`과
`ld-linux-x86-64.so.2`는 서버 이미지와 동일한 분석용 파일이다.

`Item`의 요청 크기는 `0x40`이고 glibc chunk size는 `0x50`이다.

```text
Item +0x00  label (8바이트 relabel 범위)
     +0x08  price
     +0x10  note[0x20]
     +0x30  preview_callback
     +0x38  serial
```

`sell`은 `free(items[index])` 뒤 상태만 SOLD로 바꾸며 포인터를 지우지 않는다.
따라서 SOLD slot의 `preview`와 `relabel`은 각각 UAF read와 UAF write가 된다.
다만 relabel은 첫 8바이트만 바꾸므로 `+0x30` callback을 직접 덮을 수 없다.

## 2. safe-linking key와 PIE 유출

glibc 2.43의 작은 tcache bin에서 next는 다음과 같이 저장된다.

```text
encoded_next = next ^ (address_of_next_field >> 12)
```

처음 A와 B를 만들고, tcache가 비어 있을 때 B를 해제한다. 이때 `next == NULL`이므로
B의 첫 qword는 정확히 `B >> 12`이다. SOLD B를 preview하면 다음 두 값이 나온다.

- `storage word`: B에 적용할 safe-linking key
- `preview callback`: 해제 전 남아 있던 `render_item`의 PIE 주소

따라서 callback leak에서 정적 `render_item` 오프셋을 빼면 PIE base를 구할 수
있다. 참가자 release는 stripped 상태이므로 이 오프셋과 아래 전역 slot은
disassembler에서 복구한다. 공식 solver는 서버에 배포하지 않는
`secondhand.debug`에서 같은 값을 읽는다.

## 3. 두 엔트리 tcache poisoning

key를 얻은 B를 다시 할당하면 tcache가 다시 비게 된다. 이어서 A, B 순으로
해제하면 freelist는 다음과 같다.

```text
tcache[0x50] -> B -> A       (count = 2)
```

B는 앞에서 key를 유출한 바로 그 청크이므로 heap page를 추측할 필요가 없다.
SOLD B의 relabel로 첫 qword를 아래처럼 바꾼다.

```text
poison = (PIE_base + checkout_dispatch_offset) ^ leaked_key
```

`checkout_dispatch`는 writable PIE data에 있는 16바이트 정렬 구조체이고 크기는
`Item` 하나 이상이다. 첫 `malloc(0x40)`은 B를 돌려주고, 두 번째 호출은 전역
dispatch slot을 `Item *`처럼 돌려준다. count가 2였기 때문에 두 번의 할당이
모두 실제 tcache 경로를 지난다.

두 번째 consign의 `label`에 `PIE_base + print_flag_offset`을 넣으면
`checkout_dispatch.callback`이 `print_flag`로 바뀐다. settlement 메뉴가 이
전역 callback을 호출하면서 flag를 출력한다.

## 4. 짧은 callback overwrite 경로가 없는 이유

- relabel 쓰기는 `Item + 0x00`의 8바이트로 고정되어 `+0x30`에 닿지 않는다.
- preview는 객체 callback 값을 leak하지만, 값이 정확히 `render_item`인지 검사한
  뒤 상수 `render_item`을 호출한다. heap callback 위치를 별도 poison target으로
  잡아도 `print_flag`가 호출되지 않는다.
- 결산에서 호출되는 writable 함수 포인터는 정렬된 전역
  `checkout_dispatch.callback` 하나뿐이다.

따라서 의도한 성공 경로는 UAF key leak, PIE leak, 두 엔트리 poisoning, 전역
dispatch overwrite 순서를 모두 필요로 한다.

## 5. 권한 경계

TCP listener는 Dockerfile의 `USER user:user`로 실행된다. challenge ELF의 소유자는
`pwn:pwn`, mode는 `4555`다. 커널의 정상 setuid exec 직후 프로그램은

```text
real=user, effective=pwn, saved=pwn
```

상태로 시작하지만, `main` 초기에 `setresuid(user, user, pwn)`을 호출하고 결과를
검증한다. 이후 모든 메뉴 처리는 real/effective UID `user`로 수행된다.
`/home/pwn`은 mode `0500`, flag는 `pwn:pwn` mode `0400`이므로 정상 세션은 읽을
수 없다. 변조된 dispatch가 `print_flag`에 도달했을 때만 saved UID를 effective
UID로 복구해 `/home/pwn/flag`를 읽고 즉시 다시 user로 내린다.

## 6. 공식 solver 실행

참가자 가짜 환경을 컨테이너 없이 재생할 때는 bundled loader를 명시한다.

```sh
cd for_organizer
./verify_local.py ../for_user
```

실제 TCP 서비스는 다음처럼 검증한다.

```sh
cd for_organizer
./solve.py 127.0.0.1 31337
```

solver의 allocator 순서는 다음과 같다.

1. A/B 생성
2. 빈 tcache에 B 해제 후 key와 callback leak
3. B 재할당
4. A, B 순으로 해제해 `B -> A` 구성
5. B의 next를 encoded dispatch 주소로 UAF write
6. B와 dispatch를 차례로 할당
7. dispatch에 `print_flag` 기록 후 settlement 호출
