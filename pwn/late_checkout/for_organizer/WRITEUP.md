# late_checkout 출제자 풀이

`take_last_request()`는 64바이트 지역 버퍼에 `read(..., 256)`을 수행한다.
프레임 포인터 8바이트를 지나 저장된 RIP까지의 오프셋은 72바이트다.
바이너리는 non-PIE이므로 필요한 주소는 매 실행마다 같다.

최종 배포 바이너리는 strip되어 있으므로 출제자 빌드가 기록한
`solve_constants.py`에서 정렬용 `ret`과 `print_receipt_secret()` 주소를
가져온다. 목표 함수로 곧바로 복귀하면 SysV AMD64의 16바이트 스택
정렬이 뒤집혀 함수 첫 `movaps`에서 종료된다. 따라서 페이로드는 다음 순서다.

```text
"A" * 72 | ret gadget | print_receipt_secret
```

정렬이 맞으면 목표 함수가 saved UID 2000을 effective UID로 복원하고서만
`/home/pwn/flag`를 연다. 정상 경로의 real/effective UID는 모두 2001이며,
flag는 `pwn:pwn` 소유 0400이므로 일반 접속 세션에서는 읽을 수 없다.

검증 실행:

```sh
python3 solve.py 127.0.0.1 10001
```

공식 solver는 `HOST PORT` 두 위치 인자만 받으며 원격 TCP 서비스를 대상으로 한다.
