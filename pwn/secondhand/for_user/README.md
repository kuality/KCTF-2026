# secondhand

중고품 위탁 판매 카운터입니다.

로컬 서비스는 다음 명령으로 실행합니다.

```sh
docker compose up --build
```

기본 접속 주소는 `127.0.0.1:20002`입니다. 포트를 바꾸려면
`SECONDHAND_PORT=21002 docker compose up --build`처럼 실행하십시오.

분석용 `libc.so.6`과 `ld-linux-x86-64.so.2`는 서버와 동일한 Ubuntu
26.04/glibc 2.43 산출물입니다.
