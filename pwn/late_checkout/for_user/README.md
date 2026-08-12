# late_checkout

체크아웃 직전, 호텔에 마지막 요청을 남겨 주세요.

```sh
docker compose up --build
nc 127.0.0.1 10001
```

배포 파일에는 문제 바이너리와 분석용 libc/loader, 가짜 로컬 `flag`, 정적
TCP listener 및 Docker/Compose 설정이 포함되어 독립 실행할 수 있습니다.
