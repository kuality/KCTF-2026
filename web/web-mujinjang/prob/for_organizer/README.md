# Organizer build

```bash
docker compose up -d --build
```

포트 12757. `entrypoint.sh` 가 기동할 때마다 플래그 경로를 랜덤화한다.
발행 키와 nonce 시드는 프로세스 기동 시 새로 만들어지므로 재시작하면
참가자가 복구해 둔 키가 무효가 된다. 대회 중 재시작은 피할 것.

블랙박스 문제다. `app/` 를 참가자에게 배포하지 않는다.
