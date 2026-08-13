# Organizer build

Linux x86-64 환경에서 다음 명령으로 재빌드한다.

```bash
make clean
make generate
make
make verify
```

`generate.py`가 4096바이트 메뉴판을 만들고, 그 FNV-1a 해시로 9개 stage의
연결 순서를 정한 뒤 정답 패스프레이즈를 파이프라인에 통과시켜 목표값을 얻는다.
같은 패스프레이즈를 키로 플래그를 봉인해 `generated_data.h`에 넣는다.
최종 배포 파일은 `../for_user/nyanyanyang`이다.

메뉴판을 바꾸면 stage 순서, 목표값, 봉인 결과가 모두 바뀐다.
`generate.py`는 봉인 왕복 검증을 자체적으로 수행하며, `make verify`가
평문 유출·솔버 재현·런타임 동작을 다시 확인한다.
