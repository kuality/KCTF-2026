# Organizer build

Linux x86-64 환경에서 다음 명령으로 재빌드한다.

```bash
make clean
make
make verify
```

`generate.py`가 플래그 바이트마다 VM 연산을 만든 뒤, 1번의
`Dispatch code`와 2번의 `Relay phrase`를 결합한 키로 프로그램 전체를
암호화한다. 최종 배포 파일은 `../for_user/liberation_voice`이다.

릴리스 ELF는 Ubuntu 20.04에서도 실행되도록 glibc 호환 기준을 낮춘
GCC 11/Bullseye amd64 이미지로 빌드한다. 재현성을 위해 이미지 digest까지
고정했다.

```bash
docker run --platform linux/amd64 --rm -v "$PWD":/work \
  -w /work/rev-liberation-signal-3/prob/for_organizer \
  gcc:11-bullseye@sha256:63aaebc5db8930a70241051619cba77781a5466fb3e4dc99d2ff3b752cb715f2 \
  make -B verify
```
