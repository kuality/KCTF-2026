# Organizer build

Linux x86-64 환경에서 다음 명령으로 재빌드한다.

```bash
make clean
make
make verify
```

`generate.py`가 출제 플래그에서 검증용 바이트 배열을 만들고, `challenge.c`에는
평문 플래그와 다음 단계 전달값이 들어가지 않는다. 최종 배포 파일은
`../for_user/dawn_courier`이다.

릴리스 ELF는 Ubuntu 20.04에서도 실행되도록 glibc 호환 기준을 낮춘
GCC 11/Bullseye amd64 이미지로 빌드한다. 재현성을 위해 이미지 digest까지
고정했다.

```bash
docker run --platform linux/amd64 --rm -v "$PWD":/work \
  -w /work/rev-liberation-signal-1/prob/for_organizer \
  gcc:11-bullseye@sha256:63aaebc5db8930a70241051619cba77781a5466fb3e4dc99d2ff3b752cb715f2 \
  make -B verify
```
