# secondhand build

배포 바이너리는 Ubuntu 26.04 amd64 manifest
`ubuntu:26.04@sha256:7b202b0e2e0028c6250f5fcf41d04df492d145a1654c6995a6553f0c1f6f1960`
안에서 GCC 15.2와 glibc 2.43으로 재현한다. `Dockerfile.build`는 compiler,
binutils, make, libc 개발 패키지 버전을 모두 고정한다.

WSL 리소스 보호를 위해 다른 문제의 Docker 작업이 없는지 먼저 확인하고 다음을
한 번에 한 문제씩 실행한다.

```sh
free -h
docker build --target export -t secondhand-builder:26.04 \
  -f Dockerfile.build .
builder_container="$(docker create secondhand-builder:26.04)"
mkdir -p docker-out
docker cp "$builder_container:/secondhand" docker-out/secondhand
docker cp "$builder_container:/secondhand.debug" docker-out/secondhand.debug
docker cp "$builder_container:/tcp_runner" docker-out/tcp_runner
docker cp "$builder_container:/libc.so.6" docker-out/libc.so.6
docker cp "$builder_container:/ld-linux-x86-64.so.2" \
  docker-out/ld-linux-x86-64.so.2
docker rm "$builder_container"
./package_release.sh ./docker-out
free -h
```

`package_release.sh`는 release 바이너리와 공통 libc/loader를 양쪽 패키지에
동일하게 복사한다. unstripped `secondhand.debug`는 `for_organizer/`에만
설치한다. 기존 flag는 수정하지 않는다.

초기 flag가 아직 없을 때만 아래 명령을 한 번 실행한다. 스크립트는 기존 flag를
덮어쓰지 않는다.

```sh
./generate_flags.sh
```

호스트에서 하는 저비용 확인은 다음과 같다.

```sh
make -j1 clean all verify
../for_organizer/verify_package.sh --with-exploit
```

최종 release ELF는 일반 `/lib64/ld-linux-x86-64.so.2` 인터프리터를 사용하고
RPATH/RUNPATH가 없으며 strip되어 있다. 패키지의 libc/loader는 분석 및 로컬
solver replay용이며, setuid 배포 실행은 고정 이미지의 시스템 loader/libc를
정상 경로로 사용한다.
