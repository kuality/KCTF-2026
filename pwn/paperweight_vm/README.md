# paperweight_vm

- 난이도: 상
- 분야: custom VM escape, heap OOB, PIE/libc leak, stack pivot, seccomp ORW
- 서비스 포트: container `8080`, default host `15005`
- 런타임: pinned Ubuntu 26.04 / glibc 2.43

소스와 재현 빌드는 `src/`, 공개 패키지는 `for_user/`, 운영 및 공식 풀이는
`for_organizer/`에 분리되어 있다. `for_user/`에는 실제 flag, solver,
offset metadata, writeup 또는 소스가 들어가지 않는다.
