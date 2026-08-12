# secondhand (medium)

판매 후 포인터를 지우지 않는 중고품 위탁 서비스의 UAF read/write를 이용해
glibc 2.43 tcache safe-linking을 해제하고, PIE의 16바이트 정렬 전역 dispatch
slot을 poison target으로 삼는 문제다.

- 참가자 공개물: `for_user/` 디렉터리만 배포
- 서버 배포물: `for_organizer/` 디렉터리만 사용
- 소스/빌드: `src/`
- 공식 풀이와 검증 문서: `for_organizer/`

두 패키지의 release 바이너리, listener, libc, loader, Dockerfile과 Compose는
동일하고 flag만 다르다. `for_user/`에는 source, debug ELF, solver, writeup이
들어가지 않는다.
