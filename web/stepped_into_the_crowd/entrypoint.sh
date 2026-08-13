#!/bin/sh
set -e
# 플래그 경로를 부팅 때마다 랜덤화한다 (cat /flag 한 방 방지)
RAND=$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')
FP="/flag-${RAND}.txt"
cp /flag.txt "$FP"
rm -f /flag.txt
chmod 444 "$FP"
export FLAG_PATH="$FP"
# 서명 키 길이도 배포마다 다르게 (길이확장 시 브루트포싱 강제)
N=$(od -An -N1 -tu1 /dev/urandom | tr -d ' ')
export SECRET_LEN=$(( 16 + N % 25 ))
cd /app
exec su ctf -c "FLAG_PATH='$FP' SECRET_LEN='$SECRET_LEN' node server.js"
