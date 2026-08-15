#!/bin/sh
set -e
# 플래그 경로를 기동할 때마다 바꾼다 (cat /flag 한 방 방지)
RAND=$(head -c 12 /dev/urandom | od -An -tx1 | tr -d ' \n')
FP="/flag-${RAND}.txt"
cp /flag.txt "$FP"
rm -f /flag.txt
chmod 444 "$FP"
cd /app
exec su ctf -c "FLAG_PATH='$FP' node server.js"
