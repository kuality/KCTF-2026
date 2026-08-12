# KCTF 2026 MISC 제출 문서

각 문서는 문제 제출 양식의 `문제 설명`, `문제 풀이`, `Challenge Files` 항목을
그대로 옮겨 적을 수 있도록 정리한 운영·검수용 문서다. 정답과 PoC가 포함되어 있으므로
플레이어에게 공개하지 않는다.

| # | 문제 | 제출 문서 | 공개 배포물 |
|---|---|---|---|
| 1 | shredded | [01-shredded/SUBMISSION.md](01-shredded/SUBMISSION.md) | [shredded.zip](01-shredded/dist/shredded.zip) |
| 2 | inbox-triage | [02-inbox-triage/SUBMISSION.md](02-inbox-triage/SUBMISSION.md) | [inbox-triage.zip](02-inbox-triage/dist/inbox-triage.zip) |
| 3 | intel-chain | [03-intel-chain/SUBMISSION.md](03-intel-chain/SUBMISSION.md) | [intel-chain.zip](03-intel-chain/dist/intel-chain.zip) |
| 4 | canary-index | [04-canary-index/SUBMISSION.md](04-canary-index/SUBMISSION.md) | [canary-index.zip](04-canary-index/dist/canary-index.zip) |
| 5 | alias-chain | [05-alias-chain/SUBMISSION.md](05-alias-chain/SUBMISSION.md) | [alias-chain.zip](05-alias-chain/dist/alias-chain.zip) |

공통 제출 원칙:

- `Challenge File`은 출제자 전용 생성기·레퍼런스 솔버·감사 도구를 묶은 비공개 ZIP이다.
- `Challenge Public File`은 각 문제의 `dist/*.zip` 한 개뿐이다.
- `README.md`, `SUBMISSION.md`, `solve.py`, `prob.py`, `audit.py`, `artifacts/`에는
  정답 또는 풀이 정보가 있으므로 공개 파일에 넣지 않는다.
- 공개 ZIP의 현재 SHA-256은 [SUMMARY.md](SUMMARY.md)에 기록되어 있다.
