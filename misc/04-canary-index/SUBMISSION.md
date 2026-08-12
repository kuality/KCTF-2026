# canary-index 제출 문서

| 항목 | 값 |
|---|---|
| 카테고리 | MISC |
| 난이도 | LOW–MEDIUM |
| 문제 유형 | 오프라인 의미 대조 / 대량 문서 분석 |
| FLAG | `KCTF{c4n4ry_m4tch_782992d2c39953d39ab94a74}` |

> 운영·검수 전용 문서입니다. FLAG와 PoC가 포함되어 있으므로 공개 배포물에 넣지 않습니다.

## 문제 설명

Norite Systems는 정보 유출자를 찾기 위해 수신자마다 일부 사실이 다른 브리핑을
배포했다. 외부에 게시된 익명 유출문 12개가 각각 어느 브리핑 사본에서 유출되었는지
식별하라.

유출자는 문장을 그대로 복사하지 않고 같은 뜻의 다른 표현으로 바꾸었다. 각 유출문에
대응하는 `BRIEFING-ID`를 찾아 배포 파일의 규칙대로 FLAG를 계산하라.

## 문제 풀이

각 유출문에는 호출명, 장소, 시각, 차량에 관한 네 사실이 있다.

1. AI 또는 사람이 만든 동의 표현 사전으로 유출문의 네 사실을 원래 표현으로
   정규화한다.
2. `BRIEFINGS/`의 972개 문서를 파싱해 네 사실이 모두 일치하는 문서를 찾는다.
3. 각 유출문마다 4/4 일치 후보는 하나이고 차점은 3/4다.
4. `LEAK-01`부터 `LEAK-12` 순서로 얻은 정확한 ASCII `BRIEFING-ID`를 `|`로 연결한다.
5. 연결 문자열의 SHA-256 hex digest 앞 24글자로 FLAG를 만든다.

정답 ID 순서는 다음과 같다.

```text
BRF-FD35B8F|BRF-8AA19E1|BRF-EC3B28A|BRF-33B76F4|BRF-B5E0C4A|BRF-874C8A7|BRF-3120DD5|BRF-FC0E8D0|BRF-BF47518|BRF-AA3DDA2|BRF-C96801C|BRF-95BFFEA
```

PoC는 [solve.py](solve.py)이며 Python 표준 라이브러리만 사용한다.

```bash
WORKDIR="$(mktemp -d)"
unzip -q dist/canary-index.zip -d "$WORKDIR"
python3 solve.py "$WORKDIR/canary-index"
```

주요 실행 결과:

```text
leak_01.txt: BRF-FD35B8F  (4/4 facts; runner-up 3/4)
...
leak_12.txt: BRF-95BFFEA  (4/4 facts; runner-up 3/4)
FLAG: KCTF{c4n4ry_m4tch_782992d2c39953d39ab94a74}
```

## Challenge Files

### Challenge File (zip)

오프라인 분석형 문제로 별도 서버나 Docker 이미지는 없다. 플랫폼의 비공개
`Challenge File`에는 다음 파일을 하나의 ZIP으로 묶어 제출한다.

- [prob.py](prob.py): 브리핑·유출문 및 공개 ZIP 생성기
- [solve.py](solve.py): FLAG 획득 PoC
- [audit.py](audit.py): 후보 구조·게싱·파일 크기 지름길 감사
- [README.md](README.md): 상세 풀이와 설계 기록
- [SUBMISSION.md](SUBMISSION.md): 제출 양식용 문서

이 ZIP은 정답 ID와 FLAG를 포함하므로 공개하지 않는다.

### Challenge Public File (zip)

- 파일: [dist/canary-index.zip](dist/canary-index.zip)
- SHA-256: `fbd0fc6d6de40b16fa4091ef87b6d8c404916e963cc00c271783f07ca2df43ab`
- 구성: `NOTES.txt`, 브리핑 972개, 유출문 12개

플레이어에게는 이 ZIP만 제공한다.
