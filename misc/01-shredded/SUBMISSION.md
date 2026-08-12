# shredded 제출 문서

| 항목 | 값 |
|---|---|
| 카테고리 | MISC |
| 난이도 | LOW–MEDIUM |
| 문제 유형 | 오프라인 파일 분석 / OCR |
| FLAG | `KCTF{0cr_p1p3l1n3_b34ts_th3_shr3dd3r}` |

> 운영·검수 전용 문서입니다. FLAG와 PoC가 포함되어 있으므로 공개 배포물에 넣지 않습니다.

## 문제 설명

퇴사한 직원의 자리에서 파쇄기 회수함을 통째로 확보했다. 조각 410장을 스캔했지만
접힘, 얼룩, 기울어짐, 흐림이 섞여 있어 품질이 일정하지 않다.

각 조각의 포맷과 검증 방법은 배포 파일 안의 `NOTES.txt`에 기록되어 있다. 파일명은
순서와 무관하다. 410장을 복원해 원래 페이로드를 만들고 FLAG를 획득하라.

## 문제 풀이

조각 한 장에는 `IDX | DATA | CHK` 형식의 한 줄이 있다. 사용 알파벳은
`ABCDEGHKMNORSWY4` 16개이고, 심볼 하나가 4비트를 나타낸다.

1. 모든 이미지를 grayscale로 변환하고 기울기를 보정한 뒤 3배 확대한다.
2. tesseract를 `--psm 7`과 16심볼 화이트리스트로 실행한다.
3. `IDX + DATA`의 위치 가중합으로 `CHK`를 다시 계산해 잘못 읽힌 조각을 제외한다.
4. 실패한 조각에 확대율, blur, Otsu 이진화 등을 바꿔 재시도한다. 레퍼런스 데이터는
   1차 OCR에서 386/410, 재시도 후 408/410 조각이 자동 복구된다.
5. 남은 두 조각은 사람이 읽거나, 레퍼런스 솔버처럼 필드별 OCR 후보를 체크섬과 ZIP
   CRC로 검증한다.
6. `IDX` 순으로 `DATA`를 이어 붙여 4,920바이트를 복원한다. ZIP CRC를 확인하고,
   `KCTFENC1` 직전 전체 prefix의 SHA-256으로 HMAC을 검증한 뒤 트레일러를 복호한다.

PoC는 [solve.py](solve.py)다. tesseract와 Python 패키지 `pillow`, `numpy`,
`pytesseract`가 필요하다.

```bash
WORKDIR="$(mktemp -d)"
unzip -q dist/shredded.zip -d "$WORKDIR"
../.venv/bin/python solve.py "$WORKDIR/shredded/fragments"
```

주요 실행 결과:

```text
[*] 조각 410장
[*] 1차 체크섬 통과 386/410 (94.1%), 재시도 대상 24장
[*] 재시도 후 확보 408/410, 미해결 2장
[*] 미복원 인덱스 [83, 371] — 제약 탐색으로 복구 시도
      1번째 조합에서 CRC 통과
FLAG: KCTF{0cr_p1p3l1n3_b34ts_th3_shr3dd3r}
```

## Challenge Files

### Challenge File (zip)

오프라인 분석형 문제로 별도 서버나 Docker 이미지는 없다. 플랫폼의 비공개
`Challenge File`에는 다음 출제자 파일을 하나의 ZIP으로 묶어 제출한다.

- [prob.py](prob.py): 문제 생성기
- [solve.py](solve.py): FLAG 획득 PoC
- [calibrate.py](calibrate.py): OCR 열화 파라미터 보정 도구
- [README.md](README.md): 상세 풀이와 설계·검증 기록
- [SUBMISSION.md](SUBMISSION.md): 제출 양식용 문서

이 ZIP은 정답을 포함하므로 공개하지 않는다.

### Challenge Public File (zip)

- 파일: [dist/shredded.zip](dist/shredded.zip)
- SHA-256: `d2817e59c4bf09efd35b7ef178aa5635c18aee2d6974344ef50c70bc51dc622d`
- 구성: `NOTES.txt`, PNG 조각 410장

플레이어에게는 이 ZIP만 제공한다.
