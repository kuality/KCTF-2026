# intel-chain 제출 문서

| 항목 | 값 |
|---|---|
| 카테고리 | MISC |
| 난이도 | MEDIUM |
| 문제 유형 | 오프라인 위협 인텔리전스 / 문서 교차 상관분석 |
| FLAG | `KCTF{cr0ss_d0c_c0rr3l4t10n_1s_th3_j0b}` |

> 운영·검수 전용 문서입니다. FLAG와 PoC가 포함되어 있으므로 공개 배포물에 넣지 않습니다.

## 문제 설명

합성 APT 캠페인 `BLUEHERON`의 인텔 번들을 확보했다. 번들에는 캠페인 리포트,
샌드박스 동적분석 결과, IOC 목록, 네트워크 세션 요약이 들어 있다.

서로 다른 문서의 단서를 연결해 유출 채널을 특정하고 페이로드를 복호하라. 번들에
포함된 IP와 도메인은 모두 문서·예시용 대역이며 실제 외부 시스템을 조회할 필요가 없다.

## 문제 풀이

1. PDF 6페이지는 스캔 이미지이므로 OCR을 수행한다. Wave 3의 로더 계열명은
   `kelphook.tideline`이다.
2. `sandbox/report_0517.json`의 `target.file.family`가 이 값과 일치한다. 네 도메인의
   요청 시각을 비교하면 `cdn-sync.example.net`만 60초 간격으로 41회 비콘한다.
3. `iocs.csv`에서 도메인을 정확히 일치시켜 `first_seen` 값
   `2026-03-14T09:21:44Z`를 얻는다.
4. `traffic_summary.txt`에서 같은 도메인의 payload 보유 세션을 찾는다. IOC 등록
   시각과 유출 시각은 다르며, 실제 유출 세션은 `2026-03-20T02:47:11Z`다.
5. PDF의 ATT&CK 표에서 Wave 3 기법을 표 순서대로 읽으면
   `T1566T1059T1071`이 된다. 샌드박스의 샘플 SHA-256까지 포함해 키 재료를 만든다.

```text
MATERIAL = T1566T1059T1071|cdn-sync.example.net|2026-03-14T09:21:44Z|50455be67b57b36429a4209a50c2f0c1980c01dd044f5cfab1f3dcbd250d133e
```

`MATERIAL` 바이트에 SHA-256을 12,000,000회 반복해 raw 32바이트 키를 만든다.
Base64 payload를 디코드하고 `SHA256(key + str(i))` 카운터 키스트림과 XOR하면 FLAG가
복구된다.

PoC는 [solve.py](solve.py)다. tesseract와 Python 패키지 `pillow`, `numpy`,
`pytesseract`, `pypdf`가 필요하다.

```bash
WORKDIR="$(mktemp -d)"
unzip -q dist/intel-chain.zip -d "$WORKDIR"
../.venv/bin/python solve.py "$WORKDIR/intel-chain"
```

주요 실행 결과:

```text
[1] Wave 3 로더 (OCR) : kelphook.tideline
[2] C2: cdn-sync.example.net  (60초 고정 간격 비콘 41회)
[3] first_seen: 2026-03-14T09:21:44Z
[4] 유출 세션: 2026-03-20T02:47:11Z
[5] KDF 12,000,000회
FLAG: KCTF{cr0ss_d0c_c0rr3l4t10n_1s_th3_j0b}
```

## Challenge Files

### Challenge File (zip)

오프라인 분석형 문제로 별도 서버나 Docker 이미지는 없다. 플랫폼의 비공개
`Challenge File`에는 다음 파일을 하나의 ZIP으로 묶어 제출한다.

- [prob.py](prob.py): PDF·JSON·CSV·트래픽 및 공개 ZIP 생성기
- [solve.py](solve.py): FLAG 획득 PoC
- [README.md](README.md): 상세 풀이와 설계·검증 기록
- [SUBMISSION.md](SUBMISSION.md): 제출 양식용 문서

이 ZIP은 FLAG와 키 재료를 포함하므로 공개하지 않는다.

### Challenge Public File (zip)

- 파일: [dist/intel-chain.zip](dist/intel-chain.zip)
- SHA-256: `83fe853f70d147e66c9b849083d557d87aa96ba34fe89f410b20463eca837175`
- 구성: PDF 1개, 샌드박스 JSON 3개, IOC CSV, 트래픽 요약

플레이어에게는 이 ZIP만 제공한다.
