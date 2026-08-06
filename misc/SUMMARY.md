# KCTF 2026 MISC — 출제 요약서

> **운영/검수 전용.** 정답이 들어 있으므로 배포물(`dist/*.zip`)에는 포함되지 않는다.
> 플레이어에게 나가는 것은 각 `dist/*.zip` 뿐이다.

---

## 한눈 요약

| # | 문제 | 난이도 | 시연 능력 | 플래그 |
|---|------|--------|-----------|--------|
| 1 | shredded | LOW | Vision / OCR | `KCTF{0cr_p1p3l1n3_b34ts_th3_shr3dd3r}` |
| 2 | inbox-triage | MEDIUM | 구조 기반 트리아지 | `KCTF{thr34d_h1j4ck_h1d3s_1n_th3_gr4ph}` |
| 3 | intel-chain | MEDIUM | 문서 교차 상관분석 (TI) | `KCTF{cr0ss_d0c_c0rr3l4t10n_1s_th3_j0b}` |

카테고리 컨셉: **"AI로 보안에서 이런 것도 가능하다."** AI는 정답을 알려주는 오라클이
아니라, 사람이 손으로는 못 할 대량 작업을 처리하는 도구로 쓰인다.

---

## 배포물 (플레이어 제공 = 이 파일들만)

| # | 파일 | 크기 | 구성 | SHA-256 |
|---|------|------|------|---------|
| 1 | `01-shredded/dist/shredded.zip` | 31 MB | 조각 PNG 410 + NOTES.txt | `867d526c2e2b1f59…` |
| 2 | `02-inbox-triage/dist/inbox-triage.zip` | 0.6 MB | `.eml` 600 | `f7f2f27ac5730b31…` |
| 3 | `03-intel-chain/dist/intel-chain.zip` | 1.1 MB | PDF + 샌드박스 JSON 3 + IOC CSV + 트래픽 | `83fe853f70d147e6…` |

전체 해시:
```
867d526c2e2b1f59f20fd8659a2c877f9bba9227404d7d9c05a4cd8c49c32246  shredded.zip
f7f2f27ac5730b31ea1c93999f9d1a389515d55ab7d2c451e3ac61203f6bc9ec  inbox-triage.zip
83fe853f70d147e66c9b849083d557d87aa96ba34fe89f410b20463eca837175  intel-chain.zip
```

> ZIP 은 파일 mtime 을 저장하므로, 생성기를 다시 돌리면 **내용은 같아도 zip 해시는
> 바뀐다.** 위 해시는 현재 커밋된 배포물 기준이다. 배포 시 이 zip 을 그대로 쓸 것.

---

## 문제별 정답 도출 (검수용 요지)

### 1. shredded
- 조각을 전처리 후 OCR → 체크섬으로 실패 조각만 국소화 → 스윕 재시도 →
  **남은 1장은 눈으로 판독** → 정렬·16심볼 디코드·ZIP 복원.
- 자기검증 4단: 체크섬 → 인덱스 무결성 → ZIP magic → CRC.
- 레퍼런스 솔버: `01-shredded/solve.py`, 약 6초.

### 2. inbox-triage
- 첨부 보유 66통 → Message-ID 그래프 → 구조 불변식으로 진짜 1통:
  **답장 AND 스레드 내부 전용 AND 발신자 외부**.
- 발신 도메인은 호모글리프 `norite-systerns.com` (rn≠m).
- 키 재료 = 조상 Message-ID 체인 전체(루트→부모, `,` join) + `|` + 위조 도메인,
  SHA256 1,200만 회 반복 KDF.
- 레퍼런스 솔버: `02-inbox-triage/solve.py`, 약 2초.

### 3. intel-chain
- 리포트 스캔 OCR → wave3 로더 `kelphook.tideline` → 샌드박스에서 C2
  `cdn-sync.example.net`(60초 비콘) → IOC 에서 first_seen → 트래픽에서 페이로드.
- `MATERIAL = TECH|C2도메인|first_seen|샘플SHA256`, SHA256 1,200만 회 KDF.
- 레퍼런스 솔버: `03-intel-chain/solve.py`, 약 3초.

---

## 검증 결과

| 항목 | 1 | 2 | 3 |
|------|---|---|---|
| 배포물 zip 에서 레퍼런스 솔버 완주 | ✅ | ✅ | ✅ |
| 무료 도구만으로 완주 (VLM/유료 API 불필요) | tesseract | 표준 라이브러리 | tesseract+pypdf |
| 소스 없는 에이전트 블라인드 솔브 | ✅ | ✅ | ✅ |
| 실제 IP/도메인 미포함 (RFC 5737 / example.*) | — | ✅ | ✅ |
| guessing(찍기) 지점 부재 | ✅ | ✅ | ✅ |

### guessing 부재 — 판정 기준

모든 분기점이 셋 중 하나다: **(A) 명세 명시 / (B) 데이터로 유일 결정 /
(C) 자기검증(틀리면 즉시 앎)**. "하드 시그널 없이 여러 후보 중 찍기"는 없다.

- 문제 2 ID 순서: 명세에 없지만 root-first 만 `KCTF{`, leaf-first 는 디코드 실패 (C).
- 문제 3 C2: 비콘 힌트 없이도 "샌드박스 등장 ∧ BLUEHERON ∧ 트래픽 세션" = 1개 (B).
  오답 telemetry 와 미끼 유사 도메인은 자기검증(복호 실패/자기 미끼만 생성)으로도 배제 (C).
- 미끼가 있는 2·3 모두, 진짜와 미끼를 가르는 objective 판별자(인증·스팸 / 샌드박스
  등장)가 항상 존재한다.

---

## ⚠️ 운영 주의사항

1. **미끼 플래그가 그럴듯하다.** 문제 2·3 은 잘못된(하지만 의도된) 경로로 가면
   진짜처럼 보이는 가짜 플래그가 나온다. **오답 제출이 늘 것을 전제**하고,
   오답 제한·감점 정책이 있는 플랫폼을 권한다.
   - 문제 2 미끼: `cr3d_h4rv3st3r_st4g3_tw0`, `vpn_c3rt_lur3_d3pl0y3d`, 등 6종
   - 문제 3 미끼: `b34c0n_k3y_r3c0v3r3d_w4v3_tw0`, `c2_ch4nn3l_k3y_n0t_r0t4t3d`, 등 4종
   - 이 미끼들은 **정답이 아니다.** 정답은 위 한눈 요약 표의 3개뿐이다.

2. **정답 검사는 정확 문자열 일치**로. 세 플래그 모두 `KCTF{...}` 형식.

3. **재생성 시** `SEED` 를 바꾸면 플래그 이후 바이트가 전부 바뀌므로,
   `02-inbox-triage/audit.py` 를 다시 돌리고 `misc/README.md` 잔여 위험 원장의
   4개 축(Date 분포 / 답장 지연 / 헤더 직렬화 위치 / 본문 군집)을 눈으로 확인할 것.

---

## 재현 (검수자용)

```bash
# 의존성: python venv (pillow numpy pytesseract pycryptodome reportlab pypdf) + tesseract
M=/Users/s3zer0/ctf/KCTF-2026/misc

# 배포물에서 직접 풀기 (cwd 무관, 절대경로)
unzip -q $M/01-shredded/dist/shredded.zip -d /tmp/v
$M/.venv/bin/python $M/01-shredded/solve.py     /tmp/v/shredded/fragments
$M/.venv/bin/python $M/02-inbox-triage/solve.py  # 인자 없으면 dist 자동
$M/.venv/bin/python $M/03-intel-chain/solve.py

# 문제 재생성 (결정적, 단 zip mtime·MIME boundary 등 미세 비결정 있음)
(cd $M/01-shredded && $M/.venv/bin/python prob.py)
```

## 리포지토리 안내

- 문제별 `README.md` — 문제 설명 + 상세 풀이 + 설계 노트 (라운드별 하드닝 이력 포함)
- `misc/README.md` — 카테고리 관통 원칙 + 검증 이력 + **잔여 위험 원장**
- `misc/DESIGN.md`, `misc/SPEC.md` — 설계 방향과 확정 스펙
- `01-shredded/calibrate.py` — 열화 파라미터 보정 하네스 (출제자 전용)
- `02-inbox-triage/audit.py` — 지름길 전수 감사 (출제자 전용)
