# intel-chain

| | |
|---|---|
| **카테고리** | MISC |
| **난이도** | MEDIUM |
| **플래그** | `KCTF{cr0ss_d0c_c0rr3l4t10n_1s_th3_j0b}` |
| **배포물** | `dist/intel-chain.zip` (2.2 MB) |
| **시연 능력** | Cross-document reasoning — 이종 문서 교차 상관분석 (Threat Intelligence) |

---

## 문제 설명 (출제용)

> 합성 APT 캠페인 **BLUEHERON** 에 대한 인텔 번들을 받았다.
> 리포트, 샌드박스 동적분석, IOC 목록, 네트워크 세션 요약이 들어 있다.
>
> 유출 채널을 특정하고 페이로드를 복호하라.
>
> 번들의 모든 지표는 합성이다. 실제로 찔러볼 것은 하나도 없다.

첨부: `intel-chain.zip`

---

## 구성

```
intel-chain/
├── BLUEHERON_TLPCLEAR_2026Q1.pdf   7페이지 (p.6 은 스캔 이미지)
├── sandbox/
│   ├── report_0442.json            Wave 1 샘플
│   ├── report_0517.json            Wave 3 샘플  <- 이것
│   └── report_0603.json            Wave 4 샘플
├── iocs.csv                        204행
└── traffic_summary.txt             약 2,530 세션 (payload 보유 약 170)
```

---

## 풀이 — 4단계 체인

### 1. 리포트에서 Wave 3 로더 계열명

`p.6` 은 **스캔 이미지라 텍스트 추출이 0자다.** OCR 이 필요하다.
(문제 1의 능력 재활용 — 카테고리 안에서 연결감을 준다)

```
wave 3   2026-03-11   kelphook.loader
         5045 5be6 7b57 b364 29a4 209a 50c2 f0c1
         980c 01dd 044f 5cfa b1f3 dcbd 250d 133e
```

리포트 본문이 *"Beginning with the THIRD wave, the C2 infrastructure was rotated completely"* 라고 명시한다.

조인 키는 **SHA256 이 아니라 로더 계열명** 이다. 샌드박스 JSON 의
`target.file.family` 와 맞춘다.

> **왜 해시를 조인 키로 쓰지 않는가.** 64자 hex 는 OCR 이 `0/O`, `1/l`, `5/S` 를
> 계속 틀린다. 4글자씩 끊어 적어도 `01dd`→`Oldd`, `5cfa`→`Scfa` 로 깨졌다.
> 반면 `kelphook.loader` 는 **10/10 정확**하다.
> 문제 1에서 얻은 교훈 그대로 — 단어는 OCR 을 견디고 구조화된 영숫자는 못 견딘다.
>
> wave 3 과 wave 4 가 둘 다 kelphook 계열이라, 본문 서술만으로는 안 되고
> 스캔의 wave→loader 매핑을 **실제로 읽어야** 한다.
> 잘못 고르면 그 계열명을 가진 샌드박스 리포트가 없으므로 즉시 안다 — 자기검증 지점이다.

### 2. 샌드박스에서 C2 도메인

`report_0517.json` 의 `target.file.family` 가 `kelphook.loader` 로 일치한다.

```
telemetry.example.com        requests=58
update.example.org           requests=9
ocsp.example.org             requests=23
cdn-sync.example.net         requests=41   <- C2
```

**요청 수 1위가 C2 가 아니다.** 리포트가 명시적으로 경고한다:

> *"Do NOT rank by request count. Telemetry and update endpoints frequently generate more requests than the C2 does. The discriminator is the fixed-interval beacon pattern in the HTTP timestamps."*

`network.http` 타임스탬프를 보면 `cdn-sync.example.net` 만 **60초 고정 간격 비콘 41회**다.

### 3. IOC CSV 에서 first_seen

```
cdn-sync2.example.net    2026-04-05T14:37:57Z  medium
cdn-sync.example.org     2026-03-15T15:07:35Z  high
cdn-sync.example.net     2026-03-14T09:21:44Z  high    <- 정확 일치
cdn-sync.example.com     2026-02-21T17:17:37Z  high
sync-cdn.example.net     2026-04-03T09:45:31Z  medium
```

유사 도메인이 다섯이고 전부 `campaign=BLUEHERON` 이다. confidence 로도 안 갈린다.
**정확한 문자열 일치만이 답이다.**

### 4. 트래픽에서 페이로드 + ATT&CK 에서 키

`first_seen` 시각의 세션이 유일하게 지목된다.

```
2026-03-14T09:21:44Z  192.0.2.51:52309 -> 198.51.100.77:443  TLS  cdn-sync.example.net  len=302
  payload(b64): ...
```

payload 라인 약 170개 중 이 한 줄이다.

`p.7` 의 ATT&CK 표(벡터 텍스트)에서 wave 3 에 매핑된 기법을 표 순서대로 뽑는다.

```
T1566  Phishing                            waves 1 3
T1059  Command and Scripting Interpreter   waves 3
T1071  Application Layer Protocol          waves 3 4
```

리포트가 조립 규칙을 그대로 적어준다:

```
MATERIAL  = TECH + "|" + C2DOMAIN + "|" + FIRSTSEEN
          = T1566T1059T1071|cdn-sync.example.net|2026-03-14T09:21:44Z
key       = SHA256(MATERIAL)
key       = 32바이트 raw digest (64자 hex 문자열이 아니다)
keystream = SHA256(key + str(i)) 을 i = 0,1,2,... 로 이어붙인 것
plain[j]  = cipher[j] XOR keystream[j]
```

→ `KCTF{cr0ss_d0c_c0rr3l4t10n_1s_th3_j0b}`

---

## 설계 노트

### 반복키 XOR 을 쓰지 않았다 — 초안은 체인이 장식이었다

초안은 `base64 → 15글자 반복키 XOR` 이었고 평문이 `KCTF{` 로 시작했다.
**이건 crib-drag 로 즉사한다:**

```
traffic_summary.txt 에서 payload(b64) 를 전부 grep → 디코드
각각에 "KCTF{" 를 끌어본다
```

PDF 도 샌드박스 JSON 도 IOC CSV 도 열지 않고 플래그가 나온다. **4단계가 통째로 무의미해진다.**
모델이 전혀 개입하지 않는 순수 기계적 우회이고, "번들을 모델에 던져본다" 는 점검으로는 절대 안 잡힌다.

→ SHA256 카운터 모드 스트림 암호로 교체했다. 솔버 코드는 여전히 5줄이다.

### 키 재료를 문서 3종에 걸쳐 묶었다

기법 문자열만으로 키가 정해지면 또 뚫린다:

```
ATT&CK 표의 6개 ID 중 3개를 고르는 조합 수백 개 × payload 약 170개 ≈ 2만 회
```

2만 회 SHA256 은 순식간이다. 샌드박스와 IOC 단계를 건너뛸 수 있다.
그래서 `MATERIAL` 을 세 문서에서 하나씩 가져와 조립하게 했다.

| 조각 | 출처 |
|---|---|
| `TECH` | 리포트 PDF p.7 (벡터 텍스트) |
| `C2DOMAIN` | 샌드박스 JSON (비콘 주기로 식별) |
| `FIRSTSEEN` | IOC CSV (유사 도메인 5종, 정확 일치 필요) |

이제 네 문서가 전부 하중을 받는다.

### 트래픽에 IOC 도메인을 섞었다

초안은 트래픽 도메인 집합과 `iocs.csv` 지표 집합을 교집합하면 **C2 하나만** 남았다.
한 줄이면 C2 와 유출 세션이 동시에 나와서 **샌드박스 3종과 스캔 페이지가 통째로
무의미해진다** — 이 문제의 중심 기믹이 증발한다.

```
$ 트래픽 도메인 2,447개 ∩ IOC 지표 202개
초안: 1개      현재: 48개
```

이제 교집합만으로는 못 고르고, 비콘 주기 분석이 유일한 판별자로 남는다.

### base64 패딩이 정답을 흘렸다

진짜 페이로드만 `=` 로 끝났다. `grep '=$'` 한 방에 암호문이 특정됐다.
평문을 3의 배수로 패딩하고 미끼 길이도 4의 배수로 맞춰 **`=` 로 끝나는 것 0개** 로 만들었다.

같은 이유로 C2 의 `first_seen` 과 같은 타임스탬프를 가진 도메인 행을 4개 더 뒀다.
그러지 않으면 유출 세션 시각과 대조하는 것만으로 정답이 사후 확인되는 공짜 오라클이 된다.

### ATT&CK 표는 스캔에 두지 않았다

실측한 `T1071` OCR 정확도:

| 조건 | 정확 |
|---|---|
| 18pt | 3/4 |
| 22pt | 4/4 |
| 26pt | 0/4 (폭 초과) |
| `T 1071` | 1/4 |
| 노이즈 4.0 / blur 0.35 / q72 | 4/8 |
| 노이즈 2.5 / blur 0.25 / q85 | 3/8 |
| 노이즈 1.5 / blur 0.15 / q92 | 1/8 |

**노이즈를 낮춰도 오히려 나빠진다.** 원인은 노이즈가 아니라 `T1071` 렌더링 자체의
취약성이고, 실제 생성물에서 `2 I 0 ft` 로 완파된 적이 있다. 최선이 4/8 이면
필수값으로 쓸 수 없다.

→ 표를 **벡터 텍스트 페이지로 옮겼다.** 로더 이름을 조인 키로 바꾼 것과 같은 판단이다:
**OCR 에 취약한 데이터는 텍스트에 두고, 스캔에는 OCR 로 안전하게 읽히는 것만 남긴다.**
체인에서 OCR 이 필수라는 성질은 p.6 이 그대로 유지한다.

### 서브테크닉 번호를 쓰지 않았다

표에 `T1566.001` 이 있으면 `T1566T1059T1071` 과 `T1566.001T1059.001T1071.001`
두 연결 방식이 똑같이 그럴듯해져서 **출제자 마음 맞히기**가 된다.
베이스 기법 ID 만 쓰고, 그 사실을 리포트 본문에 명시했다.

### 웨이브 열 표기를 OCR 로 실측해서 골랐다

`Waves` 열을 짧은 토큰으로 두면 OCR 이 무너진다. 네 가지 표기를 실제로 렌더링해 재봤다.

| 표기 | OCR 결과 |
|---|---|
| `1, 3` | `AEN)` — 전멸. 게다가 `T1071` → `T1O71` (O/0 혼동) |
| `1 3` | `Ls`, `12` — 여전히 깨짐 |
| `[1][3]` | `(1) [3]`, `{2] [4]` — 괄호 종류가 뒤섞임 |
| **`waves 1 3`** | **여섯 행 전부 정확. `T1071` 도 정상** |

**단어 하나가 OCR 에 문맥을 준다.** 감으로 골랐다면 `1, 3` 을 그대로 뒀을 것이고,
그러면 키 재료를 만들 수 없어 문제가 성립하지 않았다.

### PDF 를 영문으로 썼다

처음엔 한글로 썼는데 스캔 페이지가 `Wave 3: ¢c2 0h0 Oo Of.` 로 깨졌다.
Courier New 에 한글 글리프가 없기 때문이다. 위협 인텔 리포트는 영문이 자연스럽고
글꼴 문제도 사라지므로 전면 영문으로 전환했다.

### 매 단계가 자기검증적이다

MEDIUM 상한을 지키는 장치다. 이게 없으면 "어디서 틀렸는지 모르는" MED 가 HARD 로 변한다.

| 단계 | 틀렸을 때 |
|---|---|
| 1 | 그 로더 계열명을 가진 샌드박스 리포트가 없다 |
| 2 | 그 도메인이 IOC CSV 에 없거나 캠페인이 다르다 |
| 3 | 그 시각에 해당 호스트 세션이 없다 |
| 4 | 복호 결과가 UTF-8 디코드부터 실패한다 |

### 실제 IOC 를 쓰지 않았다

TI 문제는 실제 APT 데이터를 쓰고 싶어지지만, 실제 IP·도메인을 넣으면
**솔버들이 대회 중에 진짜로 찔러본다.**
IP 는 RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`),
도메인은 `example.*` 예약 네임스페이스만 썼다. 리포트 표지에도 명시했다.

---

## anti-shortcut 점검

| 항목 | 결과 |
|---|---|
| ① 모델 우회 (번들 통째 투입) | 어떤 단일 문서도 답을 담지 않는다. 4개를 전부 조인해야 키가 나온다 |
| ② 기계적 우회 (crib-drag) | 스트림 암호라 `KCTF{` 크립을 끌 수 없다 |
| ② 기계적 우회 (키 무차별 대입) | 키 재료가 3개 문서 조합이라 후보 공간이 열거 불가 |
| ② 기계적 우회 (grep) | 플래그는 암호문 안에만 존재 |
| ② 기계적 우회 (도메인 교집합) | 트래픽 ∩ IOC = **48개**. 비콘 분석 없이는 못 고른다 |
| ② 기계적 우회 (base64 패딩) | `=` 로 끝나는 payload **0개** |
| 무료 경로 | tesseract + pypdf. 유료 API 불필요 |
| 오류 감지 가능성 | 4단계 전부 자기검증적 |
| OCR 신뢰성 | 스캔에서 읽어야 하는 유일한 필수값(로더 계열명) **10/10** |

---

## 파일

| 파일 | 용도 |
|---|---|
| `prob.py` | 문제 생성기 (SEED 고정, 결정적) |
| `solve.py` | 레퍼런스 솔버 — OCR 포함 완전 자동 |
| `dist/intel-chain.zip` | 배포물 |

### 재현

```bash
pip install pillow numpy pytesseract pypdf reportlab
brew install tesseract

python3 prob.py     # 생성
python3 solve.py    # 풀이
```
