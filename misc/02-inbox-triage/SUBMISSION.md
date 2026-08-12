# inbox-triage 제출 문서

| 항목 | 값 |
|---|---|
| 카테고리 | MISC |
| 난이도 | MEDIUM |
| 문제 유형 | 오프라인 메일 포렌식 / 구조 기반 트리아지 |
| FLAG | `KCTF{thr34d_h1j4ck_h1d3s_1n_th3_gr4ph}` |

> 운영·검수 전용 문서입니다. FLAG와 PoC가 포함되어 있으므로 공개 배포물에 넣지 않습니다.

## 문제 설명

Norite Systems 침해사고 대응 중 직원 메일함 덤프 600통을 확보했다. 이 중 딱 한 통이
실제 자격증명 탈취에 성공했다.

공격자는 새 대화를 시작하지 않고 기존 내부 업무 대화에 외부 발신자로 끼어들었으며,
해당 메일은 스팸 필터까지 통과했다. 메일을 식별하고 첨부 파일을 분석해 FLAG를
복구하라.

## 문제 풀이

키워드, SPF 실패, 첨부 보유 여부 같은 단일 속성만으로는 후보가 하나로 줄지 않는다.
`Message-ID`와 `In-Reply-To`로 전체 메일의 스레드 그래프를 만든 뒤 다음 불변식을
만족하는 메일 `H`를 찾는다.

```text
H의 In-Reply-To가 코퍼스 안의 메일을 가리킨다.
AND H를 제외한 같은 스레드의 발신자·수신자 도메인이 모두 norite-systems.com이다.
AND H의 From 도메인은 norite-systems.com이 아니다.
```

교집합은 `0455.eml` 한 통이다. 발신 주소는
`helpdesk@norite-systerns.com`으로, 정상 도메인의 `m`을 `rn`으로 바꾼 호모글리프다.

첨부 `VPN_Cert_Renewal.html`의 문자코드 배열을 복원하면 암호문 `blob`과 키 유도
규칙이 나온다. 하이재킹 메일에서 `In-Reply-To`를 루트까지 재귀적으로 따라가고,
루트부터 부모까지의 Message-ID를 쉼표로 연결한다.

```text
MATERIAL = "<root>,<...>,<parent>" + "|" + "norite-systerns.com"
h = MATERIAL.encode("ascii")
repeat 12,000,000 times: h = SHA256(h).digest()
key = h
keystream = SHA256(key + str(i))를 i=0,1,2,... 순서로 연결
plain = blob XOR keystream
```

PoC는 [solve.py](solve.py)이며 Python 표준 라이브러리만 사용한다.

```bash
WORKDIR="$(mktemp -d)"
unzip -q dist/inbox-triage.zip -d "$WORKDIR"
python3 solve.py "$WORKDIR/inbox-triage/maildump"
```

주요 실행 결과:

```text
[*] 전체 600통
[*] 세 조건의 교집합: 1통
[*] 하이재킹 메일: 0455.eml
[*] 위조 도메인: norite-systerns.com  (정상: norite-systems.com)
[*] 조상 체인 4단계
[*] KDF 12,000,000회
FLAG: KCTF{thr34d_h1j4ck_h1d3s_1n_th3_gr4ph}
```

## Challenge Files

### Challenge File (zip)

오프라인 분석형 문제로 별도 서버나 Docker 이미지는 없다. 플랫폼의 비공개
`Challenge File`에는 다음 파일을 하나의 ZIP으로 묶어 제출한다.

- [prob.py](prob.py): 메일 코퍼스 및 공개 ZIP 생성기
- [solve.py](solve.py): FLAG 획득 PoC
- [audit.py](audit.py): 값싼 속성 조합과 생성기 흔적 감사
- [README.md](README.md): 상세 풀이와 설계·검증 기록
- [SUBMISSION.md](SUBMISSION.md): 제출 양식용 문서

이 ZIP은 FLAG, 풀이, 생성기 내부값을 포함하므로 공개하지 않는다.

### Challenge Public File (zip)

- 파일: [dist/inbox-triage.zip](dist/inbox-triage.zip)
- SHA-256: `612288b1ede9e882bcb898a5b32ca0655b40a4220e8be898e260319efe2ad447`
- 구성: `INCIDENT_BRIEF.txt`, EML 600통

플레이어에게는 이 ZIP만 제공한다.
