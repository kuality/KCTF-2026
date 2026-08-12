# alias-chain 제출 문서

| 항목 | 값 |
|---|---|
| 카테고리 | MISC |
| 난이도 | LOW–MEDIUM |
| 문제 유형 | 오프라인 엔티티 해석 / 플랫폼 간 별명 연결 |
| FLAG | `KCTF{4l14s_ch41n_0dff2f984c5429eeca69c499}` |

> 운영·검수 전용 문서입니다. FLAG와 PoC가 포함되어 있으므로 공개 배포물에 넣지 않습니다.

## 문제 설명

확인된 포럼 계정 하나가 있다. 운영자는 다른 플랫폼에서 사용자명을 전혀 재사용하지
않았다. 제공된 공개 아카이브만 사용해 블로그, 리뷰, 여행기, 중고장터, SNS의 별명을
차례로 연결하라.

각 계정은 같은 개인적 경험을 서로 다른 표현으로 기록했다. 올바른 계정의
`PROFILE-ID`를 모아 배포 파일의 규칙대로 FLAG를 계산하라. 외부 인터넷 검색은
필요하지 않다.

## 문제 풀이

`GUIDE.txt`가 탐색 순서를 `BLOG -> REVIEWS -> TRAVEL -> MARKET -> SOCIAL`로 고정한다.

1. `START_PROFILE.txt`에서 개인적 경험 세 가지를 추출한다.
2. BLOG의 27개 프로필에서 세 경험을 모두 다른 말로 표현한 유일한 계정을 찾는다.
3. 찾은 계정의 나머지 세 경험을 다음 플랫폼의 피벗으로 사용한다.
4. 같은 과정을 REVIEWS, TRAVEL, MARKET, SOCIAL까지 반복한다. 각 단계의 3/3 일치
   후보는 하나이고 차점은 2/3다.
5. 다섯 ASCII `PROFILE-ID`를 `|`로 연결하고 SHA-256 hex digest 앞 24글자를 사용한다.

정답 체인은 다음과 같다.

```text
PRF-AE9AE491|PRF-42A23290|PRF-D72966AB|PRF-E2D366E3|PRF-E97C1A71
```

PoC는 [solve.py](solve.py)이며 Python 표준 라이브러리만 사용한다.

```bash
WORKDIR="$(mktemp -d)"
unzip -q dist/alias-chain.zip -d "$WORKDIR"
python3 solve.py "$WORKDIR/alias-chain"
```

주요 실행 결과:

```text
BLOG   : PRF-AE9AE491  (3/3 memories; runner-up 2/3)
REVIEWS: PRF-42A23290  (3/3 memories; runner-up 2/3)
TRAVEL : PRF-D72966AB  (3/3 memories; runner-up 2/3)
MARKET : PRF-E2D366E3  (3/3 memories; runner-up 2/3)
SOCIAL : PRF-E97C1A71  (3/3 memories; runner-up 2/3)
FLAG: KCTF{4l14s_ch41n_0dff2f984c5429eeca69c499}
```

## Challenge Files

### Challenge File (zip)

오프라인 분석형 문제로 별도 서버나 Docker 이미지는 없다. 플랫폼의 비공개
`Challenge File`에는 다음 파일을 하나의 ZIP으로 묶어 제출한다.

- [prob.py](prob.py): 다섯 플랫폼 아카이브 및 공개 ZIP 생성기
- [solve.py](solve.py): FLAG 획득 PoC
- [audit.py](audit.py): 후보 구조·문장 빈도·압축 지름길 감사
- [README.md](README.md): 상세 풀이와 설계 기록
- [SUBMISSION.md](SUBMISSION.md): 제출 양식용 문서

이 ZIP은 정답 체인과 FLAG를 포함하므로 공개하지 않는다.

### Challenge Public File (zip)

- 파일: [dist/alias-chain.zip](dist/alias-chain.zip)
- SHA-256: `7e7f1ffa72a9ef18b5a89fe980416ddc863ea3d84ba4758b068325faf955ee37`
- 구성: `GUIDE.txt`, `START_PROFILE.txt`, BLOG/REVIEWS/TRAVEL/MARKET/SOCIAL 아카이브

플레이어에게는 이 ZIP만 제공한다.
