# murthehelp 언인텐 검토

| 후보 | 판정 | 근거 |
| --- | --- | --- |
| 서명 없이 등급 조작 | PASS | `BAD_SIGNATURE`. r=0, s=0, 길이 불일치 모두 거부. |
| 등급 문자열 우회 (공백/대소문자) | PASS | `GRADES` 배열 정확 일치만 통과. `BAD_GRADE`. |
| 옐로코드로 `/label` 접근 | PASS | 403 `GRADE_REQUIRED`. |
| 점 / 대괄호 접근 | PASS | 토크나이저가 문자 단위로 거부. |
| 허용 목록 밖 함수 호출 | PASS | `eval`, `require`, `Function` 모두 거부. |
| 전역 객체 이름 참조 | PASS | `process`, `global` 은 스코프에 없어 거부. |
| 네임스페이스 외 다른 탈출 경로 | 해당 없음 | `upper:`, `today:`, `grade:`, `concat:` 등 여러 진입점이 있으나 전부 같은 구멍의 변형이다. 의도된 풀이의 동치. |
| 영수증 응답에 플래그 유출 | PASS | 확인함. |
| 플래그 고정 경로 | PASS | 기동 시 `/flag-<24hex>.txt` 로 랜덤화. `process.env.FLAG_PATH` 를 읽어야 한다. |
| nonce 충돌 재현 불가 | PASS | 공식 익스 5회 연속 성공, 각 1초. |

## 운영 주의

발행 키와 nonce 시드는 프로세스 기동 시 생성된다. 컨테이너를 재시작하면
참가자가 복구해 둔 개인키가 무효가 되어 처음부터 다시 해야 한다.
대회 중에는 재시작하지 않는다.
