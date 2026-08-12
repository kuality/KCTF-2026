#!/usr/bin/env python3
"""
지름길 감사 (출제자 전용, 배포물에는 포함하지 않는다).

이 문제의 핵심 위험은 "풀린다" 가 아니라 "너무 싸게 풀린다" 는 것이다.
블라인드 검증에서 이미 두 번 걸렸다.

  1차: 첨부 보유(66) -> In-Reply-To 존재(1).      불리언 두 개로 끝
  2차: 수신자 2명 이상 AND 전원 사내 -> 1통.       역시 불리언 두 개

둘 다 사람이 눈으로 찾아낸 것이고, 그래서 매번 다른 걸 놓쳤다.
이 스크립트는 값싼 불리언 속성을 전부 나열하고 **1개짜리와 2개 조합을 전수 검사** 해서
정확히 1통을 남기는 것이 있는지 기계적으로 찾는다.

의도된 경로(그래프 불변식)는 여기 넣지 않는다 — 그건 남아야 하는 정답이다.
"""

import itertools
import os
import re
from collections import Counter
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import solve

CORP = "norite-systems.com"


def body_text(m) -> str:
    for part in m.walk():
        if part.get_content_type() == "text/plain" and not part.get_filename():
            try:
                return part.get_payload(decode=True).decode("utf-8", "ignore")
            except Exception:
                return ""
    return ""


def properties(mails, by_mid, parent):
    """값싸게 계산되는 불리언 속성들. 플레이어가 한 줄로 쓸 만한 것만."""
    def rcpts(m):
        return [a.strip() for a in str(m["To"] or "").split(",") if a.strip()]

    def subj(m):
        s = str(m["Subject"] or "")
        return s[4:] if s.startswith("Re: ") else s

    internal_subjects = {subj(m) for m in mails.values()
                         if solve.domain_of(m["From"]) == CORP}
    corp_like = ("norite", "systems", "sytems", "systerns")

    return {
        "첨부 보유": lambda fn, m: m.get_content_maintype() == "multipart",
        "In-Reply-To 있음": lambda fn, m: bool(m["In-Reply-To"]),
        "In-Reply-To 해석됨": lambda fn, m: (m["In-Reply-To"] or "").strip() in by_mid,
        "References 없음": lambda fn, m: not m["References"],
        "References 가 1개": lambda fn, m: len(str(m["References"] or "").split()) == 1,
        "발신 도메인 외부": lambda fn, m: solve.domain_of(m["From"]) != CORP,
        "발신 도메인 사내유사": lambda fn, m: (
            solve.domain_of(m["From"]) != CORP
            and any(k in solve.domain_of(m["From"]) for k in corp_like)),
        "외부 Received 홉": lambda fn, m: solve.is_external(m),
        "spf=fail": lambda fn, m: "spf=fail" in str(m["Authentication-Results"]),
        "수신자 2명 이상": lambda fn, m: len(rcpts(m)) > 1,
        "수신자 전원 사내": lambda fn, m: bool(rcpts(m)) and all(
            solve.domain_of(a) == CORP for a in rcpts(m)),
        "수신자에 외부 포함": lambda fn, m: any(
            solve.domain_of(a) != CORP for a in rcpts(m)),
        "제목이 Re:": lambda fn, m: str(m["Subject"] or "").startswith("Re: "),
        "제목이 사내 스레드 제목": lambda fn, m: subj(m) in internal_subjects,
        "스팸점수 2.0 이상": lambda fn, m: float(
            m["X-Norite-Spam-Score"] or 0) >= 2.0,
        "본문에 한글": lambda fn, m: any("가" <= c <= "힣" for c in body_text(m)),
        "본문이 영문뿐": lambda fn, m: not any(
            "가" <= c <= "힣" for c in body_text(m)),
    }


def main():
    global d
    d = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "dist", "inbox-triage", "maildump")
    mails = solve.load(d)
    by_mid, parent = solve.build_graph(mails)

    hits = solve.find_hijack(mails, by_mid, parent, verbose=False)
    if len(hits) != 1:
        print(f"[!] 정답이 {len(hits)}통 — 감사 이전에 문제가 있다")
        return 1
    answer = hits[0][0]
    print(f"정답: {answer}\n")

    props = properties(mails, by_mid, parent)
    sets = {}
    for name, fn_ in props.items():
        sets[name] = {fn for fn, m in mails.items() if fn_(fn, m)}

    print(f"{'속성':<28} 해당 통수")
    for name, s in sets.items():
        print(f"  {name:<26} {len(s):>4}")

    print("\n--- 단일 속성으로 1통이 되는가 ---")
    bad = []
    for name, s in sets.items():
        if len(s) == 1 and answer in s:
            bad.append((name,))
            print(f"  !! {name}")
    if not bad:
        print("  없음")

    print("\n--- 두 속성 조합(AND)으로 1통이 되는가 ---")
    pair_bad = []
    for a, b in itertools.combinations(sets, 2):
        inter = sets[a] & sets[b]
        if len(inter) == 1 and answer in inter:
            pair_bad.append((a, b))
            print(f"  !! {a}  AND  {b}")
    if not pair_bad:
        print("  없음")

    # --- 유일값 감사
    #
    # 불리언 조합 감사로는 안 잡히는 종류가 따로 있다. 어떤 파생값이 정답에서만
    # 유일하면 그 값으로 군집화하는 것만으로 정답이 특정된다.
    # 실제로 두 번 걸렸다:
    #   - X-Norite-Spam-Score 헤더가 정답에서만 맨 뒤에 직렬화됨 (생성기 버그)
    #   - 미끼 65통이 고정 템플릿 2개를 반복해 정답 본문만 유일했음
    print("\n--- 어떤 파생값이 정답에서만 유일한가 ---")
    raws = {}
    for fn in sorted(os.listdir(d)):
        if fn.endswith(".eml"):
            raws[fn] = open(os.path.join(d, fn), "rb").read()

    def hdr_order(b):
        head = b.split(b"\n\n")[0]
        return tuple(l.split(b":")[0] for l in head.split(b"\n")
                     if re.match(rb"^[A-Za-z-]+:", l))

    derived = {
        "헤더 키 순서": lambda fn: hdr_order(raws[fn]),
        "헤더 개수": lambda fn: len(re.findall(rb"^[A-Za-z-]+:", raws[fn], re.M)),
        "본문 앞 60자": lambda fn: body_text(mails[fn])[:60],
        "제목": lambda fn: str(mails[fn]["Subject"]),
        "발신 주소": lambda fn: solve.addr_of(mails[fn]["From"]),
        "발신 도메인": lambda fn: solve.domain_of(mails[fn]["From"]),
        "외부 IP 대역": lambda fn: (m.group(1).decode().rsplit(".", 1)[0]
                                if (m := re.search(rb"\[([\d.]+)\]", raws[fn]))
                                else ""),
        "첨부 파일명": lambda fn: next(
            (p.get_filename() for p in mails[fn].walk() if p.get_filename()), ""),
        "MIME boundary 길이": lambda fn: len(m.group(1)) if (
            m := re.search(rb'boundary="([^"]+)"', raws[fn])) else 0,
        "메일 바이트수": lambda fn: len(raws[fn]),
        "수신자 수": lambda fn: len(str(mails[fn]["To"] or "").split(",")),
    }
    # 전체 600통 기준과 첨부 보유 66통 기준을 모두 본다
    scopes = {"전체 600통": set(mails), "첨부 보유": {
        fn for fn, m in mails.items() if m.get_content_maintype() == "multipart"}}
    # 판정 기준: '정답의 값이 유일한가' 만으로는 부족하다. 본문처럼 원래 전부
    # 제각각인 필드는 600통이 모두 유일하므로 단서가 되지 않는다.
    # 진짜 단서는 **정답만 유일한 경우** — 즉 그 필드의 유일값 개수가 아주 적을 때다.
    unique_hits = []
    for scope_name, scope in scopes.items():
        for name, f in derived.items():
            c = Counter(f(fn) for fn in scope)
            singletons = sum(1 for v in c.values() if v == 1)
            if c[f(answer)] == 1 and singletons <= 3 and len(scope) > 1:
                unique_hits.append((scope_name, name))
                print(f"  !! [{scope_name}] {name} — 유일값이 {singletons}개뿐이고 "
                      f"그중 하나가 정답이다")
    if not unique_hits:
        print("  없음")

    print("\n--- 세 속성 조합(AND)으로 1통이 되는가 ---")
    tri = 0
    for a, b, c in itertools.combinations(sets, 3):
        inter = sets[a] & sets[b] & sets[c]
        if len(inter) == 1 and answer in inter:
            tri += 1
            if tri <= 8:
                print(f"  ~  {a}  AND  {b}  AND  {c}")
    print(f"  총 {tri}건 (3개까지는 어느 정도 허용 — 사실상 불변식에 근접한다)")

    print()
    if bad or pair_bad:
        print(">> 지름길이 있다. 미끼에 같은 속성을 부여해 막아야 한다.")
        return 1
    print(">> 불리언 1~2개로는 특정되지 않는다.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
