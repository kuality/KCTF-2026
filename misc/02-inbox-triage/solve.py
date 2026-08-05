#!/usr/bin/env python3
"""
KCTF 2026 MISC — inbox-triage / 레퍼런스 솔버

  python3 solve.py dist/inbox-triage/maildump

파이프라인:
  1) 600통 파싱 -> Message-ID 그래프 구축
  2) 구조 불변식으로 하이재킹 메일 1통 특정
       답장이다 AND 스레드가 내부 전용이다 AND 발신자가 외부다
     (각 조건 단독으로는 후보가 여럿 남는다 — 교집합이 유일하다)
  3) 첨부 난독화 해제 -> 키 유도 방법 확인
  4) In-Reply-To 를 재귀적으로 거슬러 조상 체인(루트~부모) 전체를 복원
  5) 키 재료 = 조상 Message-ID 를 ',' 로 이어붙인 것 + '|' + 위조 도메인
  6) SHA256 카운터 모드 키스트림으로 복호 -> 플래그

키가 루트 하나가 아니라 체인 전체인 이유:
  루트 로컬파트만 쓰면 코퍼스의 Message-ID 600개 x 첨부 66개 = 39,600회 대입이
  0.1초에 끝난다. 블라인드 검증에서 실측되었고, 의도된 경로보다 싸다.
  조상 체인 전체는 조합적으로 열거할 수 없다.
"""

import email
import email.policy
import hashlib
import os
import re
import sys
from collections import defaultdict

CORP = "norite-systems.com"


# ------------------------------------------------------------ 파싱

def load(maildir):
    mails = {}
    for fn in sorted(os.listdir(maildir)):
        if not fn.endswith(".eml"):
            continue
        with open(os.path.join(maildir, fn), "rb") as f:
            m = email.message_from_binary_file(f, policy=email.policy.default)
        mails[fn] = m
    return mails


def addr_of(value):
    if not value:
        return ""
    m = re.search(r"<([^>]+)>", str(value))
    return (m.group(1) if m else str(value)).strip().lower()


def domain_of(value):
    a = addr_of(value)
    return a.split("@")[-1] if "@" in a else ""


def is_external(m):
    """Received 체인에 외부 홉이 있는가."""
    for r in m.get_all("Received", []):
        if "mx-edge" in r or "from unknown" in r:
            return True
    return False


# ------------------------------------------------------------ 그래프

def build_graph(mails):
    by_mid = {}
    for fn, m in mails.items():
        mid = (m["Message-ID"] or "").strip()
        if mid:
            by_mid[mid] = (fn, m)
    parent = {}
    for fn, m in mails.items():
        irt = (m["In-Reply-To"] or "").strip()
        if irt and irt in by_mid:
            parent[(m["Message-ID"] or "").strip()] = irt
    return by_mid, parent


def root_of(mid, parent):
    seen = set()
    while mid in parent and mid not in seen:
        seen.add(mid)
        mid = parent[mid]
    return mid


def thread_members(root, parent, by_mid):
    """루트를 공유하는 모든 메일."""
    out = []
    for mid, (fn, m) in by_mid.items():
        if root_of(mid, parent) == root:
            out.append((mid, m))
    return out


def participants(msgs):
    """
    스레드 참여자 = 발신자 + 수신자.

    발신자만 보면 안 된다. 벤더 스레드에서 벤더가 처음 답장하는 순간은
    '외부 발신자가 지금까지 내부 발신자만 있던 스레드에 답장' 이라 하이재킹과
    구조가 똑같아 보인다. 벤더는 애초에 루트의 To 에 들어 있는 정식 참여자다.
    """
    out = set()
    for m in msgs:
        out.add(domain_of(m["From"]))
        for hdr in ("To", "Cc"):
            v = m[hdr]
            if not v:
                continue
            for a in str(v).split(","):
                d = domain_of(a)
                if d:
                    out.add(d)
    return out


# ------------------------------------------------------------ 불변식

def find_hijack(mails, by_mid, parent, verbose=True):
    """
    구조 불변식:
      H 는 답장이다 (In-Reply-To 가 코퍼스 내 메일을 가리킨다)
      AND thread(H) - H 의 참여자(발신자+수신자)가 전원 사내 도메인이다
      AND From(H) 의 도메인이 사내 도메인이 아니다         [외부인]
    """
    replies = [(fn, m) for fn, m in mails.items()
               if (m["In-Reply-To"] or "").strip() in by_mid]
    outsiders = [(fn, m) for fn, m in mails.items()
                 if domain_of(m["From"]) != CORP]
    external_hop = [(fn, m) for fn, m in mails.items() if is_external(m)]

    hits = []
    for fn, m in replies:
        mid = (m["Message-ID"] or "").strip()
        root = root_of(mid, parent)
        others = [o for o_mid, o in thread_members(root, parent, by_mid)
                  if o_mid != mid]
        if not others:
            continue
        if participants(others) != {CORP}:
            continue                      # 내부 전용 스레드가 아니다
        if domain_of(m["From"]) == CORP:
            continue                      # 외부인이 아니다
        hits.append((fn, m, root))

    if verbose:
        print(f"[*] 전체 {len(mails)}통")
        print(f"      답장          : {len(replies)}통")
        print(f"      외부 도메인   : {len(outsiders)}통")
        print(f"      외부 Received : {len(external_hop)}통")
        print(f"      첨부 보유     : "
              f"{sum(1 for _, m in mails.items() if m.get_content_maintype() == 'multipart')}통")
        print(f"[*] 세 조건의 교집합: {len(hits)}통")
    return hits


# ------------------------------------------------------------ 첨부

def get_attachment(m):
    for part in m.walk():
        if part.get_filename():
            return part.get_filename(), part.get_payload(decode=True)
    return None, None


def deobfuscate(html: bytes) -> str:
    """1차 난독화: 문자코드 배열 -> 원본 JS."""
    m = re.search(rb"var _c=\[([0-9,\s]+)\]", html)
    if not m:
        return ""
    codes = [int(x) for x in m.group(1).split(b",") if x.strip()]
    return "".join(chr(c) for c in codes)


# ------------------------------------------------------------ 복호

def keystream(key: bytes, n: int) -> bytes:
    out, i = b"", 0
    while len(out) < n:
        out += hashlib.sha256(key + str(i).encode()).digest()
        i += 1
    return out[:n]


def decrypt(blob: bytes, key: str) -> bytes:
    ks = keystream(key.encode(), len(blob))
    return bytes(a ^ b for a, b in zip(blob, ks))


# ------------------------------------------------------------ main

def solve(maildir):
    mails = load(maildir)
    by_mid, parent = build_graph(mails)

    hits = find_hijack(mails, by_mid, parent)
    if len(hits) != 1:
        print(f"[!] 불변식을 만족하는 메일이 {len(hits)}통 — 1통이어야 한다")
        for fn, m, _ in hits:
            print(f"      {fn}  {m['From']}")
        return None

    fn, m, root = hits[0]
    print(f"[*] 하이재킹 메일: {fn}")
    print(f"      From    : {m['From']}")
    print(f"      Subject : {m['Subject']}")
    print(f"      In-Reply-To : {m['In-Reply-To']}")
    print(f"      References  : {m['References']}")
    print(f"                    ^ 부모 하나뿐이다. 루트는 여기 없다")

    spoof = domain_of(m["From"])
    print(f"[*] 위조 도메인: {spoof}  (정상: {CORP})")

    # 조상 체인을 루트까지 거슬러 올라간다.
    # 각 조상의 References 가 직전 부모 하나로 잘려 있어서, 한 번의 조회로는
    # 체인이 안 나온다. 실제로 재귀적으로 걸어야 한다.
    mid = (m["Message-ID"] or "").strip()
    chain = [mid]
    while chain[-1] in parent:
        chain.append(parent[chain[-1]])
    assert chain[-1] == root
    ancestors = list(reversed(chain[1:]))          # 루트 .. 부모
    print(f"[*] 조상 체인 {len(ancestors)}단계")
    for a in ancestors:
        print(f"      {a}")

    # 키 재료 = 조상 Message-ID 전체를 ',' 로 이어붙이고 '|' + 위조 도메인.
    # 루트 하나만 쓰면 코퍼스의 로컬파트 600개 x 첨부 66개 = 39,600회 대입으로
    # 0.1초 만에 뚫린다. 체인 전체는 조합적으로 열거할 수 없다.
    key = ",".join(ancestors) + "|" + spoof
    print(f"[*] 키: {key}")

    name, payload = get_attachment(m)
    print(f"[*] 첨부: {name}")
    js = deobfuscate(payload)
    blob = re.search(r"var blob = \[([0-9,\s]+)\]", js)
    if not blob:
        print("[!] 난독화 해제 실패")
        return None
    cipher = bytes(int(x) for x in blob.group(1).split(",") if x.strip())

    plain = decrypt(cipher, key)
    try:
        text = plain.decode()
    except UnicodeDecodeError:
        print("[!] 복호 실패 — 키가 틀렸다")
        return None
    return text if text.startswith("KCTF{") else None


if __name__ == "__main__":
    d = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "dist", "inbox-triage", "maildump")
    flag = solve(d)
    print("\n" + "=" * 50)
    print("FLAG:", flag if flag else "실패")
