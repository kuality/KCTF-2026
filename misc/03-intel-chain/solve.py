#!/usr/bin/env python3
"""
KCTF 2026 MISC — intel-chain / 레퍼런스 솔버

  python3 solve.py dist/intel-chain

체인 4단계. 각 단계가 자기검증적이라 어디서 틀렸는지 즉시 안다.

  1) 리포트 PDF p.6 (스캔) OCR   -> Wave 3 샘플 SHA256
  2) 샌드박스 JSON               -> 그 해시의 C2 도메인 (고정 간격 비콘으로 식별)
  3) IOC CSV                     -> 그 도메인의 first_seen
  4) 트래픽 요약                 -> 그 시각의 세션 페이로드
     리포트 PDF p.7 (스캔) OCR   -> Wave 3 기법 ID
     -> MATERIAL = TECH|C2DOMAIN|FIRSTSEEN, key = SHA256(MATERIAL)
"""

import base64
import csv
import hashlib
import io
import json
import os
import re
import sys
from collections import Counter
from datetime import datetime

import pypdf
import pytesseract
from PIL import Image


# ------------------------------------------------------------ OCR

def ocr_scanned_pages(pdf_path):
    """텍스트 추출이 안 되는 페이지만 골라 OCR 한다."""
    r = pypdf.PdfReader(pdf_path)
    out = {}
    for i, page in enumerate(r.pages):
        if len(page.extract_text().strip()) > 20:
            continue                       # 벡터 텍스트 페이지
        for img in page.images:
            im = Image.open(io.BytesIO(img.data)).convert("L")
            im = im.resize((im.width * 2, im.height * 2), Image.LANCZOS)
            out[i + 1] = pytesseract.image_to_string(im, config="--psm 6")
    return out


def pdf_text(pdf_path):
    r = pypdf.PdfReader(pdf_path)
    return "\n".join(p.extract_text() for p in r.pages)


# ------------------------------------------------------------ 1단계

def wave3_hash(scans, sandbox_hashes):
    """
    스캔 페이지에서 Wave 3 행의 SHA256 을 읽는다.

    64자를 완벽히 OCR 할 필요는 없다. 샌드박스 리포트가 3개뿐이라
    앞부분 몇 글자만 맞아도 유일하게 결정된다 — 이게 자기검증 지점이다.
    """
    for pageno, text in scans.items():
        lines = text.splitlines()
        for n, ln in enumerate(lines):
            if not re.match(r"^\s*3\s+\d{4}-\d{2}-\d{2}", ln):
                continue
            frag = "".join(re.findall(r"[0-9a-fA-F]{16,}", ln + " " +
                                      (lines[n + 1] if n + 1 < len(lines) else "")))
            best = [h for h in sandbox_hashes
                    if _prefix_score(h, frag.lower()) >= 12]
            if len(best) == 1:
                return best[0], frag
    return None, None


def _prefix_score(full, frag):
    n = 0
    for a, b in zip(full, frag):
        if a != b:
            break
        n += 1
    return n


# ------------------------------------------------------------ 2단계

def find_c2(report):
    """
    C2 는 요청 횟수가 아니라 **고정 간격 비콘** 으로 식별한다.
    (텔레메트리 도메인이 요청 수는 더 많다 — 리포트가 명시적으로 경고한다)
    """
    by_host = {}
    for e in report["network"]["http"]:
        by_host.setdefault(e["host"], []).append(
            datetime.fromisoformat(e["ts"]))
    best = None
    for host, ts in by_host.items():
        if len(ts) < 5:
            continue
        ts.sort()
        gaps = [(b - a).total_seconds() for a, b in zip(ts, ts[1:])]
        common, cnt = Counter(gaps).most_common(1)[0]
        ratio = cnt / len(gaps)
        if ratio > 0.9:                     # 간격이 거의 일정하다
            best = (host, common, len(ts))
    return best


# ------------------------------------------------------------ main

def solve(root):
    pdf = os.path.join(root, "BLUEHERON_TLPCLEAR_2026Q1.pdf")

    print("[1] 리포트 스캔 페이지 OCR")
    scans = ocr_scanned_pages(pdf)
    print(f"      스캔 페이지 {sorted(scans)} (텍스트 추출 불가 -> OCR 필요)")

    sb_dir = os.path.join(root, "sandbox")
    reports = {}
    for fn in sorted(os.listdir(sb_dir)):
        rep = json.load(open(os.path.join(sb_dir, fn)))
        reports[rep["target"]["file"]["sha256"]] = (fn, rep)

    sha, frag = wave3_hash(scans, list(reports))
    if not sha:
        print("[!] Wave 3 해시를 못 읽었다")
        return None
    print(f"      Wave 3 SHA256 (OCR) : {frag}")
    print(f"      샌드박스와 일치      : {sha}")

    fn, rep = reports[sha]
    print(f"\n[2] 샌드박스 {fn} 에서 C2 식별")
    for d in rep["network"]["domains"]:
        print(f"      {d['domain']:<28} requests={d['requests']}")
    host, gap, n = find_c2(rep)
    print(f"      -> C2: {host}  ({gap:.0f}초 고정 간격 비콘 {n}회)")
    print(f"         요청 수 1위가 아니다 — 리포트가 경고한 함정")

    print("\n[3] IOC CSV 에서 first_seen")
    hits = []
    with open(os.path.join(root, "iocs.csv")) as f:
        rows = list(csv.DictReader(f))
    similar = [r for r in rows if "cdn" in r["indicator"] and "sync" in r["indicator"]]
    for r in similar:
        mark = "  <-" if r["indicator"] == host else ""
        print(f"      {r['indicator']:<28} {r['first_seen']}  {r['confidence']}{mark}")
        if r["indicator"] == host:
            hits.append(r)
    if len(hits) != 1:
        print(f"[!] 정확 일치가 {len(hits)}건")
        return None
    first_seen = hits[0]["first_seen"]

    print("\n[4] 트래픽 요약에서 해당 시각 세션")
    lines = open(os.path.join(root, "traffic_summary.txt")).read().splitlines()
    payload = None
    for i, ln in enumerate(lines):
        if ln.startswith(first_seen) and host in ln:
            print(f"      {ln.strip()}")
            m = re.search(r"payload\(b64\):\s*(\S+)", lines[i + 1])
            if m:
                payload = m.group(1)
    if not payload:
        print("[!] 페이로드를 못 찾았다")
        return None
    total_payloads = sum(1 for ln in lines if "payload(b64)" in ln)
    print(f"      (전체 payload 라인 {total_payloads}개 중 이 한 줄)")

    print("\n[5] ATT&CK 매핑에서 키 재료")
    tech = []
    for text in scans.values():
        for tid, waves in re.findall(r"(T\d{4})\s+.*?waves\s+([\d\s]+)", text):
            if "3" in waves.split():
                tech.append(tid)
    if not tech:
        print("[!] ATT&CK 표를 못 읽었다")
        return None
    tech_str = "".join(tech)
    print(f"      Wave 3 매핑 기법: {tech}  -> {tech_str}")

    material = f"{tech_str}|{host}|{first_seen}"
    print(f"      MATERIAL = {material}")

    key = hashlib.sha256(material.encode()).digest()
    cipher = base64.b64decode(payload)
    ks, i = b"", 0
    while len(ks) < len(cipher):
        ks += hashlib.sha256(key + str(i).encode()).digest()
        i += 1
    plain = bytes(a ^ b for a, b in zip(cipher, ks))
    try:
        text = plain.decode()
    except UnicodeDecodeError:
        print("[!] 복호 실패 — 키 재료가 틀렸다")
        return None
    return text if text.startswith("KCTF{") else None


if __name__ == "__main__":
    d = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "dist", "intel-chain")
    flag = solve(d)
    print("\n" + "=" * 55)
    print("FLAG:", flag if flag else "실패")
