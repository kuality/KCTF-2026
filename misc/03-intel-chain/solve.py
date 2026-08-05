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
import time
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

def wave3_loader(scans):
    """
    스캔 페이지에서 Wave 3 행의 로더 계열명을 읽는다.

    조인 키로 SHA256 을 쓰지 않는 이유: 64자 hex 는 OCR 이 0/O, 1/l, 5/S 를
    계속 틀린다. 4글자씩 끊어 적어도 01dd -> Oldd, 5cfa -> Scfa 로 깨졌다.
    반면 'kelphook.loader' 같은 단어는 정확히 읽힌다.
    (문제 1에서 얻은 교훈과 같다 — 화이트리스트/문맥이 있는 토큰이 강하다)

    wave 3 과 wave 4 가 둘 다 kelphook 계열이라, 리포트 서술만으로는 안 되고
    스캔 페이지의 wave -> loader 매핑을 실제로 읽어야 한다.
    """
    for text in scans.values():
        for ln in text.splitlines():
            m = re.search(r"wave\s*3\s+\d{4}-\d{2}-\d{2}\s+(\S+)", ln)
            if m:
                return m.group(1).strip()
    return None


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
    for f_ in sorted(os.listdir(sb_dir)):
        rep = json.load(open(os.path.join(sb_dir, f_)))
        reports[rep["target"]["file"]["family"]] = (f_, rep)

    loader = wave3_loader(scans)
    if loader not in reports:
        print(f"[!] Wave 3 로더를 못 읽었다 (읽은 값: {loader!r})")
        return None
    print(f"      Wave 3 로더 (OCR) : {loader}")
    print(f"      샌드박스 후보      : {sorted(reports)}")

    fn, rep = reports[loader]
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

    print("\n[4] 트래픽 요약에서 C2 도메인 세션")
    # 시각이 아니라 도메인으로 찾는다. first_seen 은 IOC 등재 시각이지
    # 유출 세션 시각이 아니다 — 둘을 같게 두면 payload 자기 위의 세션 라인만으로
    # 키 재료가 조립되어 샌드박스와 CSV 가 통째로 우회된다.
    lines = open(os.path.join(root, "traffic_summary.txt")).read().splitlines()
    payload = None
    for i, ln in enumerate(lines):
        if host in ln and "payload" not in ln:
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
    # OCR 이 ID 를 흘릴 때를 대비한 정규화. 실제로 T1071 이 T1LO71 로 읽힌 적이 있다.
    # 기법 이름은 안정적으로 읽히므로 이름을 함께 잡아 검증 근거로 남긴다.
    def norm_tid(raw):
        digits = raw[1:].translate(str.maketrans("OolIiSsBb", "001115588"))
        digits = re.sub(r"\D", "", digits)
        return "T" + digits[-4:] if len(digits) >= 4 else None

    # ATT&CK 표는 벡터 텍스트 페이지에 있다 (스캔이 아니다).
    # 출제 단계에서 T1071 의 OCR 정확도가 최선 4/8 로 측정되어, 필수값을
    # 스캔에 두지 않기로 한 결과다. OCR 은 p.6 의 웨이브->로더 매핑에서 필요하다.
    tech = []
    for text in [pdf_text(pdf)] + list(scans.values()):
        for raw, name, waves in re.findall(
                r"(T[0-9A-Za-z]{4,6})\s+([A-Za-z][A-Za-z0-9 &]+?)\s+waves\s+([\d\s]+)",
                text):
            tid = norm_tid(raw)
            if tid and "3" in waves.split():
                tech.append(tid)
                if tid != raw:
                    print(f"      OCR 보정: {raw} -> {tid}  ({name.strip()})")
    if not tech:
        print("[!] ATT&CK 표를 못 읽었다")
        return None
    tech_str = "".join(tech)
    print(f"      Wave 3 매핑 기법: {tech}  -> {tech_str}")

    sample_sha = rep["target"]["file"]["sha256"]
    material = f"{tech_str}|{host}|{first_seen}|{sample_sha}"
    print(f"      MATERIAL = {material}")

    # 반복 해시 KDF. 정직한 솔버는 후보가 1개라 0.3초면 끝나지만,
    # 무차별 대입은 후보가 10^4~10^6 개라 며칠이 된다.
    t0 = time.time()
    h = material.encode()
    for _ in range(12_000_000):
        h = hashlib.sha256(h).digest()
    key = h
    print(f"      KDF 12,000,000회 -> {time.time() - t0:.2f}초")
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
