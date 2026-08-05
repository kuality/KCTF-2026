#!/usr/bin/env python3
"""
KCTF 2026 MISC — intel-chain
문제 생성기.

이종 문서 4종을 교차 상관분석해 유출 페이로드를 복호하는 위협 인텔리전스 문제.

설계 요점 (SPEC.md 참조):

  1. 어떤 단일 문서도 답을 담지 않는다. 4개를 전부 조인해야 한다.
       리포트 PDF  -> Wave 3 샘플 SHA256
       샌드박스 JSON -> 그 해시의 C2 도메인 (비콘 주기로 식별)
       IOC CSV     -> 그 도메인의 first_seen 타임스탬프
       트래픽 요약  -> 그 시각의 세션 페이로드
       리포트 PDF  -> ATT&CK 기법 ID 시퀀스 = 복호 키 재료

  2. 반복키 XOR 을 쓰지 않는다.
     초안은 base64 -> 15글자 반복키 XOR 이었고 평문이 KCTF{ 로 시작했다.
     이러면 traffic_summary 에서 payload 를 전부 뽑아 crib-drag 하는 것만으로
     PDF 도 JSON 도 CSV 도 열지 않고 플래그가 나온다 — 4단계가 통째로 무의미해진다.
     -> key = SHA256("T1566T1059T1071") 로 유도한 스트림 암호를 쓴다.

  3. 서브테크닉 번호(.001)를 리포트 어디에도 쓰지 않는다.
     T1566.001 이 표에 있으면 "T1566T1059T1071" 과 "T1566.001T1059.001..." 두 가지
     연결 방식이 똑같이 그럴듯해져서 출제자 마음 맞히기가 된다.
     베이스 기법 ID 만 쓰고, 연결 규칙을 리포트 본문에 명시한다.

  4. 매 단계가 자기검증적이다.
     잘못된 wave 를 고르면 그 해시를 가진 샌드박스 리포트가 없다. 즉시 안다.
     이게 없으면 "어디서 틀렸는지 모르는" MED 가 HARD 로 변한다.

  5. 실제 IOC 를 쓰지 않는다.
     IP 는 RFC 5737 (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24),
     도메인은 example.* 계열. 솔버가 실제로 찔러보는 사고를 막는다.
"""

import csv
import hashlib
import io
import json
import os
import random
import shutil
import zipfile
from datetime import datetime, timedelta, timezone

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.pdfgen import canvas as pdfcanvas
from PIL import Image, ImageDraw, ImageFilter, ImageFont
import numpy as np

FLAG = "KCTF{cr0ss_d0c_c0rr3l4t10n_1s_th3_j0b}"

SEED = 20260314
HERE = os.path.dirname(os.path.abspath(__file__))
DIST = os.path.join(HERE, "dist")
OUT = os.path.join(DIST, "intel-chain")

UTC = timezone.utc

CAMPAIGN = "BLUEHERON"
C2_DOMAIN = "cdn-sync.example.net"
C2_IP = "198.51.100.77"
VICTIM_IP = "192.0.2.51"
FIRST_SEEN = datetime(2026, 3, 14, 9, 21, 44, tzinfo=UTC)

# Wave 3 에 매핑된 기법 ID. 표 순서대로 이어붙인다.
WAVE3_TECHNIQUES = ["T1566", "T1059", "T1071"]
TECH_STRING = "".join(WAVE3_TECHNIQUES)
FIRST_SEEN_STR = FIRST_SEEN.strftime("%Y-%m-%dT%H:%M:%SZ")

# 키 재료는 문서 3종에서 각각 하나씩 가져와 조립한다.
#
#   기법 문자열   <- 리포트 PDF (스캔 페이지, OCR 필요)
#   C2 도메인     <- 샌드박스 JSON (비콘 주기로 식별)
#   first_seen    <- IOC CSV (유사 도메인 다수, 정확 일치 필요)
#
# 기법 문자열만으로 키가 정해지면 페이로드 153개 x 기법 조합 수백 개 =
# 2만 회 미만의 무차별 대입으로 샌드박스와 CSV 단계를 건너뛸 수 있다.
# 세 문서를 묶어야 그 경로가 죽고 체인이 실제로 하중을 받는다.
KEY_MATERIAL = f"{TECH_STRING}|{C2_DOMAIN}|{FIRST_SEEN_STR}"

FONT_MONO = "/System/Library/Fonts/Supplemental/Courier New.ttf"
FONT_MONO_B = "/System/Library/Fonts/Supplemental/Courier New Bold.ttf"


def sha256_of(tag: str) -> str:
    return hashlib.sha256(f"{CAMPAIGN}-{tag}-{SEED}".encode()).hexdigest()


WAVES = [
    {"n": 1, "date": "2026-01-09", "hash": sha256_of("w1"),
     "name": "sandbar.dropper.a", "note": "initial access via macro attachment"},
    {"n": 2, "date": "2026-02-02", "hash": sha256_of("w2"),
     "name": "sandbar.dropper.b", "note": "reused wave 1 infrastructure"},
    {"n": 3, "date": "2026-03-11", "hash": sha256_of("w3"),
     "name": "kelphook.loader", "note": "C2 infrastructure fully rotated"},
    {"n": 4, "date": "2026-04-05", "hash": sha256_of("w4"),
     "name": "kelphook.loader.v2", "note": "persistence module added"},
]
WAVE3 = WAVES[2]

ATTACK_TABLE = [
    ("T1566", "Phishing", "1, 3"),
    ("T1204", "User Execution", "1, 2"),
    ("T1059", "Command and Scripting Interpreter", "3"),
    ("T1547", "Boot or Logon Autostart Execution", "2, 4"),
    ("T1071", "Application Layer Protocol", "3, 4"),
    ("T1041", "Exfiltration Over C2 Channel", "4"),
]


# ---------------------------------------------------------------- 암호

def keystream(key: bytes, n: int) -> bytes:
    out, i = b"", 0
    while len(out) < n:
        out += hashlib.sha256(key + str(i).encode()).digest()
        i += 1
    return out[:n]


def encrypt(plain: bytes, key_material: str) -> bytes:
    key = hashlib.sha256(key_material.encode()).digest()
    return bytes(a ^ b for a, b in zip(plain, keystream(key, len(plain))))


# ---------------------------------------------------------------- PDF

def scan_page(text_lines, path, rng):
    """
    스캔 이미지 페이지. 텍스트 추출이 안 되고 OCR 이 필요하다.
    (문제 1의 능력 재활용 — 카테고리 안에서 연결감을 준다)
    """
    W, H = 1240, 1754          # A4 150dpi
    img = Image.new("L", (W, H), 247)
    d = ImageDraw.Draw(img)

    # 종이 질감
    a = np.asarray(img, dtype=np.float32)
    a += np.random.default_rng(rng.getrandbits(63)).normal(0, 2.2, a.shape)
    img = Image.fromarray(np.clip(a, 0, 255).astype(np.uint8), "L")
    d = ImageDraw.Draw(img)

    y = 120
    for line, size, bold in text_lines:
        f = ImageFont.truetype(FONT_MONO_B if bold else FONT_MONO, size)
        d.text((110, y), line, font=f, fill=rng.randint(28, 52))
        y += int(size * 1.75)

    img = img.rotate(rng.uniform(-0.5, 0.5), resample=Image.BICUBIC,
                     fillcolor=247)
    img = img.filter(ImageFilter.GaussianBlur(0.35))

    a = np.asarray(img, dtype=np.float32)
    a += np.random.default_rng(rng.getrandbits(63)).normal(0, 4.0, a.shape)
    img = Image.fromarray(np.clip(a, 0, 255).astype(np.uint8), "L")

    jb = io.BytesIO()
    img.save(jb, "JPEG", quality=72)
    jb.seek(0)
    return Image.open(jb).convert("L")


def build_pdf(path, rng):
    c = pdfcanvas.Canvas(path, pagesize=A4)
    W, H = A4

    def head(title, page):
        c.setFont("Helvetica-Bold", 9)
        c.drawString(20 * mm, H - 15 * mm, f"TLP:CLEAR  |  {CAMPAIGN}  |  2026 Q1")
        c.setFont("Helvetica", 8)
        c.drawRightString(W - 20 * mm, H - 15 * mm, f"p.{page}")
        c.setFont("Helvetica-Bold", 15)
        c.drawString(20 * mm, H - 30 * mm, title)
        c.setFont("Helvetica", 10)

    def para(lines, y0):
        y = y0
        for ln in lines:
            c.drawString(20 * mm, y, ln)
            y -= 5.6 * mm
        return y

    # --- p.1 표지
    c.setFont("Helvetica-Bold", 22)
    c.drawString(20 * mm, H - 60 * mm, f"{CAMPAIGN} Campaign Report")
    c.setFont("Helvetica", 11)
    para(["Threat Intelligence Report / TLP:CLEAR",
          "Norite Systems CTI Team",
          "Published 2026-04-18",
          "",
          "All indicators in this document are synthetic and do not refer to",
          "real infrastructure. Addresses use RFC 5737 documentation ranges",
          "and domains use the example.* reserved namespace."],
         H - 80 * mm)
    c.showPage()

    # --- p.2~5 서술
    narrative = [
        ("Executive Summary", [
            f"{CAMPAIGN} comprises four attack waves observed between January",
            "and April 2026. The first two waves reused the same command and",
            "control infrastructure. Beginning with the THIRD wave, the C2",
            "infrastructure was rotated completely.",
            "",
            "The loader family changed at the same point, from sandbar to",
            "kelphook. This report focuses on the third wave.",
        ]),
        ("Infrastructure", [
            "Wave 1 and 2 C2 nodes were concentrated at a single hosting",
            "provider. From wave 3 onward the operators moved to CDN-style",
            "domain naming, and beacons are emitted at a fixed interval.",
            "",
            "When identifying the C2 in sandbox dynamic analysis, do NOT rank",
            "by request count. Telemetry and update endpoints frequently",
            "generate more requests than the C2 does. The discriminator is the",
            "fixed-interval beacon pattern in the HTTP timestamps.",
        ]),
        ("Detection Notes", [
            "The IOC list ships as a separate CSV. Consult the confidence",
            "column, but note that several look-alike domains carry the same",
            "campaign label. Exact string matching is required.",
            "",
            "In the network session summary, exfiltration payloads are base64",
            "encoded and protected by a stream cipher.",
        ]),
        ("Payload Protection", [
            "The wave 3 loader protects exfiltrated data as follows.",
            "",
            "  key       = SHA256( MATERIAL )",
            "  keystream = SHA256( key + str(i) ) concatenated for i = 0,1,2,...",
            "  plain[j]  = cipher[j] XOR keystream[j]",
            "",
            "MATERIAL is three fields joined with the ASCII pipe character:",
            "",
            "  MATERIAL = TECH + \"|\" + C2DOMAIN + \"|\" + FIRSTSEEN",
            "",
            "  TECH       the ATT&CK technique IDs mapped to wave 3 in this",
            "             report, concatenated in the order they appear in the",
            "             mapping table, with no separator",
            "  C2DOMAIN   the C2 domain identified from the sandbox report of",
            "             the wave 3 sample",
            "  FIRSTSEEN  that domain\'s first_seen value from the IOC list,",
            "             verbatim (e.g. 2026-01-01T00:00:00Z, unquoted)",
            "",
            "This report does not use sub-technique numbers. Base technique",
            "IDs only.",
        ]),
    ]
    for i, (title, lines) in enumerate(narrative):
        head(title, i + 2)
        para(lines, H - 45 * mm)
        c.showPage()

    # --- p.6 Campaign Timeline (스캔 이미지)
    lines = [(f"{CAMPAIGN} Campaign Timeline", 30, True), ("", 12, False),
             ("Wave  Date        Loader              SHA256", 20, True)]
    for w in WAVES:
        lines.append((f"  {w['n']}   {w['date']}  {w['name']:<20}"
                      f"{w['hash'][:32]}", 18, False))
        lines.append((f"                                    {w['hash'][32:]}",
                      18, False))
    lines += [("", 14, False), ("Notes", 20, True)]
    for w in WAVES:
        lines.append((f"  Wave {w['n']}: {w['note']}", 18, False))

    img = scan_page(lines, None, rng)
    tmp = os.path.join(DIST, "_p6.png")
    img.save(tmp)
    c.drawImage(tmp, 0, 0, width=W, height=H)
    c.showPage()

    # --- p.7 ATT&CK 매핑 (스캔 이미지)
    lines = [("ATT&CK Technique Mapping", 30, True), ("", 12, False),
             ("Technique  Name                               Mapped waves", 20, True)]
    # 웨이브 열은 'waves 1 3' 처럼 단어를 앞에 붙여 적는다.
    # 짧은 토큰만 두면 OCR 이 무너진다 — '1, 3' 은 'AEN)' 로, '[1][3]' 은 '(1) [3]' 로
    # 읽혔고, 심지어 T1071 이 T1O71(O/0 혼동)로 나왔다.
    # 'waves' 라는 단어가 문맥을 주면 여섯 행 전부 정확히 읽힌다.
    for tid, name, waves in ATTACK_TABLE:
        lines.append((f"  {tid}      {name:<34} waves {waves.replace(', ', ' ')}",
                      18, False))
    lines += [("", 14, False),
              ("Rows are ordered by first observation.", 18, False),
              ("Sub-technique numbers are not used in this report.", 18, False)]

    img = scan_page(lines, None, rng)
    tmp7 = os.path.join(DIST, "_p7.png")
    img.save(tmp7)
    c.drawImage(tmp7, 0, 0, width=W, height=H)
    c.showPage()

    c.save()
    os.remove(tmp)
    os.remove(tmp7)


# ---------------------------------------------------------------- 샌드박스

def sandbox_report(rng, sha, verdict_domains, beacon_domain, rid):
    """
    Cuckoo 유사 포맷. C2 는 요청 횟수가 아니라 고정 간격 비콘으로 식별된다.
    (요청 횟수만 보면 텔레메트리 도메인이 더 많다 — 함정)
    """
    t0 = datetime(2026, 3, 12, 4, 11, 0, tzinfo=UTC)
    http = []
    for dom, cnt, beacon in verdict_domains:
        if beacon:
            for k in range(cnt):
                http.append({
                    "ts": (t0 + timedelta(seconds=60 * k)).isoformat(),
                    "host": dom, "method": "POST", "uri": "/api/v2/sync",
                    "status": 200, "resp_len": rng.randint(120, 180)})
        else:
            for k in range(cnt):
                http.append({
                    "ts": (t0 + timedelta(seconds=rng.randint(0, 3600))).isoformat(),
                    "host": dom, "method": rng.choice(["GET", "POST"]),
                    "uri": rng.choice(["/v1/telemetry", "/update/check",
                                       "/ping", "/status"]),
                    "status": rng.choice([200, 200, 204, 304]),
                    "resp_len": rng.randint(80, 4000)})
    http.sort(key=lambda x: x["ts"])

    return {
        "report_id": rid,
        "analyzer": {"name": "norite-sandbox", "version": "3.4.1"},
        "target": {"file": {
            "name": rng.choice(["invoice_q1.docm", "update.exe", "setup.msi"]),
            "size": rng.randint(80000, 400000),
            "md5": hashlib.md5(sha.encode()).hexdigest(),
            "sha1": hashlib.sha1(sha.encode()).hexdigest(),
            "sha256": sha}},
        "signatures": [
            {"name": "creates_autorun_key", "severity": rng.randint(1, 3)},
            {"name": "network_http_post", "severity": 2},
            {"name": "obfuscated_powershell", "severity": 3},
        ],
        "network": {
            "domains": [{"domain": d, "requests": c}
                        for d, c, _ in verdict_domains],
            "hosts": [f"192.0.2.{rng.randint(2,250)}" for _ in range(3)],
            "http": http,
        },
        "behavior": {
            "processes": [
                {"pid": rng.randint(1000, 9000), "name": "winword.exe"},
                {"pid": rng.randint(1000, 9000), "name": "powershell.exe"},
            ],
            "files_written": [f"C:\\\\Users\\\\Public\\\\{rng.randrange(10**8):08x}.tmp"
                              for _ in range(4)],
        },
    }


# ---------------------------------------------------------------- 산출물

def build_iocs(rng, path):
    rows = [("indicator", "type", "campaign", "first_seen", "confidence")]
    noise_domains = [
        "cdn-sync.example.org", "cdn-sync2.example.net", "cdn-synk.example.net",
        "cdn-sync.example.com", "sync-cdn.example.net",
    ]
    entries = []
    for d in noise_domains:
        entries.append((d, "domain", CAMPAIGN,
                        (FIRST_SEEN + timedelta(days=rng.randint(-40, 40),
                                                seconds=rng.randint(0, 86400))
                         ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        rng.choice(["low", "medium", "high"])))
    entries.append((C2_DOMAIN, "domain", CAMPAIGN, FIRST_SEEN_STR, "high"))
    for _ in range(140):
        entries.append((
            f"{rng.choice(['api','cdn','mail','vpn','node','edge'])}-"
            f"{rng.randrange(10**5):05x}.example."
            f"{rng.choice(['com','net','org'])}",
            "domain", rng.choice([CAMPAIGN, "SANDPIPER", "MERLIN"]),
            (FIRST_SEEN + timedelta(days=rng.randint(-90, 90),
                                    seconds=rng.randint(0, 86400))
             ).strftime("%Y-%m-%dT%H:%M:%SZ"),
            rng.choice(["low", "medium", "high"])))
    for _ in range(54):
        entries.append((
            f"{rng.choice(['192.0.2','198.51.100','203.0.113'])}."
            f"{rng.randint(2,250)}", "ipv4",
            rng.choice([CAMPAIGN, "SANDPIPER", "MERLIN"]),
            (FIRST_SEEN + timedelta(days=rng.randint(-90, 90))
             ).strftime("%Y-%m-%dT%H:%M:%SZ"),
            rng.choice(["low", "medium", "high"])))
    rng.shuffle(entries)

    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(rows[0])
        w.writerows(entries)
    return len(entries)


def build_traffic(rng, path, cipher_b64):
    lines = ["# norite netflow / http session summary",
             "# generated 2026-04-16, all addresses are RFC 5737 documentation ranges",
             ""]
    n = 0
    base = FIRST_SEEN - timedelta(hours=6)
    events = []
    for i in range(2400):
        ts = base + timedelta(seconds=rng.randint(0, 43200))
        src = f"192.0.2.{rng.randint(2,250)}"
        dst = f"{rng.choice(['198.51.100','203.0.113'])}.{rng.randint(2,250)}"
        host = (f"{rng.choice(['api','cdn','mail','node'])}-"
                f"{rng.randrange(10**5):05x}.example."
                f"{rng.choice(['com','net','org'])}")
        payload = None
        if rng.random() < 0.06:
            payload = "".join(rng.choice(
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
                for _ in range(rng.randint(40, 90)))
        events.append((ts, src, dst, host, payload))

    events.append((FIRST_SEEN, VICTIM_IP, C2_IP, C2_DOMAIN, cipher_b64))
    events.sort(key=lambda e: e[0])

    for ts, src, dst, host, payload in events:
        lines.append(f"{ts.strftime('%Y-%m-%dT%H:%M:%SZ')}  "
                     f"{src}:{rng.randint(30000,60000)} -> {dst}:443  TLS  "
                     f"{host}  len={rng.randint(80, 900)}")
        if payload:
            lines.append(f"  payload(b64): {payload}")
            n += 1
    open(path, "w").write("\n".join(lines) + "\n")
    return len(events), n


# ---------------------------------------------------------------- main

def main():
    rng = random.Random(SEED)

    if os.path.isdir(DIST):
        shutil.rmtree(DIST)
    os.makedirs(os.path.join(OUT, "sandbox"))

    build_pdf(os.path.join(OUT, f"{CAMPAIGN}_TLPCLEAR_2026Q1.pdf"), rng)

    # 샌드박스 3종. Wave 3 해시를 가진 것은 하나뿐이다 (자기검증).
    specs = [
        (WAVES[0]["hash"], [("telemetry.example.com", 31, False),
                            ("update.example.org", 12, False),
                            ("static-a.example.net", 47, True)], "0442"),
        (WAVE3["hash"],    [("telemetry.example.com", 58, False),
                            ("update.example.org", 9, False),
                            ("ocsp.example.org", 23, False),
                            (C2_DOMAIN, 41, True)], "0517"),
        (WAVES[3]["hash"], [("telemetry.example.com", 44, False),
                            ("mirror.example.com", 19, False),
                            ("edge-7.example.net", 38, True)], "0603"),
    ]
    for sha, doms, rid in specs:
        rep = sandbox_report(rng, sha, doms, None, rid)
        with open(os.path.join(OUT, "sandbox", f"report_{rid}.json"), "w") as f:
            json.dump(rep, f, indent=2)

    n_ioc = build_iocs(rng, os.path.join(OUT, "iocs.csv"))

    import base64
    cipher = encrypt(FLAG.encode(), KEY_MATERIAL)
    cipher_b64 = base64.b64encode(cipher).decode()
    n_ev, n_pay = build_traffic(rng, os.path.join(OUT, "traffic_summary.txt"),
                                cipher_b64)

    zip_path = os.path.join(DIST, "intel-chain.zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for dirpath, _, files in os.walk(OUT):
            for fn in sorted(files):
                full = os.path.join(dirpath, fn)
                zf.write(full, os.path.relpath(full, DIST))

    print(f"배포물: {zip_path} ({os.path.getsize(zip_path)/1e6:.1f} MB)")
    print(f"  IOC 행         : {n_ioc}")
    print(f"  트래픽 이벤트  : {n_ev} (payload 보유 {n_pay})")
    print(f"  Wave3 SHA256   : {WAVE3['hash']}")
    print(f"  C2             : {C2_DOMAIN}  first_seen "
          f"{FIRST_SEEN.strftime('%Y-%m-%dT%H:%M:%SZ')}")
    print(f"  키 재료        : {KEY_MATERIAL}")
    print(f"FLAG: {FLAG}")


if __name__ == "__main__":
    main()
