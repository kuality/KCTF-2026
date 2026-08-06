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
FIRST_SEEN = datetime(2026, 3, 14, 9, 21, 44, tzinfo=UTC)   # IOC 등재 시각 (키 재료)
# 유출 세션은 다른 시각이다.
#
# 초안은 둘이 바이트 단위로 같았다. 그러면 payload 각각에 대해 '자기 바로 위
# 세션 라인의 도메인 + 타임스탬프' 를 키 재료로 넣고 기법 조합만 돌리면
# PDF p.5 와 traffic_summary.txt 만으로 1초 안에 뚫린다.
# 샌드박스도 IOC CSV 도 스캔 페이지도 전부 우회된다. (블라인드 검증 실측)
EXFIL_TS = datetime(2026, 3, 20, 2, 47, 11, tzinfo=UTC)

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

FONT_MONO = "/System/Library/Fonts/Supplemental/Courier New.ttf"
FONT_MONO_B = "/System/Library/Fonts/Supplemental/Courier New Bold.ttf"


def rand_ts(rng) -> str:
    return (FIRST_SEEN + timedelta(days=rng.randint(-90, 90),
                                   seconds=rng.randint(0, 86399))
            ).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_of(tag: str) -> str:
    return hashlib.sha256(f"{CAMPAIGN}-{tag}-{SEED}".encode()).hexdigest()


WAVES = [
    {"n": 1, "date": "2026-01-09", "hash": sha256_of("w1"),
     "name": "sandbar.dropper.a", "note": "initial access via macro attachment"},
    {"n": 2, "date": "2026-02-02", "hash": sha256_of("w2"),
     "name": "sandbar.dropper.b", "note": "reused wave 1 infrastructure"},
    {"n": 3, "date": "2026-03-11", "hash": sha256_of("w3"),
     "name": "kelphook.tideline", "note": "C2 infrastructure fully rotated"},
    {"n": 4, "date": "2026-04-05", "hash": sha256_of("w4"),
     "name": "kelphook.driftwood", "note": "persistence module added"},
]
WAVE3 = WAVES[2]

# 4번째 조각으로 Wave 3 샘플의 SHA256 을 넣는다.
#
# 이게 없으면 샌드박스 JSON 이 키 재료에 아무 기여도 하지 않는다. 무차별 대입을
# 시도하는 솔버는 CSV 도메인 150개 x 기법 조합 63개만 돌리면 되고, 샌드박스는
# 열어보지도 않는다. 해시를 넣으면 브루트포스조차 샌드박스를 읽어야 한다.
#
# 정직한 솔버에게는 부담이 아니다 — 이미 특정한 리포트의 필드를 복사하면 된다
# (스캔에서 64자 hex 를 OCR 할 필요는 없다).
KEY_MATERIAL = f"{TECH_STRING}|{C2_DOMAIN}|{FIRST_SEEN_STR}|{WAVE3['hash']}"

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


KDF_ROUNDS = 12_000_000


def derive_key(material: str) -> bytes:
    """
    반복 해시로 키를 늘린다.

    정직한 솔버는 후보가 1개라 0.3초면 끝난다.
    반면 무차별 대입은 후보가 10^4~10^6 개라 며칠이 걸린다.
    즉 '전부 대입해 본다' 를 '분석해서 후보를 좁혀야 한다' 로 바꾼다 —
    KDF 스트레칭의 목적 그대로다.

    실측 (이 환경 기준 약 6.7M hash/s):
        정직한 경로  후보 1개    x 12M = 1.8초
        무차별 대입  후보 28,350개 x 12M = 약 14시간
    (후보 공간 = 기법 조합 63 x CSV 도메인 150 x 샌드박스 해시 3)
    """
    h = material.encode()
    for _ in range(KDF_ROUNDS):
        h = hashlib.sha256(h).digest()
    return h


def encrypt(plain: bytes, key_material: str) -> bytes:
    # 평문을 3의 배수 길이로 맞춘다.
    # 이렇게 하지 않으면 base64 결과에만 '=' 패딩이 붙어서,
    # payload 라인 153개 중 '='로 끝나는 하나를 grep 하는 것만으로 정답이 잡힌다.
    # (블라인드 검증에서 실제로 걸린 우회다)
    while len(plain) % 3:
        plain += b"\n"
    key = derive_key(key_material)
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
            "domain naming.",
            "",
            "Analysts are reminded that request volume alone is a poor",
            "indicator of C2 activity in dynamic analysis; benign telemetry",
            "and update endpoints are frequently the noisiest hosts in a",
            "sandbox run.",
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
            "  key       = SHA256 applied 12000000 times, iteratively:",
            "                  h = MATERIAL as ASCII bytes",
            "                  repeat 12000000 times:  h = SHA256(h)",
            "                  key = h              <- raw 32-byte digest,",
            "                                          not a 64-char hex string",
            "  keystream = SHA256( key + str(i) ) concatenated for i = 0,1,2,...",
            "  plain[j]  = cipher[j] XOR keystream[j]",
            "",
            "MATERIAL is four fields joined with the ASCII pipe character,",
            "in this order:",
            "",
            "  MATERIAL = TECH + \"|\" + C2DOMAIN + \"|\" + FIRSTSEEN",
            "             + \"|\" + SAMPLESHA256",
            "",
            "  TECH       the wave-3 ATT&CK technique IDs, in table order,",
            "             concatenated with no separator (base IDs only;",
            "             this report uses no sub-technique numbers)",
            "  C2DOMAIN   the wave-3 command-and-control domain",
            "  FIRSTSEEN  the timestamp at which that domain was first",
            "             catalogued as an indicator, verbatim and unquoted",
            "             (e.g. 2026-01-01T00:00:00Z)",
            "  SAMPLESHA  the wave-3 sample's sha256, lowercase hex",
        ]),
    ]
    for i, (title, lines) in enumerate(narrative):
        head(title, i + 2)
        para(lines, H - 45 * mm)
        c.showPage()

    # --- p.6 Campaign Timeline (스캔 이미지)
    lines = [(f"{CAMPAIGN} Campaign Timeline", 30, True), ("", 12, False),
             ("Wave    Date         Loader family", 20, True)]
    # 스캔에는 SHA256 을 싣지 않는다.
    #
    # 두 가지 이유가 있다.
    #  1) hex 는 OCR 로 못 읽는다. 4글자씩 끊어 적어도 01dd->Oldd, 5cfa->Scfa,
    #     f0c1->f0cl 로 깨진다. 비전 없이 푸는 플레이어를 이유 없이 벌주는 셈이다.
    #  2) 스캔에도 해시가 있으면 샌드박스를 안 열고도 키 재료를 완성할 수 있다.
    #     해시가 샌드박스에만 있으면 무차별 대입조차 샌드박스를 읽어야 한다.
    # 스캔에는 OCR 로 확실히 읽히는 것(웨이브 -> 로더 계열 매핑)만 남긴다.
    for w in WAVES:
        lines.append((f"  wave {w['n']}   {w['date']}   {w['name']}", 20, False))
    lines += [("", 14, False), ("Notes", 20, True)]
    for w in WAVES:
        lines.append((f"  Wave {w['n']}: {w['note']}", 18, False))

    img = scan_page(lines, None, rng)
    tmp = os.path.join(DIST, "_p6.png")
    img.save(tmp)
    c.drawImage(tmp, 0, 0, width=W, height=H)
    c.showPage()

    # --- p.7 ATT&CK 매핑 (벡터 텍스트)
    #
    # 이 표는 스캔으로 두지 않는다. 실측하면 T1071 의 OCR 정확도가 최선 4/8 이다:
    #     노이즈 4.0/blur0.35/q72   4/8
    #     노이즈 2.5/blur0.25/q85   3/8
    #     노이즈 1.5/blur0.15/q92   1/8
    # 노이즈를 낮춰도 오히려 나빠진다 — 원인은 노이즈가 아니라 'T1071' 렌더링
    # 자체의 취약성이고, 실제 생성물에서 '2 I 0 ft' 로 완파된 적이 있다.
    #
    # 교훈은 로더 이름을 조인 키로 바꿀 때와 같다: **단어는 OCR 을 견디고
    # 구조화된 영숫자는 못 견딘다.** 그러니 OCR 에 취약한 데이터는 텍스트
    # 페이지에 두고, 스캔에는 OCR 로 안전하게 읽히는 것(웨이브->로더 매핑)만 남긴다.
    # 체인에서 OCR 이 필수라는 성질은 p.6 이 그대로 유지한다.
    head("ATT&CK Technique Mapping", 7)
    c.setFont("Courier", 10)
    y = H - 45 * mm
    c.drawString(20 * mm, y, "Technique   Name                                     Mapped waves")
    y -= 7 * mm
    for tid, name, waves in ATTACK_TABLE:
        c.drawString(20 * mm, y, f"{tid}       {name:<40} waves {waves.replace(', ', ' ')}")
        y -= 6 * mm
    c.setFont("Helvetica", 10)
    y -= 6 * mm
    for ln in ["Rows are ordered by first observation.",
               "Sub-technique numbers are not used in this report."]:
        c.drawString(20 * mm, y, ln)
        y -= 5.6 * mm
    c.showPage()

    c.save()
    os.remove(tmp)


# ---------------------------------------------------------------- 샌드박스

def sandbox_report(rng, sha, verdict_domains, family, rid):
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
            # 로더 계열명. 리포트의 스캔 페이지와 이 필드가 조인 키다.
            # 64자 hex 는 OCR 이 0/O, 1/l, 5/S 를 계속 틀려서 조인 키로 못 쓴다
            # (4글자씩 끊어 적어도 01dd->Oldd, 5cfa->Scfa 로 깨졌다).
            # 문제 1에서 얻은 교훈 그대로 — 단어는 정확히 읽히고 무작위 영숫자는 안 읽힌다.
            "family": family,
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

# 사람이 지을 법한 인프라 도메인 이름 풀.
#
# 초안은 잡음 도메인 144개가 전부 'api-1a2b3.example.com' 같은 생성기 템플릿이라,
# 그 템플릿에 안 맞는 6개(= C2 와 유사 도메인들)를 정규식 한 줄로 뽑아낼 수 있었다.
# 미끼가 미끼처럼 생기면 미끼가 아니다.
IOC_WORDS_A = ["cdn", "api", "mail", "vpn", "node", "edge", "ocsp", "mirror",
               "static", "update", "telemetry", "sync", "auth", "relay",
               "proxy", "cache", "assets", "media", "push", "log"]
IOC_WORDS_B = ["sync", "gw", "eu", "us", "r3", "prod", "cdn", "net", "svc",
               "core", "edge", "01", "02", "ha", "alt", "backup", "live"]


def ioc_name(rng):
    return (f"{rng.choice(IOC_WORDS_A)}-{rng.choice(IOC_WORDS_B)}"
            f"{rng.choice(['', '', '2', '3', 'x'])}.example."
            f"{rng.choice(['com', 'net', 'org'])}")


def build_iocs(rng, path, sandbox_domains):
    rows = [("indicator", "type", "campaign", "first_seen", "confidence")]
    # (c) 날짜만 흔들고 시:분:초를 재사용하면 09:21:44 가 59번 등장해서
    #     오히려 정답 시각이 표시된다. 초 단위까지 완전 무작위로 만든다.
    noise_domains = [
        "cdn-sync.example.org", "cdn-sync2.example.net", "cdn-synk.example.net",
        "cdn-sync.example.com", "sync-cdn.example.net",
    ]
    entries = []
    for d in noise_domains:
        entries.append((d, "domain", CAMPAIGN, rand_ts(rng),
                        rng.choice(["low", "medium", "high"])))
    entries.append((C2_DOMAIN, "domain", CAMPAIGN, FIRST_SEEN_STR, "high"))

    # (a) 샌드박스에 등장하는 나머지 도메인도 전부 IOC 에 넣는다.
    #     그러지 않으면 '샌드박스 도메인 목록 ∩ IOC 목록' 이 정확히 1개가 되어,
    #     comm 한 번으로 C2 / first_seen / 유출 세션 / wave3 샘플이 한꺼번에
    #     드러난다. 비콘 분석도 스캔 페이지도 통째로 우회된다.
    for dom in sandbox_domains:
        if dom == C2_DOMAIN:
            continue
        entries.append((dom, "domain", rng.choice([CAMPAIGN, "SANDPIPER"]),
                        rand_ts(rng), rng.choice(["low", "medium", "high"])))

    seen_names = {e[0] for e in entries}
    while len(entries) < 190:
        n = ioc_name(rng)
        if n in seen_names:
            continue
        seen_names.add(n)
        entries.append((n, "domain",
                        rng.choice([CAMPAIGN, "SANDPIPER", "MERLIN"]),
                        rand_ts(rng),
                        rng.choice(["low", "medium", "high"])))
    for _ in range(54):
        entries.append((
            f"{rng.choice(['192.0.2','198.51.100','203.0.113'])}."
            f"{rng.randint(2,250)}", "ipv4",
            rng.choice([CAMPAIGN, "SANDPIPER", "MERLIN"]),
            rand_ts(rng), rng.choice(["low", "medium", "high"])))
    rng.shuffle(entries)

    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(rows[0])
        w.writerows(entries)
    return entries


def build_traffic(rng, path, cipher_b64, ioc_entries, decoy_payloads=()):
    lines = ["# norite netflow / http session summary",
             "# generated 2026-04-16, all addresses are RFC 5737 documentation ranges",
             ""]
    n = 0
    base = EXFIL_TS - timedelta(hours=6)
    events = []

    # IOC 목록의 도메인 상당수를 트래픽에도 섞는다.
    #
    # 이게 없으면 traffic 의 도메인 집합과 iocs.csv 의 지표 집합을 교집합했을 때
    # C2 하나만 남는다. 한 줄이면 C2 와 유출 세션이 동시에 나와서 샌드박스 3종과
    # 리포트 p.6 이 통째로 무의미해진다 — 이 문제의 중심 기믹이 증발한다.
    # (블라인드 검증에서 "가장 심각한 구멍" 으로 지목된 항목)
    ioc_domains = [e[0] for e in ioc_entries
                   if e[1] == "domain" and e[0] != C2_DOMAIN]
    seeded = rng.sample(ioc_domains, min(48, len(ioc_domains)))
    for dom in seeded:
        for _ in range(rng.randint(1, 4)):
            ts = base + timedelta(seconds=rng.randint(0, 43200))
            events.append((ts, f"192.0.2.{rng.randint(2,250)}",
                           f"{rng.choice(['198.51.100','203.0.113'])}."
                           f"{rng.randint(2,250)}", dom,
                           None if rng.random() > 0.10 else "".join(rng.choice(
                               "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmno"
                               "pqrstuvwxyz0123456789+/")
                               for _ in range(rng.randint(10, 22) * 4))))

    for i in range(2400):
        ts = base + timedelta(seconds=rng.randint(0, 43200))
        src = f"192.0.2.{rng.randint(2,250)}"
        dst = f"{rng.choice(['198.51.100','203.0.113'])}.{rng.randint(2,250)}"
        host = (f"{rng.choice(['api','cdn','mail','node'])}-"
                f"{rng.randrange(10**5):05x}.example."
                f"{rng.choice(['com','net','org'])}")
        payload = None
        if rng.random() < 0.06:
            # 길이를 4의 배수로 두어 진짜와 마찬가지로 '=' 패딩이 없게 한다
            payload = "".join(rng.choice(
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/")
                for _ in range(rng.randint(10, 22) * 4))
        events.append((ts, src, dst, host, payload))

    events.append((EXFIL_TS, VICTIM_IP, C2_IP, C2_DOMAIN, cipher_b64))
    for dom, pay in decoy_payloads:
        events.append((base + timedelta(seconds=rng.randint(0, 43200)),
                       f"192.0.2.{rng.randint(2,250)}",
                       f"198.51.100.{rng.randint(2,250)}", dom, pay))
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
        (WAVES[0], [("telemetry.example.com", 31, False),
                    ("update.example.org", 12, False),
                    ("static-a.example.net", 47, True)], "0442"),
        (WAVES[2], [("telemetry.example.com", 58, False),
                    ("update.example.org", 9, False),
                    ("ocsp.example.org", 23, False),
                    (C2_DOMAIN, 41, True)], "0517"),
        (WAVES[3], [("telemetry.example.com", 44, False),
                    ("mirror.example.com", 19, False),
                    ("edge-7.example.net", 38, True)], "0603"),
    ]
    for w, doms, rid in specs:
        rep = sandbox_report(rng, w["hash"], doms, w["name"], rid)
        with open(os.path.join(OUT, "sandbox", f"report_{rid}.json"), "w") as f:
            json.dump(rep, f, indent=2)

    sandbox_domains = sorted({d for _, doms, _ in specs for d, _, _ in doms})
    ioc_entries = build_iocs(rng, os.path.join(OUT, "iocs.csv"), sandbox_domains)

    import base64
    cipher = encrypt(FLAG.encode(), KEY_MATERIAL)
    cipher_b64 = base64.b64encode(cipher).decode()

    # 근접 오답 키로 암호화한 미끼 페이로드.
    #
    # 무차별 대입은 후보 공간이 CSV 도메인 수로 묶여 있어 원리적으로 막을 수 없다.
    # 대신 **대입에 성공해도 답이 하나로 안 좁혀지게** 만든다. 유사 도메인과
    # 그 first_seen 으로 만든 키에서도 그럴듯한 플래그가 나오면, 결국 비콘 분석과
    # 정확 문자열 일치로 판정해야 한다.
    decoy_specs = [
        ("cdn-sync.example.org", "KCTF{b34c0n_k3y_r3c0v3r3d_w4v3_tw0}"),
        ("cdn-sync2.example.net", "KCTF{bluh3r0n_st4g3r_c0nf1g_dump}"),
        ("cdn-sync.example.com", "KCTF{c2_ch4nn3l_k3y_n0t_r0t4t3d}"),
        ("sync-cdn.example.net", "KCTF{3xf1l_bl0b_p4rt14l_r3c0v3ry}"),
    ]
    fs_by_dom = {e[0]: e[3] for e in ioc_entries}
    decoy_payloads = []
    for dom, fake in decoy_specs:
        if dom not in fs_by_dom:
            continue
        mat = f"{TECH_STRING}|{dom}|{fs_by_dom[dom]}|{WAVE3['hash']}"
        decoy_payloads.append(
            (dom, base64.b64encode(encrypt(fake.encode(), mat)).decode()))
    n_ev, n_pay = build_traffic(rng, os.path.join(OUT, "traffic_summary.txt"),
                                cipher_b64, ioc_entries, decoy_payloads)

    zip_path = os.path.join(DIST, "intel-chain.zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for dirpath, _, files in os.walk(OUT):
            for fn in sorted(files):
                full = os.path.join(dirpath, fn)
                zf.write(full, os.path.relpath(full, DIST))

    print(f"배포물: {zip_path} ({os.path.getsize(zip_path)/1e6:.1f} MB)")
    print(f"  IOC 행         : {len(ioc_entries)}")
    print(f"  트래픽 이벤트  : {n_ev} (payload 보유 {n_pay})")
    print(f"  Wave3 SHA256   : {WAVE3['hash']}")
    print(f"  C2             : {C2_DOMAIN}  first_seen "
          f"{FIRST_SEEN.strftime('%Y-%m-%dT%H:%M:%SZ')}")
    print(f"  키 재료        : {KEY_MATERIAL}")
    print(f"FLAG: {FLAG}")


if __name__ == "__main__":
    main()
