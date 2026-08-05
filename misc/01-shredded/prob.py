#!/usr/bin/env python3
"""
KCTF 2026 MISC — shredded
문제 생성기.

플래그 ZIP → base32 → 410조각 → 열화된 스캔 이미지 410장.

설계 요점 (SPEC.md 참조):
  - 인코딩 알파벳은 **실측 혼동행렬로 고른 16심볼** ABCDEGHKMNORSWY4 이다.
    처음엔 base32(A-Z2-7)를 썼는데 0/O, 1/l 혼동은 없어도 5->S, J->I, 6->O, Q->O
    가 남아서 문자 오독률 2.4%, 24자 라인 정답률 50% 에 그쳤다.
    핵심은 **tesseract 화이트리스트가 작을수록 오답 선택지 자체가 사라진다**는 것:
        base32  문자오독 2.37%  라인정답 50%
        hex     문자오독 0.21%  라인정답 62%
        safe16  문자오독 0.10%  라인정답 94%   <- 채택
  - 인덱스도 같은 16심볼 3자리다. 숫자를 쓰면 0/8, 5/6 혼동으로 순서가 깨지는데,
    데이터 오류는 국소적이지만 순서 오류는 전역적이라 훨씬 나쁘다.
  - 체크섬은 인덱스+데이터 전체를 **위치 가중합**으로 커버한다.
      * 데이터만 커버하면 인덱스 오독이 조용히 통과한다.
      * 단순 합이면 +3/-3 처럼 상쇄되는 오류쌍을 놓친다. 위치 가중을 넣으면
        치환 1~2개는 사실상 전부 잡힌다.
      * 12비트(3심볼)를 쓴다. 1심볼(1/16)이면 재시도 스윕 도중 우연히 체크섬을
        통과하는 오답(false pass)이 기댓값 수십 건 발생해 ZIP CRC 가 깨진다.
  - 1심볼 = 4비트이므로 페이로드는 청크당 12바이트로 딱 나눠떨어진다.
    (base32 시절의 '=' 패딩 문제 자체가 사라진다)
"""

import hashlib
import io
import os
import random
import shutil
import zipfile

import numpy as np
from PIL import Image, ImageDraw, ImageFilter, ImageFont

# ---------------------------------------------------------------- 설정

FLAG = "KCTF{sh1n_0cr_p1p3l1n3_b34ts_th3_sh4dd3r}"

SEED = 20260314
N_FRAGMENTS = 410
CHUNK_CHARS = 24            # 심볼당 4비트 -> 청크당 12바이트
IDX_CHARS = 3               # 16^3 = 4096 > 410
CHK_CHARS = 3               # 12비트 체크섬
PAYLOAD_BYTES = N_FRAGMENTS * CHUNK_CHARS // 2  # 4920

# OCR 혼동행렬 실측으로 선별한 16심볼. (문자 오독률 0.10%)
ALPHABET = "ABCDEGHKMNORSWY4"
HEXDIGITS = "0123456789abcdef"

HERE = os.path.dirname(os.path.abspath(__file__))
DIST = os.path.join(HERE, "dist")
OUT_DIR = os.path.join(DIST, "shredded", "fragments")

# --- 열화 파라미터 (calibrate.py 로 실측 보정한 값)
# 목표: 1차 OCR 체크섬 통과율 92~97%
DEG = {
    "ink":       (34, 78),      # 잉크 농도 (낮을수록 진함)
    "contrast":  (0.58, 0.82),  # 대비 감쇠 배율
    "noise":     (8.0, 14.0),   # 가우시안 노이즈 sigma
    "blur":      (0.25, 0.50),  # 최종 블러 반경
    "jpeg":      (55, 75),      # JPEG 품질
    "rotate":    3.0,           # 회전 ±도
    "fontsize":  (30, 38),
}

FONT_CANDIDATES = [
    "/System/Library/Fonts/Supplemental/Courier New.ttf",
    "/System/Library/Fonts/Supplemental/Andale Mono.ttf",
    "/System/Library/Fonts/Menlo.ttc",
    "/System/Library/Fonts/Supplemental/Courier New Bold.ttf",
]


NOTES = """\
Norite Systems / 문서 파쇄 복원 작업 안내
==========================================

파쇄기 옆 회수함에서 나온 종잇조각 410장을 스캔했다.
스캔 품질이 고르지 않다. 접힘, 얼룩, 기울어짐이 섞여 있다.

각 조각에는 한 줄이 인쇄되어 있다.

    IDX | DATA | CHK

    IDX   3심볼   조각 번호. 심볼 순서가 곧 숫자 순서다.
    DATA  24심볼  페이로드 조각.
    CHK   3심볼   검증값.

심볼은 아래 16개만 쓴다. 왼쪽부터 0, 1, 2, ... 15 를 뜻한다.

    A B C D E G H K M N O R S W Y 4

즉 심볼 1개가 4비트다. 조각을 IDX 순으로 이어붙이고 이 표대로 되돌리면
바이트열이 나온다.

CHK 는 IDX 와 DATA 를 이어붙인 27심볼에 대한 12비트 위치 가중 합이다.

    total = sum((위치 + 1) * 심볼값)  for 위치, 심볼 in enumerate(IDX + DATA)
    CHK   = (total & 0xFFF) 를 3심볼로 표기

파일 이름은 아무 의미 없다. 순서는 IDX 로만 정해진다.
"""


# ---------------------------------------------------------------- 페이로드

def _log_line(n: int) -> str:
    """복원 로그 한 줄. 결정적이고 적당히 압축 가능해야 한다."""
    r = random.Random(0xC0FFEE + n)
    bin_id = r.randrange(1, 41)
    conf = r.uniform(0.71, 0.99)
    status = r.choice(["OK", "OK", "OK", "RETRY", "PARTIAL"])
    return (f"[{n:05d}] bin={bin_id:02d} strip=S{r.randrange(1000, 9999)} "
            f"conf={conf:.3f} status={status}")


def build_payload() -> bytes:
    """
    복원 로그 텍스트를 담은 deflate ZIP 하나. 압축 후 크기가 PAYLOAD_BYTES 에
    거의 딱 맞도록 줄 수를 조정한다.

    왜 이렇게 하는가:
      플래그를 작은 ZIP 에 넣고 뒤를 패딩으로 채우면, ZIP 이 앞쪽 십수 조각 안에
      전부 들어가버려서 솔버가 나머지 대부분을 읽지 않아도 플래그가 나온다.
      압축 스트림이 페이로드 전체를 채우고 플래그가 **맨 끝 줄**에 있으면,
      중간 한 청크만 틀려도 deflate 스트림이 어긋나 끝까지 복원되지 않는다.
      → 410장 전량 정확 복원이 강제되고, ZIP CRC 가 실패를 알려준다.
    """
    header = ("SHREDDER RECOVERY LOG / Norite Systems / bin sweep 2026-03-14\n"
              "----------------------------------------------------------\n")
    footer_note = "\n-- sweep complete. reassembled artifact below --\n"

    def make_zip(n_lines: int) -> bytes:
        body = header + "\n".join(_log_line(i) for i in range(n_lines))
        body += footer_note + FLAG + "\n"
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
            zf.writestr("recovery_log.txt", body)
        return buf.getvalue()

    # 이분 탐색으로 PAYLOAD_BYTES 를 넘지 않는 최대 줄 수를 찾는다.
    lo, hi = 1, 4000
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if len(make_zip(mid)) <= PAYLOAD_BYTES:
            lo = mid
        else:
            hi = mid - 1

    raw = make_zip(lo)
    pad_len = PAYLOAD_BYTES - len(raw)
    assert pad_len >= 0

    # 남는 자투리(보통 수십 바이트)만 채운다. ZIP 은 트레일링 바이트를 무시한다.
    filler, h = b"", hashlib.sha256(b"shredded-pad")
    while len(filler) < pad_len:
        h = hashlib.sha256(h.digest())
        filler += h.digest()

    print(f"  페이로드: ZIP {len(raw)}B (로그 {lo}줄) + 패딩 {pad_len}B")
    return raw + filler[:pad_len]


def encode(blob: bytes) -> str:
    """바이트 -> 16심볼 문자열 (심볼 1개 = 4비트, hex 자리와 1:1 대응)."""
    return blob.hex().translate(str.maketrans(HEXDIGITS, ALPHABET))


def index_label(i: int) -> str:
    """0..4095 -> 3심볼. 심볼 순서 = 숫자 순서라 정렬만으로 복원된다."""
    return "".join(ALPHABET[(i >> s) & 0xF] for s in (8, 4, 0))


def checksum(idx: str, data: str) -> str:
    """
    인덱스 + 데이터 전체를 커버하는 12비트 위치 가중 체크섬.
    위치 가중이라 +3/-3 처럼 상쇄되는 오류쌍과 자리바꿈까지 잡는다.
    """
    total = sum((pos + 1) * ALPHABET.index(ch)
                for pos, ch in enumerate(idx + data))
    total &= 0xFFF
    return "".join(ALPHABET[(total >> s) & 0xF] for s in (8, 4, 0))


def build_lines() -> list:
    payload = build_payload()
    enc = encode(payload)
    assert len(enc) == N_FRAGMENTS * CHUNK_CHARS, len(enc)

    lines = []
    for i in range(N_FRAGMENTS):
        data = enc[i * CHUNK_CHARS:(i + 1) * CHUNK_CHARS]
        idx = index_label(i)
        lines.append((idx, data, checksum(idx, data)))
    return lines


# ---------------------------------------------------------------- 이미지 열화

def paper_background(rng, w, h):
    """종이 질감 + 얼룩 + 접힘선. 얼룩은 반드시 여백에만 그린다."""
    base = rng.randint(228, 244)
    img = Image.new("L", (w, h), base)
    d = ImageDraw.Draw(img)

    # 섬유 질감
    for _ in range(w * h // 90):
        x, y = rng.randrange(w), rng.randrange(h)
        d.point((x, y), fill=base - rng.randint(4, 18))

    # 커피 얼룩 — 텍스트 밴드(y: 0.30h ~ 0.70h)를 피한다
    for _ in range(rng.randint(1, 2)):
        r = rng.randint(9, 20)
        cx = rng.randint(r, w - r)
        cy = rng.choice([rng.randint(r, int(h * 0.26)),
                         rng.randint(int(h * 0.74), h - r)])
        d.ellipse([cx - r, cy - r, cx + r, cy + r],
                  outline=base - rng.randint(28, 52), width=rng.randint(1, 3))

    # 접힘선 — 세로선 1개, 역시 텍스트를 세로로 가로지르지 않도록 옅게
    if rng.random() < 0.5:
        fx = rng.randint(int(w * 0.05), int(w * 0.95))
        d.line([(fx, 0), (fx + rng.randint(-3, 3), h)],
               fill=base - rng.randint(8, 16), width=1)

    return img.filter(ImageFilter.GaussianBlur(0.4))


def torn_edges(rng, img):
    """가장자리를 찢긴 모양으로 깎아낸다."""
    w, h = img.size
    d = ImageDraw.Draw(img)
    white = 255
    for edge in ("top", "bottom"):
        pts, x = [], 0
        while x < w:
            step = rng.randint(6, 18)
            depth = rng.randint(0, 7)
            pts.append((x, depth if edge == "top" else h - depth))
            x += step
        pts.append((w, rng.randint(0, 7) if edge == "top" else h - rng.randint(0, 7)))
        poly = ([(0, 0)] + pts + [(w, 0)]) if edge == "top" else \
               ([(0, h)] + pts + [(w, h)])
        d.polygon(poly, fill=white)
    return img


def render_fragment(rng, idx, data, chk, path):
    w, h = 940, 130
    scale = 2  # 안티에일리어싱용 오버샘플
    img = paper_background(rng, w * scale, h * scale)

    font_path = rng.choice(FONT_CANDIDATES)
    size = rng.randint(*DEG["fontsize"]) * scale
    try:
        font = ImageFont.truetype(font_path, size)
    except OSError:
        font = ImageFont.truetype(FONT_CANDIDATES[0], size)

    text = f"{idx} | {data} | {chk}"
    d = ImageDraw.Draw(img)
    bbox = d.textbbox((0, 0), text, font=font)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    tx = (w * scale - tw) // 2 - bbox[0]
    ty = (h * scale - th) // 2 - bbox[1]

    ink = rng.randint(*DEG["ink"])  # 잉크 농도 편차
    d.text((tx, ty), text, font=font, fill=ink)

    img = img.resize((w, h), Image.LANCZOS)

    # 회전
    img = img.rotate(rng.uniform(-DEG["rotate"], DEG["rotate"]),
                     resample=Image.BICUBIC, fillcolor=245, expand=False)

    img = torn_edges(rng, img)

    # 대비 감쇠
    factor = rng.uniform(*DEG["contrast"])
    lut = [int(255 - (255 - v) * factor) for v in range(256)]
    img = img.point(lut)

    # 가우시안 노이즈
    sigma = rng.uniform(*DEG["noise"])
    nrng = np.random.default_rng(rng.getrandbits(63))
    arr = np.asarray(img, dtype=np.float32)
    arr += nrng.normal(0.0, sigma, arr.shape)
    img = Image.fromarray(np.clip(arr, 0, 255).astype(np.uint8), "L")

    img = img.filter(ImageFilter.GaussianBlur(rng.uniform(*DEG["blur"])))

    # JPEG 아티팩트 — 저장했다 다시 읽어 PNG 로 출력
    jb = io.BytesIO()
    img.convert("L").save(jb, "JPEG", quality=rng.randint(*DEG["jpeg"]))
    jb.seek(0)
    Image.open(jb).convert("L").save(path, "PNG")


# ---------------------------------------------------------------- main

def main():
    rng = random.Random(SEED)
    lines = build_lines()

    if os.path.isdir(DIST):
        shutil.rmtree(DIST)
    os.makedirs(OUT_DIR, exist_ok=True)

    # 파일명은 순서 힌트가 되면 안 된다 — 결정적 셔플 후 랜덤 해시명 부여.
    order = list(range(N_FRAGMENTS))
    rng.shuffle(order)

    used = set()
    for pos, i in enumerate(order):
        idx, data, chk = lines[i]
        while True:
            name = "%08x" % rng.getrandbits(32)
            if name not in used:
                used.add(name)
                break
        render_fragment(rng, idx, data, chk, os.path.join(OUT_DIR, name + ".png"))
        if (pos + 1) % 50 == 0:
            print(f"  {pos + 1}/{N_FRAGMENTS} 렌더링")

    # 배포물에 포맷 명세를 동봉한다. 인코딩 규격은 숨기는 퍼즐이 아니라
    # 주어지는 스펙이다 — 문제의 본질은 대량 OCR 과 오류 복구 루프다.
    root = os.path.join(DIST, "shredded")
    with open(os.path.join(root, "NOTES.txt"), "w") as f:
        f.write(NOTES)

    zip_path = os.path.join(DIST, "shredded.zip")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for dirpath, _, files in os.walk(root):
            for f in sorted(files):
                full = os.path.join(dirpath, f)
                zf.write(full, os.path.relpath(full, DIST))

    print(f"\n조각 {N_FRAGMENTS}장 → {OUT_DIR}")
    print(f"배포물: {zip_path} ({os.path.getsize(zip_path) / 1e6:.1f} MB)")
    print(f"FLAG: {FLAG}")


if __name__ == "__main__":
    main()
