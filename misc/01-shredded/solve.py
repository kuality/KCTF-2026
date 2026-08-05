#!/usr/bin/env python3
"""
KCTF 2026 MISC — shredded / 레퍼런스 솔버

  python3 solve.py dist/shredded/fragments

파이프라인:
  1) 전처리 (grayscale -> deskew -> upscale -> Otsu)
  2) tesseract --psm 7 + base32 화이트리스트로 1차 OCR
  3) 체크섬으로 실패 조각 국소화
  4) 실패 조각만 전처리 변형을 스윕하며 재시도  <- AI/도구를 배율기로 쓰는 지점
  5) 인덱스 집합 무결성 검증 (중복/누락 = 남아있는 인덱스 오독)
  6) 정렬 -> concat -> base32 decode -> ZIP 추출
"""

import io
import itertools
import os
import re
import sys
import zipfile
import zlib
from concurrent.futures import ThreadPoolExecutor

import numpy as np
import pytesseract
from PIL import Image

ALPHABET = "ABCDEGHKMNORSWY4"
HEXDIGITS = "0123456789abcdef"
CHUNK_CHARS = 24
IDX_CHARS = 3
CHK_CHARS = 3
N_FRAGMENTS = 410

# 화이트리스트를 16심볼로 좁히는 것이 정확도의 핵심이다.
# tesseract 는 화이트리스트 밖으로 답을 낼 수 없으므로, 알파벳이 작을수록
# 오답 선택지 자체가 사라진다. (base32 2.37% -> safe16 0.10% 문자오독)
def tess_cfg(psm: int) -> str:
    return f'--psm {psm} -c tessedit_char_whitelist={ALPHABET}| '

LINE_RE = re.compile(
    r'^([%s]{%d})\s*\|\s*([%s]{%d})\s*\|\s*([%s]{%d})$'
    % (ALPHABET, IDX_CHARS, ALPHABET, CHUNK_CHARS, ALPHABET, CHK_CHARS))

# (upscale, blur, threshold_mode, bias, flatten, unsharp, psm)
#
# 실측 결과 이진화(otsu/fixed)보다 그레이스케일 그대로가 낫다 — 열화된 스캔에서
# 이진화는 얇은 획을 끊어버린다. 스윕에는 다양성 확보용으로 남겨둔다.
#
# flatten(배경 평탄화)이 저대비 조각의 결정타다. 큰 반경 가우시안을 빼서
# 얼룩진 배경을 제거하고 대비를 재정규화하면, 어떤 전처리로도 안 읽히던
# 조각들이 살아난다.
# 아래 조합은 70장 표본으로 변형별 정확도와 합집합을 실측해 고른 것이다.
#   blur.4 68/70   blur.6+up4 68/70   otsu 68/70   base 67/70
#   up4 66/70      up5 66/70          flat 52/70   fixed-12 51/70
#   flat+psm6 46/70
#   -> 합집합 70/70 (모든 조각이 어떤 변형으로든 읽힌다)
# 언샤프는 오히려 크게 해로웠고(12/70, 1/70), psm 13 과 fixed+12 는 0/70 이라 뺐다.
PREPROC_DEFAULT = (3, 0.0, "none", 0, False, 0.0, 7)
PREPROC_SWEEP = [
    (3, 0.0, "none", 0, False, 0.0, 7),
    (3, 0.4, "none", 0, False, 0.0, 7),
    (4, 0.6, "none", 0, False, 0.0, 7),
    (3, 0.0, "otsu", 0, False, 0.0, 7),
    (4, 0.0, "none", 0, False, 0.0, 7),
    (5, 0.0, "none", 0, False, 0.0, 7),
    (3, 0.0, "none", 0, True, 0.0, 7),     # 배경 평탄화
    (4, 0.0, "fixed", -12, False, 0.0, 7),
    (3, 0.0, "none", 0, True, 0.0, 6),     # 평탄화 + psm 6
]


# ------------------------------------------------------------ 전처리

def deskew(img: Image.Image) -> Image.Image:
    """텍스트 픽셀의 주축을 찾아 회전을 되돌린다 (외부 의존성 없이)."""
    a = np.asarray(img, dtype=np.float32)
    dark = a < (a.mean() - a.std() * 0.8)
    ys, xs = np.nonzero(dark)
    if len(xs) < 50:
        return img
    # 잉크 픽셀에 직선을 최소자승 피팅 -> 기울기 = skew
    slope = np.polyfit(xs, ys, 1)[0]
    angle = np.degrees(np.arctan(slope))
    if abs(angle) < 0.15 or abs(angle) > 12:
        return img
    return img.rotate(angle, resample=Image.BICUBIC, fillcolor=245)


def flatten_bg(img: Image.Image) -> Image.Image:
    """
    배경 평탄화. 큰 반경 가우시안(= 배경 추정)을 원본에서 빼면 얼룩·조명 불균일이
    사라지고, 이어서 대비를 재정규화하면 흐린 획이 되살아난다.
    저대비 조각을 살리는 가장 효과가 큰 단계다.
    """
    from PIL import ImageFilter
    a = np.asarray(img, dtype=np.float32)
    bg = np.asarray(img.filter(ImageFilter.GaussianBlur(25)), dtype=np.float32)
    d = a - bg + 255.0
    lo, hi = np.percentile(d, 2), np.percentile(d, 98)
    if hi - lo < 1:
        return img
    d = (d - lo) / (hi - lo) * 255.0
    return Image.fromarray(np.clip(d, 0, 255).astype(np.uint8), "L")


def preprocess(path: str, params) -> Image.Image:
    upscale, blur, mode, bias, flat, unsharp, _psm = params
    img = Image.open(path).convert("L")
    img = deskew(img)

    if flat:
        img = flatten_bg(img)

    if blur > 0:
        from PIL import ImageFilter
        img = img.filter(ImageFilter.GaussianBlur(blur))

    if unsharp > 0:
        from PIL import ImageFilter
        img = img.filter(ImageFilter.UnsharpMask(radius=2, percent=int(unsharp * 100),
                                                 threshold=2))

    w, h = img.size
    img = img.resize((w * upscale, h * upscale), Image.LANCZOS)

    a = np.asarray(img, dtype=np.uint8)
    if mode == "otsu":
        hist = np.bincount(a.ravel(), minlength=256).astype(np.float64)
        tot = hist.sum()
        w0 = np.cumsum(hist)
        m = np.cumsum(hist * np.arange(256))
        mt = m[-1]
        with np.errstate(divide="ignore", invalid="ignore"):
            between = (mt * w0 / tot - m) ** 2 / (w0 * (tot - w0))
        t = int(np.nanargmax(between)) + bias
        a = np.where(a > t, 255, 0).astype(np.uint8)
    elif mode == "fixed":
        t = int(a.mean() - a.std() * 0.7) + bias
        a = np.where(a > t, 255, 0).astype(np.uint8)

    return Image.fromarray(a, "L")


# ------------------------------------------------------------ OCR

def checksum(idx: str, data: str) -> str:
    total = sum((pos + 1) * ALPHABET.index(ch)
                for pos, ch in enumerate(idx + data)) & 0xFFF
    return "".join(ALPHABET[(total >> s) & 0xF] for s in (8, 4, 0))


def checksum_ok(idx: str, data: str, chk: str) -> bool:
    return checksum(idx, data) == chk


def ocr_raw(path: str, params) -> str:
    img = preprocess(path, params)
    raw = pytesseract.image_to_string(img, config=tess_cfg(params[6])).strip()
    return " ".join(raw.split())


def ocr_fragment(path: str, params):
    m = LINE_RE.match(ocr_raw(path, params))
    if not m:
        return None
    return m.group(1), m.group(2), m.group(3)


def repair(raws, missing_idx):
    """
    스윕으로도 체크섬을 못 맞춘 조각을 복구한다.

    전략은 위치별 투표다. 전처리 변형 8종이 같은 조각에 대해 서로 다른 답을
    내는데, 대부분의 위치는 전원 일치하고 **틀리는 위치에서만 의견이 갈린다.**
    그 위치만 분기시키면 탐색 공간이 수십 개로 줄어든다.
    (맹목적 1~2글자 치환은 12비트 체크섬을 우연히 통과하는 후보가
     수백 개씩 나와서 조합 폭발한다)

    여기에 '남은 인덱스 집합' 제약과 체크섬을 걸고, 최종 판정은 ZIP CRC 가 한다.
    """
    tok_re = re.compile(f"[{ALPHABET}]+")
    data_cands, chk_cands, full = {}, set(), []   # data -> 편집비용

    def put(d, cost):
        if d not in data_cands or data_cands[d] > cost:
            data_cands[d] = cost

    for raw in raws:
        toks = tok_re.findall(raw)
        for t in toks:
            if len(t) == CHUNK_CHARS:
                put(t, 0)
            elif len(t) == CHK_CHARS:
                # 길이 3은 인덱스일 수도 체크섬일 수도 있다. 둘 다 후보로 둔다.
                chk_cands.add(t)
        # 글자 한 개가 먹히거나 덧붙은 경우까지 되살린다
        for t in toks:
            if len(t) == CHUNK_CHARS - 1:
                for pos in range(CHUNK_CHARS):
                    for c in ALPHABET:
                        put(t[:pos] + c + t[pos:], 1)
            elif len(t) == CHUNK_CHARS + 1:
                for pos in range(len(t)):
                    put(t[:pos] + t[pos + 1:], 1)
        if len(toks) >= 2 and len(toks[-2]) == CHUNK_CHARS:
            full.append(toks[-2])

    # 변형끼리 글자가 어긋난 위치만 분기시켜 조합을 만든다
    if full:
        cols = [sorted({f[p] for f in full}) for p in range(CHUNK_CHARS)]
        space = 1
        for c in cols:
            space *= len(c)
        if space <= 50000:
            for t in itertools.product(*cols):
                d = "".join(t)
                put(d, sum(1 for a, b in zip(d, full[0]) if a != b))

    if not data_cands or not chk_cands:
        return []

    # 오류가 두 개인 경우(글자 누락 + 치환)까지 잡으려면 후보마다 치환 1개를
    # 더 허용해야 한다. 매번 체크섬을 다시 계산하면 백만 번 단위라 느리므로,
    # 위치 p 의 값을 v_old -> v_new 로 바꿀 때의 증분만 본다.
    #     delta = (p + 1 + IDX_CHARS) * (v_new - v_old)
    val = {c: i for i, c in enumerate(ALPHABET)}
    out = []
    for mi in missing_idx:
        idx = int_to_index(mi)
        idx_total = sum((p + 1) * val[c] for p, c in enumerate(idx))
        for data, dcost in data_cands.items():
            base = idx_total + sum((p + 1 + IDX_CHARS) * val[c]
                                   for p, c in enumerate(data))
            for chk in chk_cands:
                target = 0
                for c in chk:
                    target = target * 16 + val[c]
                if (base & 0xFFF) == target:
                    out.append((mi, idx, data, chk, dcost))
                    continue
                need = (target - base) & 0xFFF
                for p, c in enumerate(data):
                    w = p + 1 + IDX_CHARS
                    v_old = val[c]
                    for v_new in range(16):
                        if v_new != v_old and (w * (v_new - v_old)) & 0xFFF == need:
                            out.append((mi, idx,
                                        data[:p] + ALPHABET[v_new] + data[p + 1:],
                                        chk, dcost + 1))
    return out


def index_to_int(idx: str) -> int:
    v = 0
    for ch in idx:
        v = v * 16 + ALPHABET.index(ch)
    return v


def int_to_index(i: int) -> str:
    return "".join(ALPHABET[(i >> s) & 0xF] for s in (8, 4, 0))


def decode(sym: str) -> bytes:
    return bytes.fromhex(sym.translate(str.maketrans(ALPHABET, HEXDIGITS)))


# ------------------------------------------------------------ main

def solve(frag_dir: str):
    paths = sorted(
        os.path.join(frag_dir, f)
        for f in os.listdir(frag_dir) if f.lower().endswith(".png")
    )
    print(f"[*] 조각 {len(paths)}장")

    # --- 1차 OCR (병렬)
    def first_pass(p):
        rec = ocr_fragment(p, PREPROC_DEFAULT)
        if rec and checksum_ok(*rec):
            return p, rec
        return p, None

    with ThreadPoolExecutor(max_workers=os.cpu_count()) as ex:
        results = list(ex.map(first_pass, paths))

    good = {p: r for p, r in results if r}
    failed = [p for p, r in results if not r]
    print(f"[*] 1차 체크섬 통과 {len(good)}/{len(paths)} "
          f"({len(good) / len(paths) * 100:.1f}%), 재시도 대상 {len(failed)}장")

    # --- 재시도: 실패한 조각만 전처리 스윕
    raw_bank = {}

    def retry(p):
        # 복구 단계의 투표 재료로 쓰기 위해 모든 변형의 결과를 모아둔다.
        raws = [ocr_raw(p, PREPROC_SWEEP[0])]
        for params in PREPROC_SWEEP[1:]:
            raw = ocr_raw(p, params)
            raws.append(raw)
            m = LINE_RE.match(raw)
            if m:
                rec = (m.group(1), m.group(2), m.group(3))
                if checksum_ok(*rec):
                    return p, rec, raws
        return p, None, raws

    still = []
    if failed:
        with ThreadPoolExecutor(max_workers=os.cpu_count()) as ex:
            for p, rec, raws in ex.map(retry, failed):
                raw_bank[p] = raws
                if rec:
                    good[p] = rec
        still = [p for p in failed if p not in good]
        print(f"[*] 재시도 후 확보 {len(good)}/{len(paths)}, 미해결 {len(still)}장")

    # --- 인덱스 집합 무결성 검증
    idx_map, dup = {}, []
    for p, (idx, data, chk) in good.items():
        if idx in idx_map:
            dup.append(idx)
        idx_map[idx] = data
    if dup:
        print(f"[!] 인덱스 중복 {dup} — 체크섬을 통과한 인덱스 오독이 남아있다")

    have = {index_to_int(i) for i in idx_map}
    missing = sorted(set(range(N_FRAGMENTS)) - have)

    # --- 혼동행렬 기반 복구: 남은 인덱스가 알려져 있다는 제약을 활용한다
    if missing:
        print(f"[*] 미복원 인덱스 {missing} — 제약 탐색으로 복구 시도")
        best = {}
        for p in still:
            for mi, idx, data, chk, cost in repair(raw_bank.get(p, []), missing):
                key = (mi, data)
                if key not in best or best[key] > cost:
                    best[key] = cost
        options = {}
        for (mi, data), cost in best.items():
            options.setdefault(mi, []).append((cost, data))
        for mi in missing:
            options.setdefault(mi, []).sort()
            print(f"      idx {mi}: 후보 {len(options[mi])}개")

        combos = _resolve(idx_map, missing, options)
        if combos is None:
            print("[!] 복구 실패 — 해당 조각은 사람 눈이나 VLM 으로 판독한다")
            for p in still:
                print(f"      ! {os.path.basename(p)}")
            return None
        idx_map.update(combos)
    else:
        print(f"[*] 인덱스 집합 무결성 OK (0..{N_FRAGMENTS - 1} 전부 존재)")

    return _assemble(idx_map)


def _assemble(idx_map):
    """조립 후 ZIP 으로 최종 검증. 실패하면 None."""
    try:
        sym = "".join(idx_map[int_to_index(i)] for i in range(N_FRAGMENTS))
    except KeyError:
        return None
    blob = decode(sym)
    if blob[:4] != b"PK\x03\x04":
        return None
    try:
        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            if zf.testzip():
                return None
            text = zf.read("recovery_log.txt").decode()
    except (zipfile.BadZipFile, KeyError, UnicodeDecodeError,
            zlib.error, EOFError, ValueError):
        return None
    for line in text.splitlines():
        if "KCTF{" in line:
            return line.strip()
    return None


MAX_TRIALS = 300000


def _resolve(idx_map, missing, options):
    """
    복구 후보 조합을 ZIP CRC 로 최종 검증한다.
    체크섬(12비트)만으로는 우연히 통과하는 후보가 섞이므로 CRC 가 진짜 판정자다.

    후보를 전부 교차곱하면 수천만 조합이 된다. 대신 **편집 비용이 낮은 조합부터**
    본다. 실제 정답은 OCR 결과에서 1~2글자 떨어져 있을 뿐이라 앞쪽에서 걸린다.
    """
    import heapq
    lists = [options.get(mi, []) for mi in missing]
    if any(not c for c in lists):
        return None

    start = tuple(0 for _ in lists)
    seen = {start}
    heap = [(sum(lists[k][0][0] for k in range(len(lists))), start)]
    tried = 0

    while heap and tried < MAX_TRIALS:
        _, pos = heapq.heappop(heap)
        tried += 1
        trial = dict(idx_map)
        for k, mi in enumerate(missing):
            trial[int_to_index(mi)] = lists[k][pos[k]][1]
        if _assemble(trial) is not None:
            print(f"      {tried}번째 조합에서 CRC 통과")
            return {int_to_index(mi): lists[k][pos[k]][1]
                    for k, mi in enumerate(missing)}
        for k in range(len(lists)):
            if pos[k] + 1 < len(lists[k]):
                nxt = pos[:k] + (pos[k] + 1,) + pos[k + 1:]
                if nxt not in seen:
                    seen.add(nxt)
                    heapq.heappush(
                        heap,
                        (sum(lists[j][nxt[j]][0] for j in range(len(lists))), nxt))
    print(f"      {tried}개 조합 시도 — 실패")
    return None


if __name__ == "__main__":
    d = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "dist", "shredded", "fragments")
    flag = solve(d)
    print("\n" + "=" * 50)
    print("FLAG:", flag if flag else "복원 실패")
