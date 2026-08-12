#!/usr/bin/env python3
"""KCTF 2026 MISC — alias-chain problem generator."""

import csv
import hashlib
import html
import itertools
import json
import os
import random
import shutil
import zipfile


SEED = 20260811
HERE = os.path.dirname(os.path.abspath(__file__))
DIST = os.path.join(HERE, "dist")
ROOT = os.path.join(DIST, "alias-chain")
PLATFORMS = ["BLOG", "REVIEWS", "TRAVEL", "MARKET", "SOCIAL"]
N_PER_PLATFORM = 27
PROFILE_TEXT_BYTES = 900
TARGET_POSITIONS = [7, 13, 4, 22, 9]
# Outgoing grids normally align with incoming coordinates.  The final SOCIAL
# hop has no downstream pivot, so its offset can be selected to avoid a
# container-compressibility outlier without changing candidate semantics.
TAIL_OFFSETS = [(0, 0, 0)] * (len(PLATFORMS) - 1) + [(2, 2, 2)]


# At each hop, SOURCE is wording on the already identified account and MATCH
# is wording on the same person's next alias.  They express the same three
# memories without copying the searchable surface form.
TRANSITIONS = [
    {
        "source": [
            "지난겨울 폐관 직전 별빛전망대에서 자두차를 엎질렀다.",
            "축소비율 1대87 철도 모형을 모은다.",
            "고향은 바람항이다.",
        ],
        "match": [
            "추운 계절 폐업 직전 관측소에서 건과일차를 엎었다.",
            "실물의 여든일곱 분의 일 크기인 기차 미니어처가 취미다.",
            "센 바람으로 유명한 항구 도시에서 자랐다.",
        ],
        "alt": [
            "여름 첫 개장일 수족관에서 검은 커피를 쏟은 적이 있다.",
            "실물의 육십사 분의 일 크기인 비행기 미니어처를 모은다.",
            "돌담으로 유명한 내륙 마을에서 자랐다.",
        ],
        "alt2": [
            "이른 봄 폐장일 식물원에서 레몬 탄산수를 쏟은 적이 있다.",
            "실물의 백사십사 분의 일 크기인 배 미니어처를 모은다.",
            "소나무 숲으로 유명한 산간 도시에서 자랐다.",
        ],
    },
    {
        "source": [
            "은하수서점에서 파란 지도책을 샀다.",
            "우산 손잡이에 종이학 스티커를 붙인다.",
            "목요일 21시 라디오 퀴즈를 빠뜨리지 않는다.",
        ],
        "match": [
            "별무리 이름의 책방에서 청색 지리책을 골랐다.",
            "비막이 손잡이에 접은 새 표식을 붙였다.",
            "주중 네째 날 밤 아홉 시 전파 퀴즈를 늘 듣는다.",
        ],
        "alt": [
            "햇살책방에서 붉은 요리 도감을 구입했다.",
            "여행 가방 손잡이에 둥근 달 표식을 붙였다.",
            "주중 두 번째 날 저녁 여덟 시의 음악 방송을 즐긴다.",
        ],
        "alt2": [
            "구름문고에서 초록 식물 도감을 구입했다.",
            "카메라 끈에 작은 물고기 표식을 붙였다.",
            "주중 첫날 밤 열 시의 역사 방송을 즐긴다.",
        ],
    },
    {
        "source": [
            "해오름식당에서 소금 대신 설탕을 넣은 국수를 받았다.",
            "그날 내 좌석은 17번이었다.",
            "낡은 승차권을 모으는 습관이 있다.",
        ],
        "match": [
            "해돋이 이름 식당에서 소금과 설탕이 뒤바뀐 국수를 받았다.",
            "배정된 자리는 열일곱 번째였다.",
            "낡은 대중교통 표를 수집한다.",
        ],
        "alt": [
            "달빛분식에서 고추와 후추가 엉뚱하게 뒤바뀐 만두를 받았다.",
            "배정된 자리는 스물세 번째였다.",
            "오래된 영화표를 수집한다.",
        ],
        "alt2": [
            "별그늘카페에서 꿀과 식초가 엉뚱하게 뒤바뀐 음료를 받았다.",
            "배정된 자리는 여덟 번째였다.",
            "오래된 공연 입장권을 수집한다.",
        ],
    },
    {
        "source": [
            "느린혜성 게스트하우스 204호에 묵었다.",
            "왼손잡이용 녹색 만년필을 쓴다.",
            "새벽 첫 배를 눈앞에서 놓쳤다.",
        ],
        "match": [
            "느린 별 이름 숙소 이백사 호에서 잤다.",
            "좌수용 녹색 잉크펜을 사용한다.",
            "새벽 첫 여객선을 놓쳐 섬에 못 갔다.",
        ],
        "alt": [
            "빠른유성호텔 삼백일 호에서 잤다.",
            "오른손용 푸른 연필을 사용한다.",
            "한낮의 마지막 열차를 역 앞에서 놓쳤다.",
        ],
        "alt2": [
            "푸른운석민박 오백이 호에서 잤다.",
            "양손으로 쓰는 검은 붓펜을 사용한다.",
            "해 질 무렵 첫 버스를 정류장에서 놓쳤다.",
        ],
    },
    {
        "source": [
            "자전거에는 검은 종달새라는 별명을 붙였다.",
            "비 오는 날에는 빨간 종이우산을 쓴다.",
            "1987년 기념주화를 아직 보관한다.",
        ],
        "match": [
            "자전거를 검은 아침새라고 부른다.",
            "비 오는 날 붉은 종이 우산을 들고 다닌다.",
            "천구백팔십칠 년 기념 동전을 간직한다.",
        ],
        "alt": [
            "오토바이를 하얀 갈매기라고 부른다.",
            "눈 오는 날 푸른 천 모자를 쓰고 다닌다.",
            "이천이 년을 새긴 기념 우표를 간직하고 있다.",
        ],
        "alt2": [
            "스쿠터를 붉은 참새라고 부른다.",
            "바람 부는 날 노란 천 장갑을 끼고 다닌다.",
            "천구백구십오 년을 새긴 기념 메달을 간직하고 있다.",
        ],
    },
]

# Per-platform alternatives for the three outgoing memories.  The true
# outgoing tuple and these two alternatives form a second complete 3x3x3 grid,
# keyed by the same coordinates as the incoming grid.  Thus pivot stories are
# not the only non-template tails and are not rarity/centrality anomalies.
TAIL_ALTERNATIVES = [
    [
        ["해질녘문고에서 노란 요리책을 샀다.", "솔바람서점에서 붉은 식물도감을 빌렸다."],
        ["여행 가방 지퍼에 천 물고기 배지를 달았다.", "모자 앞챙에 나무 달 모양 표식을 붙였다."],
        ["화요일 20시 음악 순위 방송을 꼭 듣는다.", "일요일 10시 역사 낭독 방송을 꼭 듣는다."],
    ],
    [
        ["달빛분식에서 후추 대신 계피를 넣은 만두를 받았다.", "솔잎식당에서 식초 대신 꿀을 넣은 국을 받았다."],
        ["그날 안내받은 자리는 8번이었다.", "그날 안내받은 자리는 23번이었다."],
        ["오래된 영화 입장권을 모은다.", "지난 공연의 종이 손목띠를 모은다."],
    ],
    [
        ["빠른유성호텔 작은 301호에 그날 묵었다.", "푸른운석민박 작은 502호에 그날 묵었다."],
        ["오른손잡이용 푸른 연필을 쓴다.", "양손으로 쓰는 검은 붓펜을 쓴다."],
        ["한낮의 마지막 열차를 놓쳤다.", "해 질 무렵 첫 버스를 놓쳤다."],
    ],
    [
        ["오토바이에 하얀 갈매기라는 별명을 붙였다.", "스쿠터에 붉은 참새라는 별명을 붙였다."],
        ["눈 오는 날에는 푸른 천 모자를 쓴다.", "바람 부는 날에는 노란 천 장갑을 낀다."],
        ["2002년 기념우표를 보관한다.", "1995년 기념메달을 보관한다."],
    ],
    [
        ["강변 창고에서 주홍 나무 나침반을 구했다.", "산마루 정자에서 자주색 도자기 새를 구했다."],
        ["청록 손잡이의 유리 구슬 장식을 상자에 둔다.", "자주색 손잡이의 도자기 새 장식을 상자에 둔다."],
        ["오래된 온실에서 나무 나침반 기념품을 산다.", "강변 창고에서 청록 구슬 기념품을 산다."],
    ],
]

FILLERS = [
    "아침에는 우유보다 보리차를 마신다.", "주말마다 오래된 다리를 산책한다.",
    "작은 화분에 바질을 기르고 있다.", "여행지에서 엽서를 한 장씩 산다.",
    "비가 오면 창가에서 재즈를 듣는다.", "도서관에서는 늘 창문 옆 자리를 고른다.",
    "노란색 연필을 세 자루 가지고 다닌다.", "매운 음식보다 담백한 국을 좋아한다.",
    "휴대전화 배경은 오래된 풍경 사진이다.", "겨울에는 회색 목도리를 자주 착용한다.",
    "토요일마다 작은 시장에서 빵을 산다.", "종이 달력에 약속을 직접 표시한다.",
    "기차에서는 진행 방향의 반대쪽에 앉는다.", "아침 일찍 동네 공원을 한 바퀴 돈다.",
    "중고 서점에서 과학 잡지를 찾아본다.", "여행 가방에는 항상 빈 공책이 있다.",
    "점심 뒤에는 짧은 산책을 한다.", "오래된 라디오를 직접 수리해 쓰고 있다.",
    "휴일에는 작은 퍼즐을 맞춘다.", "커피에는 설탕을 넣지 않는다.",
    "바닷가보다 조용한 산길을 선호한다.", "영수증을 날짜순으로 정리한다.",
    "파란 잉크로만 일기를 쓴다.", "낯선 도시에서는 먼저 서점을 찾는다.",
    "집에 들어오면 시계를 책상 위에 둔다.", "매달 마지막 날 사진을 인화한다.",
    "버스에서는 앞에서 세 번째 줄을 선호한다.", "저녁에는 휴대전화 알림을 꺼 둔다.",
    "선물 포장지는 버리지 않고 다시 쓴다.", "흐린 날에는 밝은 색 신발을 신는다.",
]


def stable_id(platform, n):
    h = hashlib.sha256(f"{SEED}:{platform}:{n}".encode()).hexdigest()[:8].upper()
    return "PRF-" + h


def handle_for(platform, n):
    h = hashlib.sha256(f"handle:{SEED}:{platform}:{n}".encode()).hexdigest()
    return "user_" + h[:10]


def pad_text(text):
    """Remove target-only file-length signals while keeping ordinary text."""
    missing = PROFILE_TEXT_BYTES - len(text.encode("utf-8"))
    if missing < 0:
        raise ValueError("profile text exceeds fixed byte budget")
    return text + (" " * missing)


def target_tail(platform_idx, outgoing):
    """Return the outgoing pivots without target-only prose structure."""
    if outgoing is None:
        return [
            "오래된 온실에서 청록 유리 구슬을 구했다.",
            "주홍 손잡이의 나무 나침반을 상자에 넣어 둔다.",
            "산마루에서 자주색 도자기 새 기념품을 산다.",
        ]
    return list(outgoing)


def flag_for(ids):
    material = "|".join(ids)
    digest = hashlib.sha256(material.encode("ascii")).hexdigest()[:24]
    return f"KCTF{{4l14s_ch41n_{digest}}}"


def profile_records(platform_idx, rng):
    incoming = TRANSITIONS[platform_idx]
    outgoing = TRANSITIONS[platform_idx + 1]["source"] if platform_idx + 1 < len(TRANSITIONS) else None
    # Complete 3x3x3 grid.  Every incoming sentence occurs 9 times, every pair
    # 3 times, and every triple once.  Correct and decoy profiles therefore
    # have the same exact-sentence frequency signature and graph degree.
    choices = list(itertools.product((0, 1, 2), repeat=3))

    records = []
    for n, choice in enumerate(choices):
        tail_choice = tuple(
            (value + TAIL_OFFSETS[platform_idx][i]) % 3
            for i, value in enumerate(choice)
        )
        facts = []
        for i, value in enumerate(choice):
            key = "match" if value == 0 else ("alt" if value == 1 else "alt2")
            facts.append(incoming[key][i])
        primary_tail = target_tail(platform_idx, outgoing)
        tail = []
        for i, value in enumerate(tail_choice):
            if value == 0:
                sentence = primary_tail[i]
            else:
                sentence = TAIL_ALTERNATIVES[platform_idx][i][value - 1]
            # Every outgoing fact receives the same coda, so all records have
            # identical repetition structure as well as sentence frequency.
            sentence = sentence.rstrip(".") + \
                " — 이 기록은 날짜와 함께 개인 공책에도 자세히 남겨 두었다."
            tail.append(sentence)
        facts += tail
        rng.shuffle(facts)
        records.append({
            "id": stable_id(PLATFORMS[platform_idx], n),
            "handle": handle_for(PLATFORMS[platform_idx], n),
            "text": pad_text(" ".join(facts)),
            "target": n == 0,
        })
    rng.shuffle(records)
    # Never let a target land at an obvious boundary merely by seed accident.
    old = next(i for i, rec in enumerate(records) if rec["target"])
    new = TARGET_POSITIONS[platform_idx]
    records[old], records[new] = records[new], records[old]
    return records


def write_blog(records):
    path = os.path.join(ROOT, "BLOG")
    os.makedirs(path)
    for seq, rec in enumerate(records):
        body = html.escape(rec["text"])
        page = f"""<!doctype html><html lang="ko"><head><meta charset="utf-8">
<meta name="profile-id" content="{rec['id']}"><title>@{rec['handle']}</title></head>
<body><h1>@{rec['handle']}</h1><article>{body}</article></body></html>
"""
        with open(os.path.join(path, f"archive_{seq:03d}.html"), "w", encoding="utf-8", newline="\n") as f:
            f.write(page)


def write_reviews(records):
    with open(os.path.join(ROOT, "REVIEWS.jsonl"), "w", encoding="utf-8", newline="\n") as f:
        for rec in records:
            f.write(json.dumps({"profile_id": rec["id"], "handle": rec["handle"],
                                "review_history": rec["text"]}, ensure_ascii=False) + "\n")


def write_travel(records):
    path = os.path.join(ROOT, "TRAVEL")
    os.makedirs(path)
    for seq, rec in enumerate(records):
        text = f"PROFILE-ID: {rec['id']}\nAUTHOR: @{rec['handle']}\n\n{rec['text']}\n"
        with open(os.path.join(path, f"journal_{seq:03d}.txt"), "w", encoding="utf-8", newline="\n") as f:
            f.write(text)


def write_market(records):
    with open(os.path.join(ROOT, "MARKET.csv"), "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["profile_id", "seller", "listing_history"])
        w.writeheader()
        for rec in records:
            w.writerow({"profile_id": rec["id"], "seller": rec["handle"],
                        "listing_history": rec["text"]})


def write_social(records):
    path = os.path.join(ROOT, "SOCIAL")
    os.makedirs(path)
    for seq, rec in enumerate(records):
        with open(os.path.join(path, f"snapshot_{seq:03d}.json"), "w", encoding="utf-8", newline="\n") as f:
            json.dump({"profile": {"id": rec["id"], "username": rec["handle"]},
                       "posts_text": rec["text"]}, f, ensure_ascii=False, indent=2)
            f.write("\n")


def guide_text():
    return """ALIAS CORRELATION TASK

확인된 시작 계정은 START_PROFILE.txt에 있다. 같은 사람이 사용한 다음 계정을
아래 플랫폼 순서로 추적하라.

    BLOG -> REVIEWS -> TRAVEL -> MARKET -> SOCIAL

각 계정은 이전 계정에서 공개한 개인적 경험 세 가지를 다른 말로 표현한다.
한두 가지가 우연히 맞는 근접 후보가 있으므로 세 가지가 모두 이어져야 한다.
찾은 계정의 나머지 이야기들은 다음 플랫폼을 찾는 피벗이 된다.

플래그 계산:
1. 위 순서에서 식별한 다섯 PROFILE-ID를 | 로 연결한다.
2. PROFILE-ID는 각 파일의 ASCII 값을 그대로 쓴다.
3. digest = SHA256(material.encode("ascii")).hexdigest()의 앞 24글자
4. FLAG = KCTF{4l14s_ch41n_<digest>}

예시(실제 답 아님):
material = PRF-12AB3400|PRF-98CD7611|...
"""


def start_text():
    facts = TRANSITIONS[0]["source"] + [
        "기록에 따르면 이 계정은 이후 다른 플랫폼에서 여러 별명을 사용했다.",
        "사용자명 자체는 재사용하지 않은 것으로 확인되었다.",
    ]
    return "KNOWN PROFILE\nPROFILE-ID: START-KNOWN\nHANDLE: @paper_crane\n\n" + " ".join(facts) + "\n"


def build():
    rng = random.Random(SEED)
    shutil.rmtree(ROOT, ignore_errors=True)
    os.makedirs(ROOT)
    with open(os.path.join(ROOT, "GUIDE.txt"), "w", encoding="utf-8", newline="\n") as f:
        f.write(guide_text())
    with open(os.path.join(ROOT, "START_PROFILE.txt"), "w", encoding="utf-8", newline="\n") as f:
        f.write(start_text())

    all_records = [profile_records(i, rng) for i in range(len(PLATFORMS))]
    write_blog(all_records[0])
    write_reviews(all_records[1])
    write_travel(all_records[2])
    write_market(all_records[3])
    write_social(all_records[4])

    target_ids = [next(r["id"] for r in records if r["target"]) for records in all_records]
    os.makedirs(DIST, exist_ok=True)
    zip_path = os.path.join(DIST, "alias-chain.zip")
    if os.path.exists(zip_path):
        os.unlink(zip_path)
    # Stored mode removes ZIP compression ratio as a semantic-content oracle.
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_STORED) as zf:
        for base, _, files in os.walk(ROOT):
            for name in sorted(files):
                path = os.path.join(base, name)
                zf.write(path, os.path.relpath(path, DIST))

    print(f"[+] profiles: {len(PLATFORMS) * N_PER_PLATFORM} / hops: {len(PLATFORMS)}")
    print(f"[+] zip: {zip_path}")
    print(f"[+] flag: {flag_for(target_ids)}")


if __name__ == "__main__":
    build()
