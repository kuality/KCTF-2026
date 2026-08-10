#!/usr/bin/env python3
"""KCTF 2026 MISC — canary-index problem generator."""

import hashlib
import itertools
import os
import random
import shutil
import zipfile


SEED = 20260810
N_LEAKS = 12
HERE = os.path.dirname(os.path.abspath(__file__))
DIST = os.path.join(HERE, "dist")
ROOT = os.path.join(DIST, "canary-index")


# Every value has two deliberately different surface forms.  The briefing form
# is used in the personalized originals; the leak form is used in the public
# posts.  The relation is semantic, but the final answer is made only from the
# exact ASCII BRIEFING-ID headers.
FACTS = {
    "codename": [
        ("겨울제비", "추운 계절을 나는 작은 철새"),
        ("유리등대", "투명한 재질로 된 항로 표지탑"),
        ("붉은나침반", "진홍색으로 칠한 방향 바늘"),
        ("새벽우산", "해 뜨기 전에 펼치는 비막이"),
        ("은빛고래", "금속빛이 나는 거대한 바다 포유류"),
        ("모래시계", "뒤집어서 시간을 재는 유리 도구"),
        ("푸른장미", "자연에서는 보기 힘든 파란 꽃"),
        ("종이달", "접은 종이로 만든 밤의 위성"),
        ("검은종달새", "어두운 깃의 아침 노래새"),
        ("비취열쇠", "초록 보석으로 만든 문 여는 도구"),
        ("느린혜성", "천천히 지나가는 꼬리별"),
        ("흰소나무", "눈처럼 밝은 빛깔의 침엽수"),
    ],
    "venue": [
        ("해오름호텔 3층", "해가 뜨는 이름의 숙소 세 번째 층"),
        ("은하수서점 지하 1층", "별들이 강처럼 흐르는 이름의 책방 바로 아래층"),
        ("바람항역 4번 출구", "바람 부는 항구 이름의 역에서 네 번째 나가는 길"),
        ("종달새도서관 옥상", "아침 새 이름의 도서관 가장 위 바깥 공간"),
        ("푸른정원카페 별실", "파란 정원을 내건 찻집의 분리된 방"),
        ("느린강미술관 동문", "천천히 흐르는 물길 이름의 전시장 동쪽 문"),
        ("수정극장 2층 로비", "투명한 광물 이름의 극장 두 번째 층 대기 공간"),
        ("모래등대공원 북문", "모래와 항로 표지탑 이름을 함께 쓰는 공원의 북쪽 입구"),
        ("흰고래호텔 7층", "하얀 바다 포유류 이름의 숙소 일곱 번째 층"),
        ("비취시장 12번 창고", "초록 보석 이름의 장터 열두 번째 보관소"),
        ("종이배식당 안쪽방", "접은 배 이름의 식당 가장 안쪽 방"),
        ("붉은우산센터 지하 2층", "빨간 비막이 이름의 센터 아래로 두 층"),
    ],
    "schedule": [
        ("월요일 18시 10분", "일요일 다음 날 저녁 여섯 시에서 십 분 뒤"),
        ("화요일 19시 20분", "월요일 다음 날 저녁 일곱 시에서 이십 분 뒤"),
        ("수요일 20시 30분", "화요일 다음 날 밤 여덟 시 반"),
        ("목요일 21시 40분", "수요일 다음 날 밤 아홉 시에서 사십 분 뒤"),
        ("금요일 17시 50분", "목요일 다음 날 오후 다섯 시에서 오십 분 뒤"),
        ("토요일 14시 15분", "금요일 다음 날 오후 두 시 십오 분"),
        ("일요일 16시 25분", "토요일 다음 날 오후 네 시 이십오 분"),
        ("월요일 22시 05분", "일요일 다음 날 밤 열 시에서 오 분 뒤"),
        ("화요일 06시 35분", "월요일 다음 날 해 뜰 무렵 여섯 시 삼십오 분"),
        ("수요일 11시 45분", "화요일 다음 날 정오를 십오 분 앞둔 때"),
        ("목요일 13시 55분", "수요일 다음 날 오후 두 시를 오 분 앞둔 때"),
        ("금요일 08시 25분", "목요일 다음 날 아침 여덟 시 이십오 분"),
    ],
    "vehicle": [
        ("청색 세단 17하 2046", "파란 승용차이며 번호 끝 네 자리는 이공사육"),
        ("은색 승합차 32로 7185", "금속빛 밴이며 번호 끝은 칠일팔오"),
        ("백색 SUV 09누 4431", "하얀 스포츠형 다목적차이고 끝 번호는 사사삼일"),
        ("적색 해치백 61더 9024", "빨간 소형 뒷문 차량이며 번호 끝은 구공이사"),
        ("녹색 트럭 44마 1358", "초록 화물차이며 끝 네 숫자는 일삼오팔"),
        ("흑색 쿠페 28버 6702", "검은 이인승 승용차이고 마지막 숫자는 육칠공이"),
        ("황색 밴 73소 4816", "노란 승합 차량이며 끝 번호는 사팔일육"),
        ("회색 세단 15고 3290", "잿빛 승용차이고 번호 마지막은 삼이구공"),
        ("남색 SUV 52주 8043", "짙은 푸른 다목적차이며 끝 네 자리는 팔공사삼"),
        ("주황색 픽업 36도 2571", "귤빛 짐칸 차량이고 끝 번호는 이오칠일"),
        ("자주색 왜건 80루 6114", "보랏빛 긴 차체 차량이며 마지막은 육일일사"),
        ("갈색 미니밴 47서 3905", "밤색 소형 승합차이고 끝 네 숫자는 삼구공오"),
    ],
}

FIELD_ORDER = ["codename", "venue", "schedule", "vehicle"]
BRIEFING_BYTES = 700

# Group-specific alternatives for every fact.  Together with ALT2_FACTS they
# form a complete 3^4 grid in which every briefing has eight distance-1
# neighbours.  The target is not the centre of an asymmetric near-miss cluster.
ALT_FACTS = {
    "codename": [
        "여름까치", "청동부표", "푸른풍향계", "한낮외투", "금빛상어", "물시계",
        "붉은백합", "나무별", "흰갈매기", "호박자물쇠", "빠른유성", "검은전나무",
    ],
    "venue": [
        "달그늘여관 5층", "별무리문구점 2층", "돌개울역 1번 출구", "갈매기학교 운동장",
        "붉은마당찻집 본관", "빠른샘박물관 서문", "호박극장 4층 로비", "자갈부표공원 남문",
        "검은상어여관 9층", "청동장터 7번 창고", "나무별분식 바깥방", "푸른외투회관 1층",
    ],
    "schedule": [
        "목요일 09시 12분", "금요일 10시 22분", "토요일 11시 32분", "일요일 12시 42분",
        "월요일 13시 52분", "화요일 14시 02분", "수요일 15시 12분", "목요일 16시 22분",
        "금요일 17시 32분", "토요일 18시 42분", "일요일 19시 52분", "월요일 20시 02분",
    ],
    "vehicle": [
        "회색 왜건 11가 7620", "갈색 트럭 22나 8531", "주황색 쿠페 33다 9442",
        "자주색 세단 44라 1353", "황색 미니밴 55마 2264", "남색 픽업 66바 3175",
        "흑색 승합차 77사 4086", "백색 해치백 88아 5997", "적색 밴 99자 6808",
        "녹색 SUV 10차 7719", "은색 세단 21카 8620", "청색 트럭 32타 9531",
    ],
}

ALT2_FACTS = {
    "codename": [
        "가을참새", "수정봉화", "황금해시계", "저녁장화", "청동문어", "별자리판",
        "흰동백", "천별", "푸른물총새", "수정빗장", "긴꼬리별", "붉은삼나무",
    ],
    "venue": [
        "별내림모텔 6층", "구름길서점 3층", "자갈들역 2번 출구", "물총새회관 테라스",
        "흰화단카페 안채", "맑은못전시관 북문", "청동극장 5층 로비", "조약돌봉화공원 동문",
        "푸른문어호텔 8층", "수정장터 9번 창고", "천별식당 창가방", "황금장화센터 지하 3층",
    ],
    "schedule": [
        "토요일 07시 18분", "일요일 08시 28분", "월요일 09시 38분", "화요일 10시 48분",
        "수요일 11시 58분", "목요일 12시 08분", "금요일 13시 18분", "토요일 14시 28분",
        "일요일 15시 38분", "월요일 16시 48분", "화요일 17시 58분", "수요일 18시 08분",
    ],
    "vehicle": [
        "녹색 쿠페 13거 1420", "남색 왜건 24너 2331", "황색 트럭 35더 3242",
        "회색 SUV 46러 4153", "갈색 밴 57머 5064", "주황색 세단 68버 6975",
        "자주색 픽업 79서 7886", "은색 미니밴 81어 8797", "청색 해치백 92저 9608",
        "백색 승합차 14처 1519", "흑색 SUV 25커 2420", "적색 쿠페 36터 3331",
    ],
}


def stable_id(tag: str) -> str:
    return "BRF-" + hashlib.sha256(f"{SEED}:{tag}".encode()).hexdigest()[:7].upper()


def display_name(n: int) -> str:
    surnames = ["김", "이", "박", "최", "정", "강", "조", "윤", "장", "임", "한", "오"]
    first = ["서준", "서윤", "지호", "수민", "민재", "하은", "도윤", "채원"]
    return surnames[n % len(surnames)] + first[(n // len(surnames)) % len(first)]


def flag_for(ids):
    material = "|".join(ids)
    digest = hashlib.sha256(material.encode("ascii")).hexdigest()[:24]
    return f"KCTF{{c4n4ry_m4tch_{digest}}}"


def briefing_text(record, recipient):
    vals = record["values"]
    text = f"""NORITE SYSTEMS / PERSONALIZED BRIEFING
BRIEFING-ID: {record['id']}
RECIPIENT: {recipient}
CLASSIFICATION: INTERNAL-CANARY

이번 브리핑에서 사용할 호출명은 '{vals['codename']}'으로 확정되었다.
접선 장소는 {vals['venue']}이며, 예정 시각은 {vals['schedule']}이다.
현장에서 확인할 차량은 {vals['vehicle']}이다.

이 문서는 수신자별로 일부 사실이 다르게 배포되었다. 외부 공유를 금한다.
"""
    missing = BRIEFING_BYTES - len(text.encode("utf-8"))
    if missing < 0:
        raise ValueError("briefing exceeds fixed byte budget")
    return text + (" " * missing)


def leak_text(n, group_idx):
    leak = {field: FACTS[field][group_idx][1] for field in FIELD_ORDER}
    intros = [
        "익명 제보로 전달받은 내용을 정리한다.",
        "현장 관계자에게서 들은 이야기다.",
        "내부 일정을 아는 사람이 남긴 메모라고 한다.",
        "출처를 밝힐 수 없는 계정이 게시한 내용이다.",
    ]
    return f"""LEAK-ID: LEAK-{n:02d}
SOURCE: anonymous public post

{intros[(n - 1) % len(intros)]}
작전명은 '{leak['codename']}'라는 표현이었다.
장소 설명은 '{leak['venue']}'였다.
약속 시각은 '{leak['schedule']}'라고 했다.
표식 차량은 '{leak['vehicle']}'라고 한다.
"""


def notes_text():
    return """NORITE SYSTEMS — CANARY LEAK REVIEW

수신자별로 서로 다른 사실을 넣은 브리핑이 외부로 유출되었다.
LEAKS의 각 게시물이 어느 BRIEFING에서 나왔는지 식별하라.

주의:
- 유출문은 원문을 그대로 복사하지 않고 뜻이 같은 말로 바꾸었다.
- 호출명, 장소, 시간, 차량 중 하나만 맞는 문서는 많다.
- 네 사실이 모두 맞는 BRIEFING은 각 LEAK마다 정확히 하나다.

플래그 계산:
1. LEAK-01부터 LEAK-12까지 대응하는 BRIEFING-ID를 순서대로 적는다.
2. ID는 헤더의 ASCII 문자열을 그대로 사용하고, 구분자 | 로 연결한다.
3. digest = SHA256(material.encode("ascii")).hexdigest()의 앞 24글자
4. FLAG = KCTF{c4n4ry_m4tch_<digest>}

예시(실제 답 아님):
material = BRF-12AB340|BRF-98CD761|...
"""


def build():
    rng = random.Random(SEED)
    shutil.rmtree(ROOT, ignore_errors=True)
    os.makedirs(os.path.join(ROOT, "BRIEFINGS"))
    os.makedirs(os.path.join(ROOT, "LEAKS"))

    # Complete 3^4 grid: every record, including the target, has exactly eight
    # one-field neighbours.  Single/pair/triple frequency signatures are also
    # identical, and dropping one fixed fact leaves 3^12 global guesses.
    patterns = list(itertools.product((0, 1, 2), repeat=len(FIELD_ORDER)))
    records = []
    targets = {}
    for group in range(N_LEAKS):
        for variant, offsets in enumerate(patterns):
            values = {}
            for pos, field in enumerate(FIELD_ORDER):
                choice = offsets[pos]
                values[field] = (FACTS[field][group][0] if choice == 0 else
                                 ALT_FACTS[field][group] if choice == 1 else
                                 ALT2_FACTS[field][group])
            record = {
                "group": group,
                "variant": variant,
                "values": values,
                "id": stable_id(f"g{group}:v{variant}"),
            }
            records.append(record)
            if variant == 0:
                targets[group] = record

    rng.shuffle(records)
    for seq, record in enumerate(records):
        path = os.path.join(ROOT, "BRIEFINGS", f"document_{seq:04d}.txt")
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(briefing_text(record, display_name(seq)))

    leak_groups = list(range(N_LEAKS))
    random.Random(SEED ^ 0xC4A4).shuffle(leak_groups)
    answer_ids = []
    for n, group in enumerate(leak_groups, 1):
        with open(os.path.join(ROOT, "LEAKS", f"leak_{n:02d}.txt"),
                  "w", encoding="utf-8", newline="\n") as f:
            f.write(leak_text(n, group))
        answer_ids.append(targets[group]["id"])

    with open(os.path.join(ROOT, "NOTES.txt"), "w", encoding="utf-8", newline="\n") as f:
        f.write(notes_text())

    os.makedirs(DIST, exist_ok=True)
    zip_path = os.path.join(DIST, "canary-index.zip")
    if os.path.exists(zip_path):
        os.unlink(zip_path)
    # Stored mode prevents compressed-size differences from becoming a second
    # classifier for records whose visible UTF-8 lengths are equal.
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_STORED) as zf:
        for base, _, files in os.walk(ROOT):
            for name in sorted(files):
                path = os.path.join(base, name)
                arc = os.path.relpath(path, DIST)
                zf.write(path, arc)

    print(f"[+] briefings: {len(records)} / leaks: {N_LEAKS}")
    print(f"[+] zip: {zip_path}")
    print(f"[+] flag: {flag_for(answer_ids)}")


if __name__ == "__main__":
    build()
