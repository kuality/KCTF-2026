#!/usr/bin/env python3
"""
열화 파라미터 보정용 하네스 (출제자 전용, 배포물에는 포함하지 않는다).

표본 조각을 렌더링하고 레퍼런스 솔버의 1차 OCR 을 돌려 체크섬 통과율을 실측한다.
목표: 92~97%.
  - 100% 면 열화가 약해서 '재시도 루프' 라는 교육 포인트가 사라진다
  - 90% 미만이면 재시도 물량이 과해서 LOW 난이도가 아니다
"""
import os
import random
import shutil
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import prob
import solve

SAMPLE = int(sys.argv[1]) if len(sys.argv) > 1 else 80
TMP = "/tmp/shredded_calib"


def main():
    lines = prob.build_lines()
    truth = {}

    if os.path.isdir(TMP):
        shutil.rmtree(TMP)
    os.makedirs(TMP)

    rng = random.Random(prob.SEED)
    picks = random.Random(99).sample(range(prob.N_FRAGMENTS), SAMPLE)

    t = time.time()
    for n, i in enumerate(picks):
        idx, data, chk = lines[i]
        path = os.path.join(TMP, f"{n:04d}.png")
        prob.render_fragment(rng, idx, data, chk, path)
        truth[path] = (idx, data, chk)
    print(f"{SAMPLE}장 렌더 {time.time() - t:.1f}s")

    t = time.time()
    ok = bad = 0
    false_pass = 0
    wrong_examples = []

    for path, (idx, data, chk) in truth.items():
        rec = solve.ocr_fragment(path, solve.PREPROC_DEFAULT)
        if rec is None:
            bad += 1
            wrong_examples.append((f"{idx}|{data}", "PARSE-FAIL"))
            continue
        r_idx, r_data, r_chk = rec
        passes = solve.checksum_ok(r_idx, r_data, r_chk)
        correct = (r_idx, r_data, r_chk) == (idx, data, chk)
        if passes and not correct:
            false_pass += 1  # 체크섬을 통과했는데 실제로는 틀림 = 최악
            wrong_examples.append((f"{idx}|{data}|{chk}",
                                   f"{r_idx}|{r_data}|{r_chk} (FALSE PASS)"))
        elif passes:
            ok += 1
        else:
            bad += 1
            if len(wrong_examples) < 8:
                wrong_examples.append((f"{idx}|{data}|{chk}",
                                       f"{r_idx}|{r_data}|{r_chk}"))

    total = len(truth)
    print(f"OCR {time.time() - t:.1f}s\n")
    print(f"  1차 체크섬 통과 : {ok}/{total}  ({ok / total * 100:.1f}%)")
    print(f"  재시도 필요     : {bad}/{total}  ({bad / total * 100:.1f}%)")
    print(f"  FALSE PASS      : {false_pass}   <- 0 이어야 한다")
    print()
    for a, b in wrong_examples[:8]:
        print(f"    정답 {a}")
        print(f"    인식 {b}\n")

    rate = ok / total * 100
    if false_pass:
        print("!! FALSE PASS 발생 — 체크섬이 오독을 못 잡고 있다")
    elif rate > 97:
        print(">> 열화가 약하다. 노이즈 sigma / 대비 감쇠를 키울 것")
    elif rate < 90:
        print(">> 열화가 세다. LOW 난이도를 벗어남")
    else:
        print(">> 목표 구간(92~97%) 근처. 양호")


if __name__ == "__main__":
    main()
