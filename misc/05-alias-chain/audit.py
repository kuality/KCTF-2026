#!/usr/bin/env python3
"""Organizer-side shortcut audit for alias-chain."""

import difflib
import csv
import json
import math
import os
import re
import zlib
from collections import Counter

from prob import N_PER_PLATFORM, PLATFORMS, TARGET_POSITIONS, TRANSITIONS
from solve import load_profiles


HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "dist", "alias-chain")
CODA = " — 이 기록은 날짜와 함께 개인 공책에도 자세히 남겨 두었다"


def load_raw_records(platform):
    """Return the exact per-profile container bytes used by recompression attacks."""
    out = {}
    if platform == "BLOG":
        folder = os.path.join(ROOT, "BLOG")
        for name in sorted(os.listdir(folder)):
            raw = open(os.path.join(folder, name), "rb").read()
            pid = re.search(rb'profile-id" content="([^"]+)"', raw).group(1).decode()
            out[pid] = raw
    elif platform == "REVIEWS":
        for raw in open(os.path.join(ROOT, "REVIEWS.jsonl"), "rb").read().splitlines():
            out[json.loads(raw)["profile_id"]] = raw
    elif platform == "TRAVEL":
        folder = os.path.join(ROOT, "TRAVEL")
        for name in sorted(os.listdir(folder)):
            raw = open(os.path.join(folder, name), "rb").read()
            pid = re.search(rb"^PROFILE-ID:\s*(\S+)", raw, re.M).group(1).decode()
            out[pid] = raw
    elif platform == "MARKET":
        lines = open(os.path.join(ROOT, "MARKET.csv"), "rb").read().splitlines()
        for raw in lines[1:]:
            pid = next(csv.reader([raw.decode("utf-8")]))[0]
            out[pid] = raw
    elif platform == "SOCIAL":
        folder = os.path.join(ROOT, "SOCIAL")
        for name in sorted(os.listdir(folder)):
            raw = open(os.path.join(folder, name), "rb").read()
            out[json.loads(raw)["profile"]["id"]] = raw
    return out

source = open(os.path.join(ROOT, "START_PROFILE.txt"), encoding="utf-8").read()
lexical_ranks = []
branch_product = 1
compression_failures = []

for i, platform in enumerate(PLATFORMS):
    profiles = load_profiles(ROOT, platform)
    ranked = sorted(
        ((sum(q in text for q in TRANSITIONS[i]["match"]), pid, text)
         for pid, text in profiles),
        key=lambda x: (-x[0], x[1]),
    )
    assert len(profiles) == N_PER_PLATFORM
    assert ranked[0][0] == 3 and sum(x[0] == 3 for x in ranked) == 1
    assert ranked[1][0] == 2
    near = sum(x[0] >= 2 for x in ranked)
    branch_product *= near

    lexical = sorted(
        ((difflib.SequenceMatcher(None, source, text).ratio(), pid) for pid, text in profiles),
        reverse=True,
    )
    lexical_ranks.append(next(j + 1 for j, x in enumerate(lexical) if x[1] == ranked[0][1]))
    sizes = {len(text.encode("utf-8")) for _, text in profiles}
    assert len(sizes) == 1, (platform, sizes)
    meaningful = sorted((len(text.rstrip().encode("utf-8")), pid) for pid, text in profiles)
    meaningful_rank = next(j + 1 for j, (_, pid) in enumerate(meaningful)
                           if pid == ranked[0][1])
    assert 5 <= meaningful_rank <= N_PER_PLATFORM - 4, (platform, meaningful_rank)

    raw_records = load_raw_records(platform)
    compression_ranks = {}
    for level in (6, 9):
        level_ranks = []
        for payloads in (
            raw_records,
            {pid: re.sub(rb" {20,}", b"", raw) for pid, raw in raw_records.items()},
            {pid: text.rstrip().encode("utf-8") for pid, text in profiles},
        ):
            ordered = sorted(
                ((len(zlib.compress(raw, level)), pid) for pid, raw in payloads.items()),
                reverse=True,
            )
            rank = next(j + 1 for j, (_, pid) in enumerate(ordered)
                        if pid == ranked[0][1])
            if not 5 <= rank <= N_PER_PLATFORM - 4:
                compression_failures.append((platform, level, rank, ordered[:5]))
            level_ranks.append(rank)
        compression_ranks[level] = level_ranks

    # Every record must have the same exact-sentence rarity signature.  This
    # catches the old [1,1,1,6,6,6] target-only marker.
    sentences = {
        pid: [x.strip() + "." for x in re.split(r"\.\s*", text.strip()) if x.strip()]
        for pid, text in profiles
    }
    freq = Counter(sentence for parts in sentences.values() for sentence in parts)
    signatures = {tuple(sorted(freq[s] for s in parts)) for parts in sentences.values()}
    assert signatures == {(9, 9, 9, 9, 9, 9)}, (platform, signatures)

    normalized = {pid: text.replace(CODA, "") for pid, text in profiles}
    norm_sentences = {
        pid: [x.strip() + "." for x in re.split(r"\.\s*", text.strip()) if x.strip()]
        for pid, text in normalized.items()
    }
    norm_freq = Counter(s for parts in norm_sentences.values() for s in parts)
    norm_signatures = {
        tuple(sorted(norm_freq[s] for s in parts)) for parts in norm_sentences.values()
    }
    assert norm_signatures == {(9, 9, 9, 9, 9, 9)}, (platform, norm_signatures)

    coda_counts = {pid: text.count(CODA) for pid, text in profiles}
    target_coda_count = coda_counts[ranked[0][1]]
    coda_ties = sum(count == target_coda_count for count in coda_counts.values())
    assert coda_ties >= 9, (platform, target_coda_count, coda_ties)

    # Regression for the blind tester's generalized tail-template shortcut.
    def collapse_tail_templates(text):
        out = []
        for sentence in [x.strip() + "." for x in text.strip().split(".") if x.strip()]:
            if "손잡이" in sentence and "상자에 넣어 둔다" in sentence:
                sentence = "<BOX>."
            elif "기념품을 산다" in sentence:
                sentence = "<SOUVENIR>."
            elif sentence.endswith("구했다."):
                sentence = "<ACQUIRE>."
            out.append(sentence)
        return out

    collapsed = {pid: collapse_tail_templates(text) for pid, text in profiles}
    collapsed_freq = Counter(s for parts in collapsed.values() for s in parts)
    idf_scores = {
        pid: sum(math.log(N_PER_PLATFORM / collapsed_freq[s]) for s in parts)
        for pid, parts in collapsed.items()
    }
    best = max(idf_scores.values())
    best_ties = sum(abs(score - best) < 1e-12 for score in idf_scores.values())
    assert best_ties >= 9, (platform, best_ties)
    source_order = [pid for pid, _ in profiles]
    actual_position = source_order.index(ranked[0][1])
    assert actual_position == TARGET_POSITIONS[i]
    assert actual_position not in (0, N_PER_PLATFORM - 1)
    source = ranked[0][2]
    print(f"[+] {platform}: unique 3/3, >=2-fact candidates={near}, "
          f"equal text bytes={sizes.pop()}, rarity=(9,9,9,9,9,9), "
          f"meaningful-length rank={meaningful_rank}/{N_PER_PLATFORM}, "
          f"zlib ranks={compression_ranks}, "
          f"old-template top ties={best_ties}, coda-count ties={coda_ties}, "
          f"target position={actual_position}")

print(f"[+] two-fact-only combined guessing space: {branch_product:,}")
print(f"[+] plain character-similarity target ranks: {lexical_ranks}")
assert branch_product >= 7 ** 5
assert max(lexical_ranks) >= 10
assert not compression_failures, compression_failures
print("[+] PASS: no length, zlib-recompression, filename, username, two-fact, or plain-similarity oracle")
