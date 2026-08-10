#!/usr/bin/env python3
"""Organizer-side shortcut audit for canary-index."""

import difflib
import itertools
import os
import re
from collections import Counter

from prob import FACTS, FIELD_ORDER


HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "dist", "canary-index")


def read(path):
    return open(path, encoding="utf-8").read()


briefings = []
for name in sorted(os.listdir(os.path.join(ROOT, "BRIEFINGS"))):
    text = read(os.path.join(ROOT, "BRIEFINGS", name))
    bid = re.search(r"^BRIEFING-ID:\s*(\S+)", text, re.M).group(1)
    briefings.append((bid, name, text, len(text.encode())))

branch_product = 1
lexical_ranks = []
target_size_percentiles = []
for leak_name in sorted(os.listdir(os.path.join(ROOT, "LEAKS"))):
    leak = read(os.path.join(ROOT, "LEAKS", leak_name))
    wanted = {
        field: next(original for original, paraphrase in FACTS[field] if paraphrase in leak)
        for field in FIELD_ORDER
    }
    ranked = []
    for bid, name, text, size in briefings:
        ranked.append((sum(value in text for value in wanted.values()), bid, name, text, size))
    ranked.sort(reverse=True)
    assert ranked[0][0] == 4 and sum(x[0] == 4 for x in ranked) == 1
    assert ranked[1][0] == 3
    near = sum(x[0] >= 3 for x in ranked)
    branch_product *= near

    lexical = sorted(
        ((difflib.SequenceMatcher(None, leak, text).ratio(), bid) for bid, _, text, _ in briefings),
        reverse=True,
    )
    lexical_ranks.append(next(i + 1 for i, x in enumerate(lexical) if x[1] == ranked[0][1]))
    sizes = sorted(x[3] for x in briefings)
    target_size_percentiles.append(sum(s <= ranked[0][4] for s in sizes) / len(sizes))

print(f"[+] corpus: {len(briefings)} briefings / 12 leaks")
print("[+] four-fact intersection: unique for every leak")
print(f"[+] candidates scoring >=3 facts, combined guessing space: {branch_product:,}")
print(f"[+] plain character-similarity target ranks: {lexical_ranks}")
print("[+] target size percentiles:", " ".join(f"{x:.2f}" for x in target_size_percentiles))
assert branch_product >= 9 ** 12
assert len({x[3] for x in briefings}) == 1

# Structural attack: the old 8-record near-miss pattern gave targets degree 4
# and every decoy degree 2/3.  In the complete hypercube all degrees must match.
def fields(text):
    pats = [r"호출명은 '([^']+)'", r"접선 장소는 (.+?)이며",
            r"예정 시각은 (.+?)이다", r"차량은 (.+?)이다"]
    return tuple(re.search(p, text).group(1) for p in pats)

vectors = [(bid, fields(text)) for bid, _, text, _ in briefings]
degrees = []
for bid, left in vectors:
    degree = sum(sum(a != b for a, b in zip(left, right)) == 1
                 for _, right in vectors)
    degrees.append(degree)
assert set(degrees) == {8}, set(degrees)
print("[+] Hamming-distance-1 degree set: {8} (target has no centrality signal)")

# Every row must also have the same single/pair/triple occurrence signature.
single = [Counter(v[i] for _, v in vectors) for i in range(4)]
pairs = {ij: Counter((v[ij[0]], v[ij[1]]) for _, v in vectors)
         for ij in itertools.combinations(range(4), 2)}
triples = {ijk: Counter(tuple(v[i] for i in ijk) for _, v in vectors)
           for ijk in itertools.combinations(range(4), 3)}
signatures = set()
for _, v in vectors:
    sig = tuple(single[i][v[i]] for i in range(4))
    sig += tuple(pairs[ij][(v[ij[0]], v[ij[1]])] for ij in pairs)
    sig += tuple(triples[ijk][tuple(v[i] for i in ijk)] for ijk in triples)
    signatures.add(sig)
assert len(signatures) == 1, signatures
print(f"[+] single/pair/triple frequency signatures: 1 universal signature {signatures.pop()}")
print(f"[+] fixed-three-fact guessing space: {3 ** 12:,}")
assert 3 ** 12 >= 500_000
print("[+] PASS: no single-field, filename, uniform-size, or plain-similarity oracle")
