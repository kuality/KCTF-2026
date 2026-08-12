#!/usr/bin/env python3
"""Reference solver for canary-index."""

import hashlib
import os
import re
import sys

from prob import FACTS, FIELD_ORDER


def read_text(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def briefing_id(text):
    m = re.search(r"^BRIEFING-ID:\s*(BRF-[0-9A-F]+)\s*$", text, re.M)
    if not m:
        raise ValueError("BRIEFING-ID missing")
    return m.group(1)


def solve(root):
    briefings = []
    bdir = os.path.join(root, "BRIEFINGS")
    for name in sorted(os.listdir(bdir)):
        text = read_text(os.path.join(bdir, name))
        briefings.append((briefing_id(text), name, text))

    answer = []
    ldir = os.path.join(root, "LEAKS")
    for leak_name in sorted(os.listdir(ldir)):
        leak = read_text(os.path.join(ldir, leak_name))
        wanted = {}
        for field in FIELD_ORDER:
            hits = [brief for brief, leaked in FACTS[field] if leaked in leak]
            if len(hits) != 1:
                raise ValueError(f"{leak_name}: {field} semantic normalization failed")
            wanted[field] = hits[0]

        ranked = []
        for bid, filename, text in briefings:
            score = sum(value in text for value in wanted.values())
            ranked.append((score, bid, filename))
        ranked.sort(reverse=True)
        if ranked[0][0] != 4 or ranked[1][0] != 3:
            raise AssertionError(f"bad candidate shape: {leak_name} {ranked[:3]}")
        answer.append(ranked[0][1])
        print(f"{leak_name}: {ranked[0][1]}  (4/4 facts; runner-up 3/4)")

    material = "|".join(answer)
    digest = hashlib.sha256(material.encode("ascii")).hexdigest()[:24]
    return f"KCTF{{c4n4ry_m4tch_{digest}}}"


if __name__ == "__main__":
    default = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dist", "canary-index")
    print("FLAG:", solve(sys.argv[1] if len(sys.argv) > 1 else default))
