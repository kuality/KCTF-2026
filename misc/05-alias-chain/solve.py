#!/usr/bin/env python3
"""Reference solver for alias-chain."""

import csv
import hashlib
import html
import json
import os
import re
import sys

from prob import PLATFORMS, TRANSITIONS


def load_profiles(root, platform):
    out = []
    if platform == "BLOG":
        path = os.path.join(root, "BLOG")
        for name in sorted(os.listdir(path)):
            text = open(os.path.join(path, name), encoding="utf-8").read()
            pid = re.search(r'<meta name="profile-id" content="([^"]+)">', text).group(1)
            article = re.search(r"<article>(.*?)</article>", text, re.S).group(1)
            out.append((pid, html.unescape(article)))
    elif platform == "REVIEWS":
        for line in open(os.path.join(root, "REVIEWS.jsonl"), encoding="utf-8"):
            row = json.loads(line)
            out.append((row["profile_id"], row["review_history"]))
    elif platform == "TRAVEL":
        path = os.path.join(root, "TRAVEL")
        for name in sorted(os.listdir(path)):
            text = open(os.path.join(path, name), encoding="utf-8").read()
            pid = re.search(r"^PROFILE-ID:\s*(\S+)", text, re.M).group(1)
            out.append((pid, text.split("\n\n", 1)[1].rstrip("\n")))
    elif platform == "MARKET":
        with open(os.path.join(root, "MARKET.csv"), encoding="utf-8") as f:
            for row in csv.DictReader(f):
                out.append((row["profile_id"], row["listing_history"]))
    elif platform == "SOCIAL":
        path = os.path.join(root, "SOCIAL")
        for name in sorted(os.listdir(path)):
            row = json.load(open(os.path.join(path, name), encoding="utf-8"))
            out.append((row["profile"]["id"], row["posts_text"]))
    return out


def solve(root):
    answer = []
    for i, platform in enumerate(PLATFORMS):
        profiles = load_profiles(root, platform)
        ranked = []
        for pid, text in profiles:
            score = sum(phrase in text for phrase in TRANSITIONS[i]["match"])
            ranked.append((score, pid, text))
        ranked.sort(key=lambda x: (-x[0], x[1]))
        if ranked[0][0] != 3 or ranked[1][0] != 2:
            raise AssertionError(f"bad candidate shape at {platform}: {ranked[:3]}")
        answer.append(ranked[0][1])
        print(f"{platform:7s}: {ranked[0][1]}  (3/3 memories; runner-up 2/3)")

    material = "|".join(answer)
    digest = hashlib.sha256(material.encode("ascii")).hexdigest()[:24]
    return f"KCTF{{4l14s_ch41n_{digest}}}"


if __name__ == "__main__":
    default = os.path.join(os.path.dirname(os.path.abspath(__file__)), "dist", "alias-chain")
    print("FLAG:", solve(sys.argv[1] if len(sys.argv) > 1 else default))
