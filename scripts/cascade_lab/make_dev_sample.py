"""
Build a reproducible DEVELOPMENT sample of HTTP requests for the cascade lab.

Source: `eval.jsonl` — the committed, NON-PROTECTED legacy V4-era labeled set at
the repo root. This is DEVELOPMENT traffic for exercising the cascade routes and
measuring cost/latency mechanics. It is NOT a protected evaluation set, NOT
held-out, and may overlap V5 training sources, so it must NOT be used for a
generalization or security headline (D18/D60; TRAIN-only categories). Protected
sets (INTERNAL_TEST / STAB-HELD / E6 / external) are never touched here.

Each input is normalized to a well-framed HTTP/1.1 wire request: LF -> CRLF, and a
`Content-Length` header is injected for requests that carry a body (the legacy
inputs omit it), so the strict wire parser frames them unambiguously.

Output: JSONL rows {id, wire, label, category, source}. Deterministic under --seed.
"""
import argparse
import json
import os
import random
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
EVAL = os.path.join(REPO, "eval.jsonl")


def to_wire(input_text: str) -> str:
    """Normalize a legacy V4 input into a well-framed HTTP/1.1 request string."""
    if "\n\n" in input_text:
        head, body = input_text.split("\n\n", 1)
    else:
        head, body = input_text, ""
    head_lines = head.split("\n")
    # inject Content-Length when a body is present and none is declared
    if body and not any(l.lower().startswith("content-length:") for l in head_lines):
        head_lines.append("Content-Length: %d" % len(body.encode("utf-8")))
    wire = "\r\n".join(head_lines) + "\r\n\r\n" + body
    return wire


def label_of(output: str):
    out = output.replace("###END###", "").strip()
    decision = out.split("|", 1)[0].strip().split()[0]
    category = out.split("|", 1)[1].strip() if "|" in out else ""
    return decision, category


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=600)
    ap.add_argument("--seed", type=int, default=20261026)
    ap.add_argument("--per-category-cap", type=int, default=70)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    rows = []
    with open(EVAL, encoding="utf-8") as f:
        for i, line in enumerate(f):
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            dec, cat = label_of(r["output"])
            rows.append({"idx": i, "input": r["input"], "label": dec, "category": cat})

    rng = random.Random(args.seed)
    rng.shuffle(rows)

    # stratify: half ALLOW, half BLOCK; within BLOCK spread across categories with a cap.
    want_block = args.n // 2
    want_allow = args.n - want_block
    allow = [r for r in rows if r["label"] == "ALLOW"][:want_allow]
    by_cat = defaultdict(list)
    for r in rows:
        if r["label"] == "BLOCK":
            by_cat[r["category"]].append(r)
    block = []
    cats = sorted(by_cat)
    # round-robin across categories up to the cap, until we reach want_block
    pos = {c: 0 for c in cats}
    while len(block) < want_block and any(pos[c] < min(len(by_cat[c]), args.per_category_cap) for c in cats):
        for c in cats:
            if len(block) >= want_block:
                break
            if pos[c] < min(len(by_cat[c]), args.per_category_cap):
                block.append(by_cat[c][pos[c]])
                pos[c] += 1
    sample = allow + block
    rng.shuffle(sample)

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as out:
        for k, r in enumerate(sample):
            out.write(json.dumps({
                "id": "dev-%05d" % k,
                "wire": to_wire(r["input"]),
                "label": r["label"],
                "category": r["category"],
                "source": "eval.jsonl:legacy-v4-dev:idx%d" % r["idx"],
            }, ensure_ascii=False) + "\n")

    n_allow = sum(1 for r in sample if r["label"] == "ALLOW")
    print("wrote %d rows (%d ALLOW, %d BLOCK) to %s"
          % (len(sample), n_allow, len(sample) - n_allow, args.out))
    catcount = defaultdict(int)
    for r in sample:
        if r["label"] == "BLOCK":
            catcount[r["category"]] += 1
    for c, n in sorted(catcount.items(), key=lambda x: -x[1]):
        print("  %4d  %s" % (n, c))


if __name__ == "__main__":
    main()
