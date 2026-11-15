#!/usr/bin/env python3
"""C-S3: value-masked request-token purity by split, aggregate output only."""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import re

SPLITS = ("TRAIN", "VALIDATION", "INTERNAL_TEST")
TOKEN = re.compile(r"[A-Za-z0-9_]+|[^\w\s]", re.UNICODE)
TRACKED = ("the", "please", "https")


def _masked(text: str, spans: dict) -> str:
    intervals = sorted((int(a), int(b)) for a, b in spans.values())
    last = 0
    chunks = []
    for a, b in intervals:
        if not (last <= a <= b <= len(text)):
            raise ValueError("overlapping or out-of-range value span")
        chunks.append(text[last:a])
        chunks.append(" VALUE ")
        last = b
    chunks.append(text[last:])
    return "".join(chunks)


def check(dataset: Path) -> dict:
    out = {"schema": "v5-cs3-token-purity/v1", "splits": {},
           "thresholds": {"min_coverage": .01, "warn_purity_gte": .80,
                          "block_purity_gte": .95, "tracked_warn_purity_gte": .70}}
    for split in SPLITS:
        texts = [json.loads(x) for x in (dataset / f"rows.{split}.jsonl")
                 .read_text(encoding="utf-8").splitlines()]
        meta = [json.loads(x) for x in (dataset / f"rows.{split}.meta.jsonl")
                .read_text(encoding="utf-8").splitlines()]
        if len(texts) != len(meta):
            raise ValueError(f"row/meta count differs in {split}")
        n = len(meta)
        counts: dict[str, Counter] = defaultdict(Counter)
        for row, record in zip(meta, texts):
            masked = _masked(record["text"], row["leaf_spans"])
            for token in set(TOKEN.findall(masked.lower())):
                counts[token][row["label"]] += 1
        eligible = {token: c for token, c in counts.items() if sum(c.values()) / n >= .01}
        block = warn = 0
        max_purity = 0.0
        for c in eligible.values():
            purity = max(c.values()) / sum(c.values())
            max_purity = max(max_purity, purity)
            block += purity >= .95
            warn += .80 <= purity < .95
        tracked = {}
        for token in TRACKED:
            c = counts.get(token, Counter())
            coverage = sum(c.values()) / n
            purity = max(c.values()) / sum(c.values()) if c else None
            tracked[token] = {"coverage": coverage, "purity": purity,
                              "warn": bool(purity is not None and coverage >= .01 and purity >= .70)}
        out["splits"][split] = {"rows": n, "eligible_tokens": len(eligible),
                                 "max_purity": max_purity, "block_tokens": block,
                                 "warn_tokens": warn, "tracked": tracked,
                                 "blocking_pass": block == 0}
    out["blocking_pass"] = all(x["blocking_pass"] for x in out["splits"].values())
    return out


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("dataset", type=Path)
    p.add_argument("--out", type=Path, required=True)
    a = p.parse_args()
    result = check(a.dataset)
    a.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"blocking_pass": result["blocking_pass"],
                      "blocked_splits": [s for s, x in result["splits"].items()
                                         if not x["blocking_pass"]]}, sort_keys=True))


if __name__ == "__main__":
    main()
