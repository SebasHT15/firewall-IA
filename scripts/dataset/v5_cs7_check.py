#!/usr/bin/env python3
"""Count value-pool element dominance per split and class (D75 C-S7).

Only aggregate counts leave this checker; held-out element IDs and rows are never
included in its output. Each element counts at most once per row.
"""
from __future__ import annotations

import argparse
from collections import Counter
import json
from pathlib import Path

SPLITS = ("TRAIN", "VALIDATION", "INTERNAL_TEST")
CLASSES = ("ALLOW", "BLOCK")
WARN = 0.01
BLOCK = 0.03


def check(dataset: Path, preregistration: Path | None = None) -> dict:
    amended = False
    if preregistration is not None:
        policy = json.loads(preregistration.read_text(encoding="utf-8"))["ratified"]["acceptance_thresholds"]["C-S7"]
        amended = (policy.get("owner_ruling") == "D76"
                   and policy.get("TRAIN") == "BLOCK_ABOVE_0.03"
                   and policy.get("VALIDATION") == "WARN_ONLY_REPORT_EXCESS"
                   and policy.get("INTERNAL_TEST") == "WARN_ONLY_REPORT_EXCESS")
    cells = {}
    for split in SPLITS:
        rows = [json.loads(line) for line in
                (dataset / f"rows.{split}.meta.jsonl").read_text(encoding="utf-8").splitlines()]
        for label in CLASSES:
            selected = [row for row in rows if row.get("disposition") == "split"
                        and row.get("label") == label]
            n = len(selected)
            counts = Counter(element for row in selected
                             for element in {tuple(entry) for entry in row.get("value_entries", [])})
            maximum = max(counts.values(), default=0)
            over_warn = sum(count / n > WARN for count in counts.values()) if n else 0
            over_block = sum(count / n > BLOCK for count in counts.values()) if n else 0
            raw_status = "BLOCK" if over_block else "WARN" if over_warn else "PASS"
            status = "WARN" if amended and split != "TRAIN" and raw_status == "BLOCK" else raw_status
            cells[f"{split}|{label}"] = {
                "rows": n, "distinct_elements": len(counts),
                "max_element_rows": maximum,
                "max_element_share": maximum / n if n else None,
                "elements_over_warn": over_warn,
                "elements_over_block": over_block,
                "raw_status": raw_status, "status": status,
            }
    return {"schema": "v5-cs7-check/v1", "thresholds": {"warn_gt": WARN, "block_gt": BLOCK},
            "owner_ruling": "D76" if amended else None,
            "cells": cells, "blocking_pass": all(x["status"] != "BLOCK" for x in cells.values())}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--preregistration", type=Path)
    args = parser.parse_args()
    result = check(args.dataset, args.preregistration)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"blocking_pass": result["blocking_pass"],
                      "blocked_cells": [k for k, v in result["cells"].items() if v["status"] == "BLOCK"]},
                     sort_keys=True))


if __name__ == "__main__":
    main()
