#!/usr/bin/env python3
"""Aggregate, content-free V5 shortcut checks C-S1, C-S2 and C-S6.

This is deliberately a partial §7 checker: C-S3 token purity and C-S4 fitted
structure probe need separate implementations and remain pending.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path

SPLITS = ("TRAIN", "VALIDATION", "INTERNAL_TEST")
FEATURES = ("carrier", "method", "media_type", "encoder_profile", "length_bin",
            "field_names", "struct_cluster_id", "template_id", "placement_mode",
            "attacked_slot_role", "attacked_slot_type")
# `hex_normalized` is computed solely from BLOCK payload_wire (generator line
# 477); it is neither an envelope feature nor independently populated for the
# benign twin. Treating this provenance flag as model-visible structure would
# manufacture a shortcut failure. Visible encoder_profile remains checked.


def _val(row: dict, key: str) -> str:
    return json.dumps(row.get(key), sort_keys=True, ensure_ascii=False)


def _cells(rows: list[dict], key: str) -> dict[str, Counter]:
    groups: dict[str, Counter] = defaultdict(Counter)
    for row in rows:
        groups[_val(row, key)][row["label"]] += 1
    return groups


def _score(rows: list[dict], key: str) -> dict:
    groups = _cells(rows, key)
    n = len(rows)
    accuracy = sum(max(c.values()) for c in groups.values()) / n if n else None
    baseline = max(Counter(x["label"] for x in rows).values()) / n if n else None
    return {"accuracy": accuracy, "margin": accuracy - baseline if n else None,
            "levels": len(groups), "rows": n}


def check(dataset: Path) -> dict:
    result = {"schema": "v5-shortcut-checks/v1-PARTIAL", "coverage": ["C-S1", "C-S2", "C-S6"],
              "pending": ["C-S3", "C-S4"], "splits": {}}
    for split in SPLITS:
        rows = [json.loads(x) for x in (dataset / f"rows.{split}.meta.jsonl")
                .read_text(encoding="utf-8").splitlines()]
        # Benign twin records do not carry payload_family_id. Resolve family
        # membership through the pair, without emitting family identities.
        pair_family = {r["pair_id"]: r["payload_family_id"] for r in rows
                       if r.get("payload_family_id") is not None}
        families: dict[str, list[dict]] = defaultdict(list)
        for row in rows:
            family = pair_family.get(row["pair_id"])
            if family is not None:
                families[family].append(row)

        s1 = {feature: _score(rows, feature) for feature in FEATURES}
        s1_fail = [f for f, value in s1.items()
                   if value["accuracy"] >= .80 or value["margin"] >= .10]
        within_fail = 0
        within_checked = 0
        for family_rows in families.values():
            for feature in FEATURES:
                score = _score(family_rows, feature)
                within_checked += 1
                within_fail += score["accuracy"] >= .80 or score["margin"] >= .10

        s2_fail = 0
        s2_max_purity = 0.0
        s2_levels = 0
        for feature in FEATURES:
            for counts in _cells(rows, feature).values():
                total = sum(counts.values())
                if total / len(rows) < .01:
                    continue
                purity = max(counts.values()) / total
                s2_levels += 1
                s2_max_purity = max(s2_max_purity, purity)
                s2_fail += purity >= .99

        s6_levels = 0
        s6_block = 0
        s6_warn = 0
        s6_min_ratio = 1.0
        for family_rows in families.values():
            # Carrier-feature levels follow the same non-payload feature set as S1.
            for feature in FEATURES:
                for counts in _cells(family_rows, feature).values():
                    a, b = counts["ALLOW"], counts["BLOCK"]
                    if (a + b) / len(family_rows) < .01:
                        continue
                    ratio = min(a, b) / max(a, b) if max(a, b) else 1.0
                    s6_levels += 1
                    s6_min_ratio = min(s6_min_ratio, ratio)
                    s6_block += ratio < .50
                    s6_warn += .50 <= ratio < .80

        result["splits"][split] = {
            "C-S1": {"global_features": s1, "global_block_features": sorted(s1_fail),
                     "family_feature_checks": within_checked, "family_feature_blocks": within_fail,
                     "blocking_pass": not s1_fail and within_fail == 0},
            "C-S2": {"eligible_levels": s2_levels, "max_purity": s2_max_purity,
                     "blocked_levels": s2_fail, "blocking_pass": s2_fail == 0},
            "C-S6": {"eligible_levels": s6_levels, "minimum_ratio": s6_min_ratio,
                     "blocked_levels": s6_block, "warn_levels": s6_warn,
                     "blocking_pass": s6_block == 0},
        }
    result["blocking_pass_for_checks_run"] = all(
        r[gate]["blocking_pass"] for r in result["splits"].values()
        for gate in result["coverage"])
    result["freeze_ready"] = False
    return result


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("dataset", type=Path)
    p.add_argument("--out", type=Path, required=True)
    a = p.parse_args()
    result = check(a.dataset)
    a.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"blocking_pass_for_checks_run": result["blocking_pass_for_checks_run"],
                      "pending": result["pending"]}, sort_keys=True))


if __name__ == "__main__":
    main()
