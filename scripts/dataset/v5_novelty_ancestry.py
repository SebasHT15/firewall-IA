#!/usr/bin/env python3
"""L10/L11: aggregate payload novelty and CSIC ancestry screens.

Does not emit protected request text or CSIC content. Record IDs identify
publicly curated payloads so any L11 hit can receive an explicit ruling.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/dataset"))
from parse_dataset_v4 import canonical_key  # noqa: E402

SPLITS = ("TRAIN", "VALIDATION", "INTERNAL_TEST")


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check(dataset: Path, attack_pool: Path, v4_train: Path, csic: Path) -> dict:
    if sha(csic) != "c420f0bc0464376de75b6c419a0ac226fe69fe12c8ac4908843273721e44e637":
        raise ValueError("CSIC source hash differs from registered local input")
    records = {r["record_id"]: r for r in (json.loads(x) for x in attack_pool.open(encoding="utf-8"))}
    v4_requests = [canonical_key(json.loads(x)["input"]) for x in v4_train.open(encoding="utf-8")]
    csic_bytes = csic.read_bytes()
    ids_by_split = {}
    for split in SPLITS:
        meta = (json.loads(x) for x in (dataset / f"rows.{split}.meta.jsonl").open(encoding="utf-8"))
        ids_by_split[split] = [r["payload_record_id"] for r in meta if r["label"] == "BLOCK"]
    all_ids = {rid for ids in ids_by_split.values() for rid in ids}
    missing = sorted(all_ids - records.keys())
    if missing:
        raise ValueError(f"{len(missing)} payload record ids missing from source")
    novelty = {}
    ancestry = {}
    for rid in all_ids:
        payload = records[rid]["payload_wire"]
        canon = canonical_key(payload)
        novelty[rid] = bool(canon and any(canon in request for request in v4_requests))
        raw = payload.encode("utf-8")
        ancestry[rid] = bool(raw and raw in csic_bytes)
    splits = {}
    for split, ids in ids_by_split.items():
        n = len(ids)
        v4_count = sum(novelty[rid] for rid in ids)
        csic_count = sum(ancestry[rid] for rid in ids)
        splits[split] = {"block_rows": n,
                         "v4_canonical_substring_rows": v4_count,
                         "v4_share": v4_count / n if n else None,
                         "L10_warn": split != "TRAIN" and n > 0 and v4_count / n > .5,
                         "csic_literal_substring_rows": csic_count,
                         "csic_hit_record_ids": sorted({rid for rid in ids if ancestry[rid]}),
                         "L11_rulings_required": len({rid for rid in ids if ancestry[rid]})}
    return {"schema": "v5-l10-l11-screen/v1", "dataset_manifest_sha256": sha(dataset / "manifest.json"),
            "source_sha256": {"attack_pool": sha(attack_pool), "v4_train": sha(v4_train), "csic": sha(csic)},
            "splits": splits, "L11_unique_hit_record_ids": sorted(rid for rid in all_ids if ancestry[rid])}


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("dataset", type=Path)
    p.add_argument("--attack-pool", type=Path, default=ROOT / "datasets/v5_sources/final_candidate/attack_pool.jsonl")
    p.add_argument("--v4-train", type=Path, default=ROOT / "datasets/v4_clean/train.jsonl")
    p.add_argument("--csic", type=Path, default=ROOT / "csic_database.csv")
    p.add_argument("--out", type=Path, required=True)
    a = p.parse_args()
    result = check(a.dataset, a.attack_pool, a.v4_train, a.csic)
    a.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"L10_warn_splits": [s for s, x in result["splits"].items() if x["L10_warn"]],
                      "L11_unique_hit_records": len(result["L11_unique_hit_record_ids"])}, sort_keys=True))


if __name__ == "__main__":
    main()
