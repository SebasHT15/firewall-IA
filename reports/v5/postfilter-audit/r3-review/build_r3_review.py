#!/usr/bin/env python3
"""Deterministic builder for the R3 (ChatGPT GPT-6) post-filter review materials.

Reads ONLY the frozen round-1 artifacts and emits:
  reviewer/batch_XX.jsonl        blinded reviewer packets (NO labels, NO membership) — 217 unique records
  coordinator/manifest.jsonl     canonical manifest (provenance + integrity) per unique record
  coordinator/membership.json    subset/disagreement/overlap bookkeeping + a1/a2 labels (COORDINATOR ONLY)
  coordinator/integrity.json     counts, uniqueness, membership relations, omission/duplicate detection

It writes NO labels and performs NO evaluation. Ordering is deterministic (by sample_id).
Run:  python3 -I reports/v5/postfilter-audit/r3-review/build_r3_review.py
"""
import json, os, hashlib, csv, argparse
from collections import Counter

_HERE = os.path.dirname(os.path.abspath(__file__))
_ap = argparse.ArgumentParser(description="Deterministic builder for the R3 review materials.")
_ap.add_argument("--round1", default=os.path.normpath(os.path.join(_HERE, "..", "round-1")),
                 help="frozen round-1 directory (default: ../round-1 next to this script)")
_ap.add_argument("--out", default=_HERE, help="output directory (default: this script's directory)")
_args = _ap.parse_args()
ROUND1 = _args.round1
OUT = _args.out
BATCH_SIZE = 50
REVIEWER_FIELDS = ["sample_id", "category", "payload_logical", "payload_wire", "source_file"]

def jl(path):
    rows = []
    with open(path) as f:
        for ln in f:
            ln = ln.rstrip("\n")
            if ln.strip():
                rows.append(json.loads(ln))
    return rows

def sha_file(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()

sample = jl(f"{ROUND1}/sample.jsonl")
by_id = {r["sample_id"]: r for r in sample}
a1 = {r["sample_id"]: r["label_class"] for r in jl(f"{ROUND1}/annotations_a1.jsonl")}
a2 = {r["sample_id"]: r["label_class"] for r in jl(f"{ROUND1}/annotations_a2.jsonl")}

subset200 = set()
with open(f"{ROUND1}/human_review/human_review_sample.csv") as f:
    for row in csv.DictReader(f):
        subset200.add(row["sample_id"])
disagr33 = {r["sample_id"] for r in jl(f"{ROUND1}/adjudication_pending.jsonl")}

all_ids = {r["sample_id"] for r in sample}
assert subset200 <= all_ids and disagr33 <= all_ids, "subset/disagreements must be inside the 453 frame"
overlap16 = subset200 & disagr33
union217 = sorted(subset200 | disagr33)   # deterministic order by sample_id

os.makedirs(f"{OUT}/reviewer", exist_ok=True)
os.makedirs(f"{OUT}/coordinator", exist_ok=True)

# ---- reviewer batches (blinded) + canonical manifest + membership ----
manifest, membership, seen = [], [], Counter()
batch_no, line_no, fh = 0, 0, None
for i, sid in enumerate(union217):
    if i % BATCH_SIZE == 0:
        if fh: fh.close()
        batch_no += 1; line_no = 0
        fh = open(f"{OUT}/reviewer/batch_{batch_no:02d}.jsonl", "w")
    line_no += 1
    seen[sid] += 1
    rec = by_id[sid]
    # reviewer packet: reviewer-facing fields only, verbatim, no truncation/normalization
    packet = {k: rec.get(k) for k in REVIEWER_FIELDS}
    fh.write(json.dumps(packet, ensure_ascii=False) + "\n")
    manifest.append({
        "sample_id": sid, "record_id": rec.get("record_id"), "category": rec["category"],
        "source_file": rec["source_file"], "payload_wire_sha256": rec.get("payload_wire_sha256"),
        "batch": f"batch_{batch_no:02d}.jsonl", "line_in_batch": line_no,
    })
    membership.append({
        "sample_id": sid, "category": rec["category"],
        "in_subset_200": sid in subset200, "in_disagreements_33": sid in disagr33,
        "in_overlap_16": sid in overlap16, "a1_label": a1.get(sid), "a2_label": a2.get(sid),
    })
if fh: fh.close()

with open(f"{OUT}/coordinator/manifest.jsonl", "w") as f:
    for m in manifest:
        f.write(json.dumps(m, ensure_ascii=False) + "\n")
with open(f"{OUT}/coordinator/membership.json", "w") as f:
    json.dump({"note": "COORDINATOR ONLY — never shown to R3. Subset/disagreement/overlap bookkeeping and a1/a2 labels.",
               "records": membership}, f, ensure_ascii=False, indent=2)

# ---- integrity ----
duplicates = [sid for sid, c in seen.items() if c > 1]
batch_files = sorted(f for f in os.listdir(f"{OUT}/reviewer")
                     if f.startswith("batch_") and f.endswith(".jsonl"))
packed_ids = []
for bf in batch_files:
    for r in jl(f"{OUT}/reviewer/{bf}"):
        packed_ids.append(r["sample_id"])
integrity = {
    "frame_453": len(all_ids),
    "subset_200": len(subset200), "disagreements_33": len(disagr33),
    "overlap_16": len(overlap16), "unique_217_expected": 217,
    "unique_217_built": len(union217),
    "union_identity_ok": len(union217) == len(subset200) + len(disagr33) - len(overlap16),
    "packed_rows_total": len(packed_ids), "packed_unique": len(set(packed_ids)),
    "duplicates_across_batches": duplicates,
    "missing_from_packing": sorted(set(union217) - set(packed_ids)),
    "extra_in_packing": sorted(set(packed_ids) - set(union217)),
    "batches": {bf: sum(1 for _ in open(f"{OUT}/reviewer/{bf}")) for bf in batch_files},
    "per_category_217": dict(Counter(by_id[s]["category"] for s in union217)),
    "source_hashes": {
        "sample.jsonl": sha_file(f"{ROUND1}/sample.jsonl"),
        "annotations_a1.jsonl": sha_file(f"{ROUND1}/annotations_a1.jsonl"),
        "annotations_a2.jsonl": sha_file(f"{ROUND1}/annotations_a2.jsonl"),
        "adjudication_pending.jsonl": sha_file(f"{ROUND1}/adjudication_pending.jsonl"),
        "human_review_sample.csv": sha_file(f"{ROUND1}/human_review/human_review_sample.csv"),
    },
}
with open(f"{OUT}/coordinator/integrity.json", "w") as f:
    json.dump(integrity, f, ensure_ascii=False, indent=2)

print(json.dumps({k: integrity[k] for k in [
    "unique_217_built", "union_identity_ok", "packed_rows_total", "packed_unique",
    "duplicates_across_batches", "missing_from_packing", "extra_in_packing", "batches", "per_category_217"]},
    ensure_ascii=False, indent=2))
