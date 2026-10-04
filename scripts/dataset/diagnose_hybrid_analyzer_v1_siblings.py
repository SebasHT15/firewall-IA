"""
firewall-IA — sibling diagnostic for hybrid_analyzer_v1 (Phase 2B, Issue #53). Diagnostic,
not a benchmark; it changes nothing.

Question: does the D51 VALIDATION carve-out separate rows that the V4 generator kept
together? The generator assigns its train/eval split per *generator group* (D16):
a CSIC request shape with digits collapsed (`parse_dataset_v4.csic_group_key`), or one
canonical attack payload rendered as a base row plus an augmentation variant, possibly
on different paths / parameters. D51 groups by the header-free canonical *request* or the
feature vector, which is finer. Rows of one generator group can therefore sit in TRAIN
and VALIDATION, but never in V4 train and V4 eval.

Generator group ids are not stored in the JSONL, so two proxies are measured:
  csic      `csic_group_key` itself, recomputed from the request (exact for CSIC rows)
  payload   for synthetic BLOCK rows, the longest canonical (`canonical_key`) parameter
            value or body; an approximation of the canonical payload

For each proxy: VALIDATION rows whose key also occurs in TRAIN (same label), against
V4-eval rows whose key occurs in V4 train. Only aggregate counts are produced.

RUN (repository root):
    python3.12 scripts/dataset/diagnose_hybrid_analyzer_v1_siblings.py \
        --out reports/hybrid/phase2b-analyzer-baselines/validation_sibling_diagnostic.json
"""

import argparse
import hashlib
import json
import os
import sys
from collections import Counter
from urllib.parse import parse_qsl

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO_ROOT, "scripts", "dataset"))

import analyze_analyzer_targets as design  # noqa: E402
import parse_dataset_v4 as gen  # noqa: E402

DATASET = os.path.join(REPO_ROOT, "datasets", "hybrid_analyzer_v1", "hybrid_analyzer_v1.jsonl")
MANIFEST = os.path.join(REPO_ROOT, "datasets", "manifest_hybrid_analyzer_v1.json")
MIN_PAYLOAD = 4   # shorter canonical values ("1", "en") identify nothing


def payload_key(method, path, query, ctype, body):
    values = [v for _, v in parse_qsl(query, keep_blank_values=True)]
    if body:
        values += ([v for _, v in parse_qsl(body, keep_blank_values=True)]
                   if ctype == "application/x-www-form-urlencoded" else [body])
    canon = [gen.canonical_key(v) for v in values]
    canon = [c for c in canon if len(c) >= MIN_PAYLOAD]
    return max(canon, key=lambda c: (len(c), c)) if canon else None


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out")
    args = ap.parse_args()

    raw = open(DATASET, "rb").read()
    if hashlib.sha256(raw).hexdigest() != json.load(open(MANIFEST))["artifact"]["sha256"]:
        raise SystemExit("FATAL: dataset hash differs from its manifest")
    meta = {}
    for line in raw.decode("utf-8").splitlines():
        r = json.loads(line)
        meta[(r["meta_v4_split"], r["meta_v4_line"])] = r

    v4 = json.load(open(design.MANIFEST))
    design.load(v4)                                 # verifies the V4-clean SHA-256
    rows = []
    for split in ("train", "eval"):
        with open(os.path.join(design.DATA, f"{split}.jsonl"), encoding="utf-8") as f:
            for i, line in enumerate(f):
                m = meta[(split, i)]
                if m["slice"] is not None:
                    continue
                method, path, query, ctype, body = design.parse_text(json.loads(line)["input"])
                key = None
                if m["meta_source"] == "csic":
                    key = ("csic", gen.csic_group_key({"method": method, "path": path,
                                                       "query": query, "body": body}))
                elif m["target_attack"] == 1:
                    pk = payload_key(method, path, query, ctype, body)
                    key = ("payload", pk) if pk else None
                rows.append({"role": m["role"], "attack": m["target_attack"], "key": key,
                             "src": m["meta_source"]})

    def overlap(ref_roles, probe_role):
        ref = {(r["key"], r["attack"]) for r in rows if r["role"] in ref_roles and r["key"]}
        out = {}
        for kind, label in (("csic", 0), ("csic", 1), ("payload", 1)):
            probe = [r for r in rows if r["role"] == probe_role and r["key"]
                     and r["key"][0] == kind and r["attack"] == label]
            hit = sum((r["key"], r["attack"]) in ref for r in probe)
            out[f"{kind} ({'BLOCK' if label else 'ALLOW'})"] = {
                "rows_with_key": len(probe), "key_in_reference": hit,
                "share": round(hit / len(probe), 4) if probe else None}
        n = sum(1 for r in rows if r["role"] == probe_role)
        out["all_fitted_rows_of_probe"] = n
        out["rows_with_sibling_in_reference"] = sum(v["key_in_reference"] for k, v in out.items()
                                                    if isinstance(v, dict))
        return out

    result = {
        "kind": "diagnostic (aggregate counts only; JWT excluded)",
        "proxies": {"csic": "parse_dataset_v4.csic_group_key (the generator's own CSIC group key)",
                    "payload": f"longest canonical_key(parameter value or body), >= {MIN_PAYLOAD} "
                               "chars; synthetic BLOCK rows only (approximation)"},
        "validation_vs_train (D51 carve-out)": overlap({"train"}, "validation"),
        "v4_eval_vs_v4_train (generator split)": overlap({"train", "validation"}, "internal_test"),
    }
    text = json.dumps(result, indent=2) + "\n"
    if args.out:
        with open(args.out, "x", encoding="utf-8") as f:
            f.write(text)
    print(text, end="")


if __name__ == "__main__":
    main()
