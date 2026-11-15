"""
firewall-IA — per-case V4 decisions on the legacy 135-case manual suite (issue #57).

DIAGNOSTIC SUPPORT ONLY. The stored legacy run (`reports/v4_clean_manual_diagnostic.json`)
kept per-category counts, not per-case decisions. This runs the unchanged V4 runtime
(`control_plane/inference_core.py`: load_model, classify_raw, parse_prediction; greedy
decoding, D27) once over the same 135 cases, in suite order, and writes one record per
case. Inference only: nothing is trained, tuned or thresholded. Invalid outputs are kept as
invalid (E5), never coerced.

Consistency check: the per-category correct counts and the confusion counts must reproduce
the stored diagnostic; a mismatch is reported, never "fixed" by re-running.

ML environment (torch + transformers + peft), from the repository root:

    python3.12 scripts/evaluation/v4_manual_suite_decisions.py \
        --out reports/hybrid/v4-analyzer-disagreement-v1/raw/v4_manual_suite_decisions.jsonl
"""

import argparse
import ast
import hashlib
import json
import os
import platform
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TEST_MODEL = os.path.join(REPO_ROOT, "scripts", "evaluation", "test_model.py")
STORED = os.path.join(REPO_ROOT, "reports", "v4_clean_manual_diagnostic.json")
SUITE_LISTS = ("SYSTEMATIC_CASES", "ADVERSARIAL_CASES", "FALSE_POSITIVE_CASES")
SUITE_SHA256 = "7715c92a42c22e9b280f206009869d9fced8341dfce7b8abf7bbd50d74fcd0ca"
ADAPTER_SHA256 = "7bf168758a428fa7775dff0328de3d07d3063ddf99b961dc8b8406a0dce93de1"


def manual_suite(path=TEST_MODEL):
    """The literal suite, read with `ast` (no import, no execution): list of
    (request, expected, category, description), in suite order, and its JSON SHA-256."""
    with open(path, encoding="utf-8") as f:
        tree = ast.parse(f.read())
    lists = {}
    for node in tree.body:
        if (isinstance(node, ast.Assign) and len(node.targets) == 1
                and isinstance(node.targets[0], ast.Name) and node.targets[0].id in SUITE_LISTS):
            lists[node.targets[0].id] = ast.literal_eval(node.value)
    if set(lists) != set(SUITE_LISTS):
        raise ValueError("manual suite lists not found")
    cases = [tuple(c) for name in SUITE_LISTS for c in lists[name]]
    digest = hashlib.sha256(json.dumps([list(c) for c in cases]).encode()).hexdigest()
    return cases, digest


def score_against_stored(records, stored):
    """Per-category correct counts and confusion counts vs the stored legacy run."""
    per_cat = Counter()
    n_cat = Counter()
    tp = tn = fp = fn = 0
    for r in records:
        n_cat[r["category"]] += 1
        ok = r["status"] == "ok" and r["decision"] == r["expected"]
        per_cat[r["category"]] += int(ok)
        pred_block = r["status"] == "ok" and r["decision"] == "BLOCK"
        if r["expected"] == "BLOCK":
            tp, fn = tp + pred_block, fn + (not pred_block)
        else:
            fp, tn = fp + pred_block, tn + (not pred_block)
    ours = {c: {"n": n_cat[c], "ok": per_cat[c]} for c in n_cat}
    theirs = stored["manual_per_case_category"]
    cm = stored["binary"]["confusion_matrix"]
    return {"per_category_matches": ours == theirs,
            "per_category_mismatches": {c: {"rerun": ours.get(c), "stored": theirs.get(c)}
                                        for c in set(ours) | set(theirs)
                                        if ours.get(c) != theirs.get(c)},
            "confusion_rerun": {"TP": tp, "FP": fp, "FN": fn, "TN": tn},
            "confusion_stored": cm,
            "confusion_matches": {"TP": tp, "FP": fp, "FN": fn, "TN": tn} == cm}


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.strip().split("\n")[0])
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)
    meta_path = os.path.splitext(args.out)[0] + ".meta.json"
    for p in (args.out, meta_path):
        if os.path.exists(p):
            raise SystemExit(f"REFUSING to overwrite {p}")

    cases, digest = manual_suite()
    if digest != SUITE_SHA256:
        raise SystemExit("manual suite differs from the one fixed in the protocol")
    sys.path.insert(0, os.path.join(REPO_ROOT, "control_plane"))
    import inference_core as ic  # noqa: E402  (ML environment only)
    adapter = ic.DEFAULT_ADAPTER_DIR
    adapter_sha = sha256_file(os.path.join(adapter, "adapter_model.safetensors"))
    if adapter_sha != ADAPTER_SHA256:
        raise SystemExit("V4 adapter differs from model-output-v4-clean (7bf16875…)")

    started = datetime.now(timezone.utc).isoformat(timespec="seconds")
    tok, mdl = ic.load_model(adapter)
    device = ic.resolve_device()
    records = []
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "x", encoding="utf-8") as f:
        for i, (request, expected, category, desc) in enumerate(cases):
            raw, dt = ic.classify_raw(tok, mdl, request, device)
            decision, reason, status = ic.parse_prediction(raw)
            rec = {"index": i, "text_sha256": hashlib.sha256(request.encode("utf-8")).hexdigest(),
                   "expected": expected, "category": category, "description": desc,
                   "decision": decision, "reason": reason, "status": status, "raw": raw,
                   "generate_ms (observation only, not a benchmark)": round(dt, 3)}
            records.append(rec)
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            print(f"{i + 1:3d}/{len(cases)} {expected:5s} -> {decision} ({status})", flush=True)

    with open(STORED, encoding="utf-8") as f:
        check = score_against_stored(records, json.load(f))
    import torch
    import transformers
    import peft
    meta = {"started_utc": started,
            "finished_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "suite_sha256": digest, "n_cases": len(cases), "adapter_dir": adapter,
            "adapter_model_sha256": adapter_sha,
            "inference_core_sha256": sha256_file(os.path.join(REPO_ROOT, "control_plane", "inference_core.py")),
            "stored_diagnostic_sha256": sha256_file(STORED),
            "git_head": subprocess.run(["git", "-C", REPO_ROOT, "rev-parse", "HEAD"],
                                       capture_output=True, text=True).stdout.strip(),
            "environment": {"python": platform.python_version(), "torch": torch.__version__,
                            "transformers": transformers.__version__, "peft": peft.__version__,
                            "device": str(device)},
            "decoding": "greedy (inference_core, D27)",
            "consistency_with_stored_legacy_run": check,
            "runs": 1}
    with open(meta_path, "x", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(json.dumps(check, indent=2))
    return 0 if check["per_category_matches"] and check["confusion_matches"] else 1


if __name__ == "__main__":
    sys.exit(main())
