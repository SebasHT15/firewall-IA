"""
Compute the separated cascade evaluation matrix from a paired-pass JSONL.

Every figure is tagged by provenance: `measured` (observed in this run),
`derived` (computed from measured values), or `not_estimable`. Positive class =
BLOCK (D19). Percentiles are nearest-rank; no outliers removed (D32/benchmark
protocol). Model 2 is reported with SELECTIVE metrics (early-block FP, attack
early-block, BLOCK precision, DEFER rate) — it has no ALLOW class, so a standard
binary accuracy would be meaningless for it (D73/§4). V5-only and the cascades are
reported with binary metrics, with the invalid-output rate separate (invalid is an
error under E5 for model quality; the gateway reject is runtime behavior).

Population caveats are NOT silently dropped: these are DEVELOPMENT figures on
legacy non-protected traffic that may overlap V5 training; 13 of 19 categories are
OUTSIDE V5's 6-category vocabulary, so per-category block rates for those measure
only whether V5 fires at all, never trained recall. No protected set is used.

Writes a summary JSON and a set of CSV tables.
"""
import argparse
import csv
import json
import math
import os
from collections import defaultdict

# V5's trained vocabulary categories (from v5_output_contract PILOT_VOCABULARY).
V5_INVOCAB = {
    "SQL injection payload detected.",
    "Cross-site scripting payload detected.",
    "Path traversal attack detected.",
    "File inclusion attack detected.",
    "Command injection payload detected.",
    "Server-side template injection payload detected.",
}


def pct(values, p):
    """Nearest-rank percentile; no interpolation, no outlier removal."""
    if not values:
        return None
    s = sorted(values)
    k = max(1, math.ceil(p / 100 * len(s)))
    return s[k - 1]


def dist(values):
    vals = [v for v in values if v is not None]
    if not vals:
        return {"n": 0}
    mean = sum(vals) / len(vals)
    var = sum((v - mean) ** 2 for v in vals) / len(vals)
    return {"n": len(vals), "mean": mean, "p50": pct(vals, 50), "p95": pct(vals, 95),
            "p99": pct(vals, 99), "min": min(vals), "max": max(vals), "std": math.sqrt(var)}


def ratio(num, den):
    return (num / den) if den else None


# Invalid-output taxonomy (E5). A content-boundary rejection is a RUNTIME
# no-generation event (the content budget refused generation), NOT a model-quality
# error; the rest are genuine bad model outputs. Both are counted as errors in the
# PRINCIPAL view — the split is reported so the two causes are never conflated.
CONTENT_BOUNDARY_REASONS = {"content_rejected"}
MODEL_OUTPUT_ERROR_REASONS = {"no_eos", "not_in_vocabulary"}


def _metrics(tp, tn, fp, fn):
    n = tp + tn + fp + fn
    return {
        "TP": tp, "TN": tn, "FP": fp, "FN": fn, "N": n,
        "accuracy": ratio(tp + tn, n),
        "precision_block": ratio(tp, tp + fp),
        "recall_block": ratio(tp, tp + fn),
        "fpr": ratio(fp, fp + tn),
        "fnr": ratio(fn, fn + tp),
        "f1_block": ratio(2 * tp, 2 * tp + fp + fn),
    }


def binary_confusion(items):
    """items: list of (label, decision | None, invalid_reason | None). Positive=BLOCK.

    E5 (frozen in scripts/evaluation/test_model.py::score_binary) emits TWO views;
    they are never merged into one headline number:

      PRINCIPAL — every case is counted. An invalid/None output is an INCORRECT
        security decision mapped to the OPPOSITE of the true label, so garbage can
        never earn credit: a BLOCK-labelled invalid becomes an FN, an ALLOW-labelled
        invalid becomes an FP. N == total cases.
      PARSEABLE_ONLY — invalids are excluded; shows the metrics over the cases the
        model actually produced a parseable decision for. N == valid cases.

    The invalid block reports the rate and the content-boundary vs model-output
    split. (D4 fail-closed runtime behaviour is a separate operational control, not
    evaluation credit — see test_model.py.)"""
    ptp = ptn = pfp = pfn = 0          # principal (invalids as errors)
    vtp = vtn = vfp = vfn = 0          # parseable-only
    content_boundary = model_error = other_invalid = 0
    for label, dec, reason in items:
        if dec is None:               # invalid output -> error in the true class
            if label == "BLOCK":
                pfn += 1
            else:
                pfp += 1
            if reason in CONTENT_BOUNDARY_REASONS:
                content_boundary += 1
            elif reason in MODEL_OUTPUT_ERROR_REASONS:
                model_error += 1
            else:
                other_invalid += 1
            continue
        if label == "BLOCK" and dec == "BLOCK":
            ptp += 1; vtp += 1
        elif label == "ALLOW" and dec == "ALLOW":
            ptn += 1; vtn += 1
        elif label == "ALLOW" and dec == "BLOCK":
            pfp += 1; vfp += 1
        elif label == "BLOCK" and dec == "ALLOW":
            pfn += 1; vfn += 1
    invalid = content_boundary + model_error + other_invalid
    principal = _metrics(ptp, ptn, pfp, pfn)
    return {
        "view": "E5 (BLOCK positive); PRINCIPAL is the headline view",
        "principal": {**principal,
                      "note": "invalids counted as errors in their true class "
                              "(BLOCK->FN, ALLOW->FP)"},
        "parseable_only": {**_metrics(vtp, vtn, vfp, vfn),
                           "note": "invalids excluded; decisions the model produced"},
        "invalid": {
            "total": invalid,
            "rate_of_total": ratio(invalid, principal["N"]),
            "content_boundary_rejections": content_boundary,
            "model_output_errors": model_error,
            "model_output_error_reasons": sorted(MODEL_OUTPUT_ERROR_REASONS),
            "other": other_invalid,
            "note": "content_boundary = no-generation content-boundary reject (runtime, "
                    "not model quality); model_output_errors = no_eos / not_in_vocabulary "
                    "(genuine bad output). Both count as errors in PRINCIPAL.",
        },
    }


def v5_applied(rec):
    """V5-only applied decision: ok -> its decision; invalid/error -> None (invalid)."""
    v = rec.get("v5") or {}
    if v.get("status") == "ok":
        return v.get("decision")
    return None


def v5_cell(rec):
    """(decision | None, invalid_reason | None) for the V5-only confusion."""
    v = rec.get("v5") or {}
    if v.get("status") == "ok":
        return v.get("decision"), None
    return None, v.get("invalid_reason")


def cascade_cell(rec, which):
    """Cascade confusion cell with Fast Path CONTINUE: Model 2 BLOCK short-circuits
    (no invalid possible); else V5 (invalid -> None with its reason). Returns
    (decision | None, invalid_reason | None, deciding_stage). `which` =
    'model2_baseline34' | 'model2_ablation32'."""
    m2 = rec.get(which) or {}
    if m2.get("decision") == "BLOCK":
        return "BLOCK", None, "model2"
    dec, reason = v5_cell(rec)
    return dec, reason, "v5"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--paired", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()
    os.makedirs(args.out_dir, exist_ok=True)

    rows = [json.loads(l) for l in open(args.paired, encoding="utf-8") if l.strip()]
    n_total = len(rows)
    wire_bad = [r for r in rows if not r.get("wire_ok", False)]
    canon = defaultdict(int)
    for r in rows:
        canon[r.get("canonical_outcome")] += 1
    accept = [r for r in rows if r.get("canonical_outcome") == "ACCEPT"]

    summary = {
        "provenance_note": "DEVELOPMENT run on legacy non-protected eval.jsonl; mechanism/route/cost "
                           "measurement, NOT a generalization or security headline. No protected set used.",
        "population": {
            "n_total": n_total,
            "wire_rejected": len(wire_bad),
            "canonical_outcomes": dict(canon),
            "n_accept": len(accept),
            "label_counts": {"ALLOW": sum(1 for r in rows if r["label"] == "ALLOW"),
                             "BLOCK": sum(1 for r in rows if r["label"] == "BLOCK")},
            "provenance": "measured",
        },
    }

    # ── V5-only (binary) on ACCEPT ──
    v5_items = [(r["label"],) + v5_cell(r) for r in accept]
    summary["v5_only"] = {"confusion": binary_confusion(v5_items),
                          "provenance": "measured (binary); E5 principal + parseable-only views"}

    # ── Model 2 selective metrics (each candidate) on ACCEPT ──
    for cand in ("model2_baseline34", "model2_ablation32"):
        benign = [r for r in accept if r["label"] == "ALLOW"]
        attack = [r for r in accept if r["label"] == "BLOCK"]
        blocks = [r for r in accept if (r.get(cand) or {}).get("decision") == "BLOCK"]
        defers = [r for r in accept if (r.get(cand) or {}).get("decision") == "DEFER"]
        benign_block = sum(1 for r in benign if (r.get(cand) or {}).get("decision") == "BLOCK")
        attack_block = sum(1 for r in attack if (r.get(cand) or {}).get("decision") == "BLOCK")
        block_tp = sum(1 for r in blocks if r["label"] == "BLOCK")
        summary[cand] = {
            "n_reaching_model2": len(accept),
            "threshold": (rows and next((r.get(cand, {}).get("threshold") for r in accept), None)),
            "early_block_fp_rate": ratio(benign_block, len(benign)),
            "early_block_fp_count": benign_block, "benign_reaching": len(benign),
            "attack_early_block_rate": ratio(attack_block, len(attack)),
            "attack_early_block_count": attack_block, "attack_reaching": len(attack),
            "block_precision": ratio(block_tp, len(blocks)),
            "block_count": len(blocks), "defer_count": len(defers),
            "defer_rate": ratio(len(defers), len(accept)),
            "provenance": "measured (selective; Model 2 has no ALLOW class, DEFER is not FN)",
        }

    # ── cascades (binary applied) ──
    for cand in ("model2_baseline34", "model2_ablation32"):
        items = []
        stage_counts = defaultdict(int)
        v5_calls = 0
        early_block = 0
        for r in accept:
            dec, reason, stage = cascade_cell(r, cand)
            items.append((r["label"], dec, reason))
            stage_counts[stage] += 1
            if stage == "v5":
                v5_calls += 1
            else:
                early_block += 1
        conf = binary_confusion(items)
        name = "cascade_" + cand.replace("model2_", "")
        summary[name] = {
            "confusion": conf,
            "deciding_stage_counts": dict(stage_counts),
            "v5_calls": v5_calls,
            "early_block_count": early_block,
            # NOT a measured time/call reduction: a counterfactual estimate of the
            # V5 calls that early BLOCK could avoid, derived from the recorded
            # predictions in THIS pass (no positive Fast Path policy applied).
            "v5_calls_avoided_vs_v5only_counterfactual": len(accept) - v5_calls,
            "v5_call_avoided_fraction_counterfactual": ratio(early_block, len(accept)),
            "provenance": "derived (counterfactual call-avoidance from observed predictions; "
                          "NOT a measured runtime time/call reduction)",
        }

    # ── derived headline (baseline34 cascade vs V5-only), PRINCIPAL E5 ──
    # Every number here is DERIVED from the measured confusions above, recomputed
    # from the kept JSONL — never an operating rate or a security headline.
    cb = summary["cascade_baseline34"]["confusion"]["principal"]
    vo = summary["v5_only"]["confusion"]["principal"]
    def _pp(a, b):
        return None if (a is None or b is None) else (a - b) * 100
    summary["derived_headline_baseline34_vs_v5only"] = {
        "cascade_recall_block": cb["recall_block"],
        "v5_only_recall_block": vo["recall_block"],
        "recall_uplift_pp": _pp(cb["recall_block"], vo["recall_block"]),
        "cascade_fpr": cb["fpr"],
        "v5_only_fpr": vo["fpr"],
        "extra_false_blocks_over_benign": cb["FP"] - vo["FP"],
        "benign_reaching": cb["FP"] + cb["TN"],
        "provenance": "derived (recomputed from kept records on DEVELOPMENT traffic); "
                      "NOT an operating rate, NOT a generalization or security claim",
    }

    # ── complementarity: cascade (baseline) vs V5-only ──
    comp = {"early_block_correct": 0, "early_block_added_fp": 0,
            "early_block_on_attack_v5_would_miss": 0,
            "early_block_on_attack_v5_would_catch": 0}
    for r in accept:
        m2b = (r.get("model2_baseline34") or {}).get("decision")
        if m2b != "BLOCK":
            continue
        v5d = v5_applied(r)
        if r["label"] == "BLOCK":
            comp["early_block_correct"] += 1
            if v5d == "ALLOW":
                comp["early_block_on_attack_v5_would_miss"] += 1
            elif v5d == "BLOCK":
                comp["early_block_on_attack_v5_would_catch"] += 1
        else:  # benign early-blocked: an error V5 could not fix
            comp["early_block_added_fp"] += 1
    comp["provenance"] = "measured; V5's counterfactual decision is recorded for every ACCEPT"
    summary["complementarity_baseline_vs_v5only"] = comp

    # ── latency per stage (measured) ──
    summary["latency_ms"] = {
        "canonicalization": {**dist([r.get("canon_ms") for r in accept]), "provenance": "measured"},
        "fast_path": {**dist([(r.get("fast_path") or {}).get("ms") for r in accept]), "provenance": "measured"},
        "model2_baseline34_score": {**dist([(r.get("model2_baseline34") or {}).get("ms") for r in accept]), "provenance": "measured"},
        "model2_ablation32_score": {**dist([(r.get("model2_ablation32") or {}).get("ms") for r in accept]), "provenance": "measured"},
        "v5_generate": {**dist([(r.get("v5") or {}).get("generate_ms") for r in accept]), "provenance": "measured (model-side generate only; NOT D36 pipeline)"},
        "v5_http_roundtrip": {**dist([(r.get("v5") or {}).get("roundtrip_ms") for r in accept]), "provenance": "measured (client->service->client incl. queue)"},
        "note": "P95/P99 are per-request measured, never summed across stages. V5 generate "
                "excludes warm-up separation; see the dedicated latency run for D31/D36 scope.",
    }

    # ── per-category V5 block rate (binary; caveated in/out of vocab) ──
    catrows = []
    bycat = defaultdict(list)
    for r in accept:
        if r["label"] == "BLOCK":
            bycat[r["category"]].append(r)
    for cat, items in sorted(bycat.items()):
        v5_block = sum(1 for r in items if v5_applied(r) == "BLOCK")
        m2b_block = sum(1 for r in items if (r.get("model2_baseline34") or {}).get("decision") == "BLOCK")
        catrows.append({"category": cat, "in_v5_vocab": cat in V5_INVOCAB, "n": len(items),
                        "v5_block": v5_block, "v5_block_rate": ratio(v5_block, len(items)),
                        "model2_block": m2b_block})
    summary["per_category_block_rate"] = {
        "rows": catrows,
        "provenance": "measured binary block rate; out-of-vocab categories measure only whether V5 fires, "
                      "never trained recall (13/19 categories are out of V5's 6-category vocabulary).",
    }

    with open(os.path.join(args.out_dir, "summary.json"), "w") as f:
        json.dump(summary, f, indent=2)

    # CSV tables
    with open(os.path.join(args.out_dir, "per_category.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["category", "in_v5_vocab", "n", "v5_block",
                                          "v5_block_rate", "model2_block"])
        w.writeheader()
        for row in catrows:
            w.writerow(row)

    with open(os.path.join(args.out_dir, "latency.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["stage", "n", "mean", "p50", "p95", "p99", "min", "max", "std"])
        for stage, d in summary["latency_ms"].items():
            if isinstance(d, dict) and "n" in d:
                w.writerow([stage, d["n"], d.get("mean"), d.get("p50"), d.get("p95"),
                            d.get("p99"), d.get("min"), d.get("max"), d.get("std")])

    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
