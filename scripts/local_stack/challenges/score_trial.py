"""Score sealed challenge-app trials without treating operational fail-closed as TP.

This only scores quality/effect rows from real V5.1. The V5 double, unlabeled
cases and direct controls are never counted as detector classification results.
Rows must be paired by exact case IDs, source hash, app and transport.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
import math
from pathlib import Path
import random
import statistics

import trial


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load_run(path, *, scope):
    path = Path(path)
    summary = json.loads((path / "SUMMARY.json").read_text())
    rows_path = path / "ROWS.jsonl"
    rows = [json.loads(line) for line in rows_path.read_text().splitlines() if line.strip()]
    clean = json.loads((path / "CLEAN.json").read_text())
    if (summary.get("status") != "COMPLETE" or summary.get("scope") != scope or
            summary.get("rows_sha256") != digest(rows_path) or
            summary.get("cases") != len(rows) or not clean.get("clean") or
            len({r.get("case_id") for r in rows}) != len(rows) or
            any(r.get("source_cases_sha256") != summary.get("cases_sha256") or
                r.get("arm") != summary.get("arm") or
                r.get("transport") != summary.get("transport") for r in rows)):
        raise ValueError(f"invalid or incomplete trial: {path}")
    if scope == "SEALED_REAL" and summary.get("v5") != "real" and summary.get("arm") in (
            "v5only", "fastv5", "fastv5_guard", "guarded", "guarded_fast"):
        raise ValueError("only a real V5 arm may be scored")
    return summary, {r["case_id"]: r for r in rows}


def classify(row):
    """Model classification, with infrastructure and invalid results separate."""
    if row["arm"] == "direct":
        return "CONTROL"
    if row.get("layer") in ("front", "unattributed") or not row.get("complete"):
        return "INFRA_ERROR"
    if row.get("canonical_outcome") not in (None, "ACCEPT"):
        return "OUT_OF_SCOPE"
    v5 = row.get("v5") or {}
    if v5 and (v5.get("status") != "ok" or v5.get("decision") not in ("ALLOW", "BLOCK")):
        return "MODEL_INVALID"
    if row.get("applied") == "DENY":
        if row["arm"] == "crs" and row.get("layer") == "crs":
            return "BLOCK"
        stage = row.get("deciding_stage")
        if stage == "v5" and v5.get("decision") == "BLOCK":
            return "BLOCK"
        if stage == "model2" and (row.get("model2") or {}).get("status") == "OK" and (row.get("model2") or {}).get("decision") == "BLOCK":
            return "BLOCK"
        if stage == "request_guard":
            return "BLOCK" if (row.get("request_guard") or {}).get("status") == "MATCH" else "INFRA_ERROR"
        return "OUT_OF_SCOPE"
    if row.get("applied") == "FORWARD" and row.get("app_received"):
        return "ALLOW"
    return "INFRA_ERROR"


def primary_cell(row):
    label = row["label"]
    if row.get("sequence_role") in ("observe", "setup"):
        return None
    result = classify(row)
    if label not in ("ALLOW", "BLOCK"):
        return None
    if result == "BLOCK":
        return "TP" if label == "BLOCK" else "FP"
    if result == "ALLOW":
        return "FN" if label == "BLOCK" else "TN"
    if result == "MODEL_INVALID":
        return "FN" if label == "BLOCK" else "FP"
    return "UNCLASSIFIED_ATTACK" if label == "BLOCK" else "UNCLASSIFIED_BENIGN"


def ratio(a, b):
    return a / b if b else None


def percentile(values, fraction):
    if not values:
        return None
    values = sorted(values)
    pos = (len(values) - 1) * fraction
    lo, hi = int(pos), min(len(values) - 1, int(pos) + 1)
    return values[lo] + (values[hi] - values[lo]) * (pos - lo)


def cluster_interval(groups, numerator, denominator):
    """95% percentile interval, resampling independent group IDs with replacement."""
    keys = sorted(groups)
    if len(keys) < 2:
        return None
    rng = random.Random(20261105)
    draws = []
    for _ in range(2000):
        sampled = [groups[rng.choice(keys)] for _ in keys]
        n = sum(sum(g[k] for k in numerator) for g in sampled)
        d = sum(sum(g[k] for k in denominator) for g in sampled)
        if d:
            draws.append(n / d)
    if len(draws) < 1000:
        return None
    return {"low": percentile(draws, .025), "high": percentile(draws, .975),
            "unit": "group_id", "groups": len(keys), "draws": len(draws)}


def model2_diagnostics(rows):
    """Purely diagnostic ranking/calibration; no threshold is selected here."""
    pairs = []
    for row in rows.values():
        m = row.get("model2") or {}
        score = m.get("p_block")
        if (row.get("label") in ("ALLOW", "BLOCK") and m.get("status") == "OK" and
                isinstance(score, (int, float)) and math.isfinite(score) and 0 <= score <= 1):
            pairs.append((float(score), int(row["label"] == "BLOCK")))
    if not pairs:
        return {"n": 0, "auroc": None, "average_precision": None,
                "brier": None, "ece_10_bins": None, "fixed_threshold_curve": []}
    positives = sum(y for _, y in pairs)
    negatives = len(pairs) - positives
    brier = sum((score - y) ** 2 for score, y in pairs) / len(pairs)
    bins = [list() for _ in range(10)]
    for score, y in pairs:
        bins[min(9, int(score * 10))].append((score, y))
    ece = sum(len(bucket) / len(pairs) * abs(sum(s for s, _ in bucket) / len(bucket) -
                    sum(y for _, y in bucket) / len(bucket)) for bucket in bins if bucket)
    groups = defaultdict(Counter)
    for score, y in pairs:
        groups[score]["positive" if y else "negative"] += 1
    tp = fp = 0
    ap = auc_numerator = 0.0
    for score in sorted(groups, reverse=True):
        pos, neg = groups[score]["positive"], groups[score]["negative"]
        tp += pos
        fp += neg
        if positives:
            ap += (pos / positives) * (tp / (tp + fp))
        auc_numerator += pos * (negatives - fp) + .5 * pos * neg
    curve = []
    for threshold in (0.5, 0.9, 0.95, 0.99):
        flagged = [(s, y) for s, y in pairs if s >= threshold]
        pos = sum(y for _, y in flagged)
        neg = len(flagged) - pos
        curve.append({"threshold_diagnostic_only": threshold,
                      "fraction_flagged": len(flagged) / len(pairs),
                      "attack_fraction_flagged": ratio(pos, positives),
                      "benign_fraction_flagged": ratio(neg, negatives)})
    return {"n": len(pairs), "positives": positives, "negatives": negatives,
            "auroc": auc_numerator / (positives * negatives) if positives and negatives else None,
            "average_precision": ap if positives and negatives else None,
            "brier": brier, "ece_10_bins": ece, "fixed_threshold_curve": curve}


def score_arm(rows, direct):
    counts = Counter()
    families = defaultdict(Counter)
    groups = defaultdict(Counter)
    sessions = defaultdict(list)
    latencies = []
    for cid, row in rows.items():
        label = row["label"]
        result = classify(row)
        counts[f"result_{result}"] += 1
        if row.get("sequence_role") not in ("observe", "setup"):
            counts[f"label_{label}"] += 1
        cell = primary_cell(row)
        if cell is not None:
            counts[cell] += 1
            families[row["family"]][cell] += 1
            groups[row["group_id"]][cell] += 1
        if row.get("applied") == "DENY" and result != "BLOCK":
            counts["operational_denials_outside_detector"] += 1
        if row.get("app_received") and row.get("applied") == "DENY":
            counts["block_delivery_discrepancy"] += 1
        if row.get("status") in (502, 503):
            counts[f"http_{row['status']}"] += 1
        if (label == "BLOCK" and result == "BLOCK" and
                row.get("deciding_stage") == "v5" and row.get("expected_v5_reason")):
            reason = (row.get("v5") or {}).get("reason")
            counts["v5_reason_evaluable"] += 1
            if reason == row["expected_v5_reason"]:
                counts["v5_reason_correct"] += 1
            elif reason is None:
                counts["v5_reason_missing"] += 1
            else:
                counts["v5_reason_wrong"] += 1
        if row.get("complete") and row.get("client_ms") is not None:
            latencies.append(row["client_ms"])
        if label == "ALLOW" and row.get("sequence_role") not in ("observe", "setup"):
            sessions[row["session_id"]].append(row)
        base = direct[cid]
        if label == "BLOCK":
            if base.get("effect_eligible") is False:
                counts["non_exploit_oracle_excluded"] += 1
            elif base.get("effect_observed") is True:
                counts["eligible_effect_positive_direct"] += 1
                if row.get("effect_observed") is False:
                    if (row.get("applied") == "DENY" and
                            row.get("layer") in ("firewall", "crs") and
                            not row.get("app_received")):
                        counts["effect_prevented_by_firewall"] += 1
                    else:
                        counts["effect_absent_other_cause"] += 1
                elif row.get("effect_observed") is True:
                    counts["effect_persisted"] += 1
                else:
                    counts["effect_unknown"] += 1
            elif base.get("effect_observed") is False:
                counts["direct_effect_negative"] += 1
            else:
                counts["direct_effect_unknown"] += 1
    tp, tn, fp, fn = (counts[k] for k in ("TP", "TN", "FP", "FN"))
    # Invalid and infrastructure rows are not silently folded into detector cells.
    complete_sessions = sum(all(r.get("effect_observed") is True and
                                classify(r) == "ALLOW" and r.get("app_received")
                                for r in group) for group in sessions.values())
    return {"sequence_effects": sequence_effects(rows, direct),
            "counts": dict(counts), "family_counts": {k: dict(v) for k, v in families.items()},
            "recall_primary": ratio(tp, tp + fn),
            "fnr_primary": ratio(fn, tp + fn),
            "fpr_primary": ratio(fp, fp + tn),
            "specificity_primary": ratio(tn, fp + tn),
            "prevalence_labeled": ratio(counts["label_BLOCK"],
                                        counts["label_BLOCK"] + counts["label_ALLOW"]),
            "classification_coverage_attack": ratio(tp + fn, counts["label_BLOCK"]),
            "classification_coverage_benign": ratio(fp + tn, counts["label_ALLOW"]),
            "precision_primary": ratio(tp, tp + fp),
            "f1_primary": ratio(2 * tp, 2 * tp + fp + fn),
            "recall_cluster_ci95": cluster_interval(groups, ("TP",), ("TP", "FN")),
            "fpr_cluster_ci95": cluster_interval(groups, ("FP",), ("FP", "TN")),
            "effect_prevention": ratio(counts["effect_prevented_by_firewall"],
                                       counts["eligible_effect_positive_direct"]),
            "v5_reason_accuracy": ratio(counts["v5_reason_correct"],
                                        counts["v5_reason_evaluable"]),
            "model2_score_diagnostics": model2_diagnostics(rows),
            "benign_sessions": len(sessions), "benign_sessions_complete": complete_sessions,
            "latency_ms": {"n": len(latencies), "p50": percentile(latencies, .5),
                           "p95": percentile(latencies, .95),
                           "p99": percentile(latencies, .99),
                           "mean": statistics.mean(latencies) if latencies else None}}


def compare(v5only, guarded, direct):
    counts = Counter()
    group_a, group_b = defaultdict(Counter), defaultdict(Counter)
    benign_sessions_a, benign_sessions_b = defaultdict(list), defaultdict(list)
    for cid in v5only:
        a, b = v5only[cid], guarded[cid]
        counts["model2_ms_total_guarded"] += float((b.get("gateway_stage_ms") or {}).get("model2") or 0)
        counts["v5_ms_total_v5only"] += float((a.get("gateway_stage_ms") or {}).get("v5") or 0)
        counts["v5_ms_total_guarded"] += float((b.get("gateway_stage_ms") or {}).get("v5") or 0)
        if a["label"] == "ALLOW":
            benign_sessions_a[a["session_id"]].append(a)
            benign_sessions_b[b["session_id"]].append(b)
        if a["label"] == "BLOCK" and direct[cid].get("effect_eligible") is not False and direct[cid].get("effect_observed") is True:
            counts["paired_effect_eligible"] += 1
            for row, name in ((a, "v5only_effect_prevented"),
                              (b, "guarded_effect_prevented")):
                if (row.get("applied") == "DENY" and not row.get("app_received") and
                        row.get("effect_observed") is False and row.get("layer") in ("firewall", "crs")):
                    counts[name] += 1
        for row, groups in ((a, group_a), (b, group_b)):
            cell = primary_cell(row)
            if cell:
                groups[row["group_id"]][cell] += 1
        if b.get("deciding_stage") == "model2" and b.get("applied") == "DENY":
            counts["model2_early_blocks"] += 1
            if a["label"] == "BLOCK":
                counts["model2_early_attack_blocks"] += 1
                if classify(a) == "ALLOW":
                    counts["model2_rescues"] += 1
            elif a["label"] == "ALLOW":
                counts["model2_early_benign_blocks"] += 1
                if classify(a) == "ALLOW":
                    counts["model2_new_benign_damage"] += 1
        if a.get("v5") is not None and b.get("v5") is None:
            counts["v5_calls_avoided"] += 1
        if isinstance(b.get("model2"), dict) and b["model2"].get("decision") == "DEFER":
            counts["model2_defer"] += 1
    def rate(groups, num, den):
        total = Counter()
        for group in groups.values():
            total.update(group)
        return ratio(total[num], sum(total[k] for k in den))
    counts["paired_recall_delta"] = None
    counts["paired_fpr_delta"] = None
    counts["paired_effect_prevention_delta"] = ratio(
        counts["guarded_effect_prevented"] - counts["v5only_effect_prevented"],
        counts["paired_effect_eligible"])
    counts["v5_ms_observed_difference"] = (counts["v5_ms_total_v5only"] -
                                           counts["v5_ms_total_guarded"])
    def completed(sessions):
        return sum(all(r.get("effect_observed") is True and classify(r) == "ALLOW" and
                       r.get("app_received") for r in group) for group in sessions.values())
    counts["paired_benign_sessions"] = len(benign_sessions_a)
    counts["paired_benign_sessions_complete_delta"] = completed(benign_sessions_b) - completed(benign_sessions_a)
    for name, num, den in (("recall", "TP", ("TP", "FN")),
                           ("fpr", "FP", ("FP", "TN"))):
        va, vb = rate(group_a, num, den), rate(group_b, num, den)
        counts[f"paired_{name}_delta"] = vb - va if va is not None and vb is not None else None
        keys = sorted(group_a)
        ci = None
        if len(keys) > 1 and keys == sorted(group_b):
            rng = random.Random(20261105)
            draws = []
            for _ in range(2000):
                chosen = [rng.choice(keys) for _ in keys]
                ca, cb = Counter(), Counter()
                for key in chosen:
                    ca.update(group_a[key])
                    cb.update(group_b[key])
                da, db = sum(ca[k] for k in den), sum(cb[k] for k in den)
                if da and db:
                    draws.append(cb[num] / db - ca[num] / da)
            if len(draws) >= 1000:
                ci = {"low": percentile(draws, .025), "high": percentile(draws, .975),
                      "unit": "paired_group_id", "groups": len(keys), "draws": len(draws)}
        counts[f"paired_{name}_delta_cluster_ci95"] = ci
    return dict(counts)


def sequence_effects(rows, direct):
    sequences = defaultdict(list)
    for cid, row in rows.items():
        if row.get("attack_sequence_id"):
            sequences[row["attack_sequence_id"]].append(cid)
    counts = Counter()
    detail = {}
    for sid, ids in sequences.items():
        attacks = [cid for cid in ids if direct[cid].get("sequence_role") == "attack"]
        obs = [cid for cid in ids if direct[cid].get("sequence_role") == "observe"]
        counts["sequences"] += 1
        if not attacks or not obs or not all(direct[cid].get("effect_observed") is True for cid in obs):
            counts["direct_not_positive_or_incomplete"] += 1
            detail[sid] = "DIRECT_NOT_POSITIVE"
            continue
        counts["eligible_positive_direct"] += 1
        if any(rows[cid].get("effect_observed") is True for cid in obs):
            outcome = "PERSISTED"
        elif any(rows[cid].get("effect_observed") is None or not rows[cid].get("complete") for cid in obs):
            outcome = "UNKNOWN"
        elif any(classify(rows[cid]) == "BLOCK" and not rows[cid].get("app_received") for cid in attacks):
            outcome = "PREVENTED_AT_ATTACK"
        elif any(classify(rows[cid]) == "BLOCK" and not rows[cid].get("app_received") for cid in obs):
            outcome = "DELIVERY_BLOCKED_AT_OBSERVATION"
        else:
            outcome = "ABSENT_OTHER_CAUSE"
        counts[outcome.lower()] += 1
        detail[sid] = outcome
    return {"counts": dict(counts), "outcomes": detail,
            "prevention_at_attack": ratio(counts["prevented_at_attack"], counts["eligible_positive_direct"]),
            "note": "Observation/setup steps are not independent benign classification examples. Observation blocking is reported separately from preventing injection."}


def compare_fast_path(reference, candidate, direct):
    counts = Counter()
    for cid, a in reference.items():
        b = candidate[cid]
        counts["paired_requests"] += 1
        if a["label"] == "ALLOW" and a.get("sequence_role") not in ("observe", "setup"):
            counts["benign_requests"] += 1
        stage = b.get("deciding_stage")
        hit = stage == "fast_path" and b.get("applied") == "FORWARD"
        if hit:
            counts["fast_path_hits"] += 1
            if a["label"] == "ALLOW" and a.get("sequence_role") not in ("observe", "setup"): counts["benign_fast_path_hits"] += 1
            elif a["label"] == "BLOCK": counts["attack_fast_path_hits"] += 1
            if (b.get("complete") and b.get("response_sha256") == direct[cid].get("response_sha256")):
                counts["fast_path_response_hash_equal_direct"] += 1
        for row, prefix in ((a, "reference"), (b, "candidate")):
            counts[prefix + "_v5_calls"] += int(row.get("v5") is not None)
            counts[prefix + "_v5_stage_ms"] += float((row.get("gateway_stage_ms") or {}).get("v5") or 0)
        if a.get("v5") is not None and b.get("v5") is None:
            counts["v5_calls_avoided_" + ("fast_path" if hit else stage or "unattributed")] += 1
        if b.get("model2") is not None: counts["unexpected_model2_records"] += 1
        if a["label"] == "ALLOW" and a.get("sequence_role") not in ("observe", "setup") and a.get("effect_observed") is True and b.get("effect_observed") is not True:
            counts["new_benign_oracle_failure"] += 1
        if a["label"] == "ALLOW" and classify(a) == "ALLOW" and classify(b) == "BLOCK":
            counts["new_benign_damage"] += 1
        if a["label"] == "BLOCK" and classify(a) == "BLOCK" and classify(b) == "ALLOW":
            counts["new_attack_delivery"] += 1
    return {"counts": dict(counts),
            "benign_fast_path_coverage": ratio(counts["benign_fast_path_hits"], counts["benign_requests"]),
            "fast_path_calls_avoided_fraction": ratio(counts["v5_calls_avoided_fast_path"], counts["reference_v5_calls"]),
            "v5_time_observed_difference_ms": counts["reference_v5_stage_ms"] - counts["candidate_v5_stage_ms"],
            "note": "V5 time difference is observed across runs; only actual call elimination is directly attributable. Audit calls are counted separately in run summaries."}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--direct", type=Path, required=True)
    p.add_argument("--seal", type=Path, required=True)
    p.add_argument("--arm", type=Path, action="append", required=True)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    seal = json.loads(args.seal.read_text())
    if (seal.get("schema") != trial.SCHEMA or seal.get("status") != "SEALED" or
            seal.get("source_sha256") != trial.source_hashes() or
            seal.get("metrics_spec_sha256") != digest(trial.METRICS_SPEC)):
        raise ValueError("sealed source or measurement specification changed")
    direct_summary, direct = load_run(args.direct, scope="DIRECT_DRAFT")
    if seal["direct_rows_sha256"] != direct_summary["rows_sha256"]:
        raise ValueError("direct controls differ from seal")
    output = {"schema": "challenge-trial-score/v1", "scope": "SEALED_REAL_ONLY",
              "direct_rows_sha256": direct_summary["rows_sha256"],
              "arms": {}, "paired": None}
    loaded = {}
    for path in args.arm:
        summary, rows = load_run(path, scope="SEALED_REAL")
        arm = summary["arm"]
        if arm in loaded or arm == "direct":
            raise ValueError("duplicate or direct comparison arm")
        if (summary["cases_sha256"] != direct_summary["cases_sha256"] or
                summary.get("seal_sha256") != digest(args.seal) or
                summary["config_sha256"] != seal["configs"][arm]["sha256"] or
                summary["transport"] != direct_summary["transport"] or
                summary["app"] != direct_summary["app"] or
                set(rows) != set(direct) or
                any(rows[cid]["label"] != direct[cid]["label"] or
                    rows[cid]["group_id"] != direct[cid]["group_id"] or
                    rows[cid]["session_id"] != direct[cid]["session_id"] or
                    rows[cid].get("attack_sequence_id") != direct[cid].get("attack_sequence_id") or
                    rows[cid].get("sequence_role") != direct[cid].get("sequence_role") for cid in rows)):
            raise ValueError("runs are not exact case, label, group and transport pairs")
        loaded[arm] = rows
        output["arms"][arm] = {"rows_sha256": summary["rows_sha256"],
                                **score_arm(rows, direct)}
    if "v5only" in loaded and "guarded" in loaded:
        output["paired"] = compare(loaded["v5only"], loaded["guarded"], direct)
    output["paired_fast_path"] = {
        arm: compare_fast_path(loaded["v5only"], loaded[arm], direct)
        for arm in ("fastv5", "fastv5_guard") if arm in loaded and "v5only" in loaded}
    if args.out.exists():
        raise FileExistsError("new score output required")
    args.out.write_text(json.dumps(output, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"out": str(args.out), "arms": list(loaded), "paired": output["paired"]},
                     indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
