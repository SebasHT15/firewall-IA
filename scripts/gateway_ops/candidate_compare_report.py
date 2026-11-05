"""
Joins the per-case rows of `candidate_compare.py` with the censuses of the delivery. No GPU, no service.

    .venv-dataplane/bin/python scripts/gateway_ops/candidate_compare_report.py --trials <trials dir> \
        --delivery <post-training report dir> --evaluation <evaluation dir> --out <new file>

Everything is recomputed from the rows, so a field of an earlier summary never decides a number here.
Ids, closed codes and numbers only. A difference is listed case by case and never absorbed into a total.
References are expectations and the sink proves delivery: nothing here selects anything.
"""
import argparse
import collections
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import candidate_compare as CC  # noqa: E402

# label of a run: (directory, mode, runtime census, counterfactual the delivery reconstructed)
RUNS = {"native/V5_ONLY": ("compare-native", "V5_ONLY", "native", None),
        "native/CASCADE_ACTIVE+baseline34": ("compare-native", "CASCADE_ACTIVE", "native", None),
        "fast/V5_ONLY": ("compare-verified", "V5_ONLY", "fast", None),
        "fast/CASCADE_ACTIVE+baseline34": ("compare-verified", "CASCADE_ACTIVE", "fast", "baseline34"),
        "fast/CASCADE_ACTIVE+ablation32": ("compare-verified-ablation32", "CASCADE_ACTIVE", "fast",
                                           "ablation32")}


def by_id(path):
    return {row["id"]: row for row in CC.read_jsonl(path) if row.get("phase", "quality") == "quality"}


def censuses(delivery, evaluation):
    return {"native": by_id(os.path.join(delivery, "native-recipe/quality-run/predictions.jsonl")),
            "fast": by_id(os.path.join(delivery, "verified-suffix/quality-run/predictions.jsonl")),
            "previous": by_id(os.path.join(evaluation, "current-v5-verified/quality-run/predictions.jsonl")),
            "baseline34": by_id(os.path.join(delivery, "counterfactual-baseline34-t090/predictions.jsonl")),
            "ablation32": by_id(os.path.join(delivery,
                                             "counterfactual-path-ablation32-t090/predictions.jsonl"))}


def model2_scores(evaluation):
    return {"baseline34": by_id(os.path.join(evaluation, "model2-baseline34/predictions.jsonl")),
            "ablation32": by_id(os.path.join(evaluation, "model2-path-ablation32/predictions.jsonl"))}


def layers(rows):
    """One cohort of one run. The four layers are counted apart."""
    return {"cases": len(rows), "classification": CC.confusion(rows),
            "deciding_stage": dict(collections.Counter(str(r["action"]["deciding_stage"]) for r in rows)),
            "action": dict(collections.Counter(str(r["action"]["applied"]) for r in rows)),
            "status": dict(collections.Counter(str(r["status"]) for r in rows)),
            "received": dict(collections.Counter(str(r["reception"]["received"]) for r in rows)),
            "action_follows_decision": sum(CC.action_follows(r) for r in rows),
            "status_follows_action": sum(CC.status_follows(r) for r in rows),
            "reception_follows_action": sum(CC.reception_follows(r) for r in rows)}


def same_as_census(rows, census):
    """V5 answers seen through the gateway against the API census of that runtime."""
    asked = [r for r in rows if r["classification"]["v5"]["status"] is not None]
    different = [r["id"] for r in asked
                 if (r["classification"]["v5"]["status"], r["classification"]["v5"]["decision"])
                 != (census[r["id"]]["status"], census[r["id"]]["decision"])]
    return {"compared": len(asked), "same": len(asked) - len(different), "different": sorted(different)}


def same_as_counterfactual(rows, counterfactual):
    different = [{"id": r["id"], "gateway": CC.decided(r), "stage": r["action"]["deciding_stage"],
                  "counterfactual": counterfactual[r["id"]]["decision"],
                  "counterfactual_stage": counterfactual[r["id"]].get("deciding_stage")}
                 for r in rows if (CC.decided(r), r["action"]["deciding_stage"]) !=
                 (counterfactual[r["id"]]["decision"], counterfactual[r["id"]].get("deciding_stage"))]
    return {"compared": len(rows), "same": len(rows) - len(different), "different": different}


def score_differences(rows, scores):
    scored = [r for r in rows if r["classification"]["model2"]["p_block"] is not None]
    gaps = [abs(r["classification"]["model2"]["p_block"] - scores[r["id"]]["p_block"]) for r in scored]
    return {"compared": len(scored), "max_absolute_difference": max(gaps) if gaps else None}


def known_cases(authored_fp, validation_fp, changed, census, rows_of):
    """What became of every case the delivery singled out, on each route it could take."""
    previous = census["previous"]
    regressed = [i for i, row in census["fast"].items()
                 if row["decision"] != previous[i]["decision"]
                 and row["decision"] != rows_of["fast/V5_ONLY"][i]["reference"]]
    named = {"authored_false_block": authored_fp, "validation_false_block": validation_fp,
             "native_vs_fast_change": changed, "previous_vs_fast_regression": sorted(regressed)}
    out = []
    for why, ids in named.items():
        for case in ids:
            entry = {"id": case, "why": why, "reference": rows_of["fast/V5_ONLY"][case]["reference"],
                     "api": {"previous": previous[case]["decision"], "native": census["native"][case]["decision"],
                             "fast": census["fast"][case]["decision"]}}
            for label, rows in rows_of.items():
                row = rows[case]
                entry[label] = {"decision": CC.decided(row), "stage": row["action"]["deciding_stage"],
                                "applied": row["action"]["applied"], "status": row["status"],
                                "received": row["reception"]["received"]}
            out.append(entry)
    return out


def model2_effect(active, alone):
    """Cases where the early block changed what V5 alone did, read from the two gateway runs."""
    changed = []
    for case, row in active.items():
        if CC.decided(row) != CC.decided(alone[case]):
            changed.append({"id": case, "reference": row["reference"], "v5_alone": CC.decided(alone[case]),
                            "cascade": CC.decided(row), "stage": row["action"]["deciding_stage"],
                            "p_block": row["classification"]["model2"]["p_block"]})
    return {"changed": sorted(changed, key=lambda c: c["id"]),
            "early_blocks": sum(r["action"]["deciding_stage"] == "model2" for r in active.values())}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--trials", required=True)
    parser.add_argument("--delivery", required=True)
    parser.add_argument("--evaluation", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    census = censuses(args.delivery, args.evaluation)
    scores = model2_scores(args.evaluation)
    rows_of, results = {}, {}
    for label, (directory, mode, runtime, counterfactual) in RUNS.items():
        rows = CC.read_jsonl(os.path.join(args.trials, directory, f"rows-{mode}.jsonl"))
        rows_of[label] = {r["id"]: r for r in rows}
        cohorts = collections.defaultdict(list)
        for row in rows:
            cohorts[row["cohort"]].append(row)
        part = {"cohorts": {name: layers(members) for name, members in sorted(cohorts.items())},
                "same_as_api_census": same_as_census(rows, census[runtime])}
        reached = [r for r in rows if r["canonical_equals_census"] is not None]
        part["round_trip"] = {"reached_v5": len(reached),
                              "canonical_equal": sum(r["canonical_equals_census"] for r in reached),
                              "wire_origin": dict(collections.Counter(r["wire_origin"] for r in rows))}
        if counterfactual:
            part["same_as_counterfactual"] = same_as_counterfactual(rows, census[counterfactual])
            part["model2_scores_vs_census"] = score_differences(rows, scores[counterfactual])
        results[label] = part
    with open(os.path.join(args.delivery, "authored-native-false-blocks.public.json"), encoding="utf-8") as fh:
        authored_fp = [c["id"] for c in json.load(fh)["cases"]]
    with open(os.path.join(args.delivery, "validation-false-blocks.public.json"), encoding="utf-8") as fh:
        validation_fp = [c["id"] for c in json.load(fh)["cases"]]
    with open(os.path.join(args.delivery, "COMPARISON.json"), encoding="utf-8") as fh:
        changed = [c["id"] for c in json.load(fh)["runtime_bundle_changes_native_DQ_vs_fast_noDQ"]]
    document = {
        "schema": "firewall-candidate-compare-report/v1",
        "scope": "Known DEV and selection data. References are expectations. The sink proves delivery. "
                 "No threshold, runtime or candidate selected.",
        "runs": results,
        "model2_effect": {
            "native+baseline34": model2_effect(rows_of["native/CASCADE_ACTIVE+baseline34"],
                                               rows_of["native/V5_ONLY"]),
            "fast+baseline34": model2_effect(rows_of["fast/CASCADE_ACTIVE+baseline34"], rows_of["fast/V5_ONLY"]),
            "fast+ablation32": model2_effect(rows_of["fast/CASCADE_ACTIVE+ablation32"], rows_of["fast/V5_ONLY"])},
        "known_cases": known_cases(authored_fp, validation_fp, changed, census, rows_of)}
    with open(args.out, "x", encoding="utf-8") as fh:
        json.dump(document, fh, indent=1, sort_keys=True)
        fh.write("\n")
    for label, part in results.items():
        print(label, {k: v["classification"] for k, v in part["cohorts"].items()},
              "census", part["same_as_api_census"]["same"], "/", part["same_as_api_census"]["compared"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
