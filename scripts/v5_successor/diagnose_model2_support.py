"""Describe Model2 TRAIN support and known Docker errors without changing a model.

Reads only the frozen TRAIN rows, the already-known Docker DEV population and
their recorded decisions. Guard variants are CPU counterfactuals, not policies.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

from scripts.model2 import training as model2
from scripts.v5_successor.docker_eval import population


REPO = Path(__file__).resolve().parents[2]
TRAIN = REPO / "datasets/v5_sources/final_source_2026-10-26-v4/rows.TRAIN.jsonl"
ARTIFACT = REPO / "model-output-model2/final/v4-d82-20261027T052308Z/baseline34.json"
DOCKER = REPO / "reports/v5/docker-application-2026-11-02/run-1"
PRIVATE_CASES = Path(
    "/home/sebas/Documents/Codex/2026-10-26/ta/work/docker-application-20261102-run1/cases.private.jsonl"
)
EXPECTED_TRAIN = "809ce774cf8d20b4243fcda47d587252d0aa07e4b3e5a6c4619fa222a8fbe745"
EXPECTED_ARTIFACT = "da6f6eb85c5a687bd038c6298baf59abdbe0489a80c8993b74a34dae7c60aa38"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def jsonl(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def confusion(rows):
    counts = Counter((r["label"], r["decision"]) for r in rows)
    return {"TP": counts["BLOCK", "BLOCK"], "TN": counts["ALLOW", "ALLOW"],
            "FP": counts["ALLOW", "BLOCK"], "FN": counts["BLOCK", "ALLOW"]}


def root_terms(artifact):
    root = "GET / HTTP/1.1\n"
    features = model2.vector(root, artifact["feature_view"])
    encoded = {f"{k}={v}" if type(v) is str else k: 1.0 if type(v) is str else float(v)
               for k, v in features.items()}
    terms = [{"name": n, "value": encoded.get(n, 0.0), "contribution": encoded.get(n, 0.0) / s * c}
             for n, s, c in zip(artifact["feature_names"], artifact["scale"],
                                artifact["coefficients"], strict=True)
             if encoded.get(n, 0.0)]
    terms.sort(key=lambda x: abs(x["contribution"]), reverse=True)
    return {"canonical_sha256": sha(root.encode()), "p_block": model2.score(artifact, root),
            "intercept": artifact["intercept"],
            "logit": artifact["intercept"] + sum(t["contribution"] for t in terms),
            "features": features, "nonzero_terms": terms}


def run(output):
    train_raw = TRAIN.read_bytes()
    if sha(train_raw) != EXPECTED_TRAIN:
        raise ValueError("frozen TRAIN hash changed")
    artifact = model2.load_artifact(ARTIFACT, expected_sha256=EXPECTED_ARTIFACT)
    train = [r["text"] for r in jsonl(TRAIN)]
    if len(train) != 3080:
        raise ValueError("unexpected TRAIN length")
    train_features = [model2.vector(text, artifact["feature_view"]) for text in train]
    support = {"rows": len(train), "exact_root_count": sum(t == "GET / HTTP/1.1\n" for t in train),
               "path_length_min": min(f["path_length"] for f in train_features),
               "symbol_ratio_max": max(f["symbol_ratio"] for f in train_features)}

    private = jsonl(PRIVATE_CASES)
    public = jsonl(DOCKER / "cases.jsonl")
    if [population.public_case(c) for c in private] != public:
        raise ValueError("private and public sealed cases differ")
    cases = {c["id"]: c for c in private if c["cohort"] == "new_application_DEV"}
    v5_rows = {r["id"]: r for r in jsonl(DOCKER / "native-V5_ONLY.jsonl")
               if r["cohort"] == "new_application_DEV"}
    cascade_rows = {r["id"]: r for r in jsonl(DOCKER / "native-CASCADE_ACTIVE.jsonl")
                    if r["cohort"] == "new_application_DEV"}
    if not (len(cases) == len(v5_rows) == len(cascade_rows) == 540
            and set(cases) == set(v5_rows) == set(cascade_rows)):
        raise ValueError("Docker DEV case alignment changed")

    enriched = []
    for cid, case in cases.items():
        text = population.canonical(case)
        public_hash = population.public_case(case)["canonical_sha256"]
        v5, cascade = v5_rows[cid], cascade_rows[cid]
        if (v5["canonical_sha256"] != public_hash or cascade["canonical_sha256"] != public_hash
                or v5["v5"]["status"] != "ok" or v5["v5"]["decision"] not in ("ALLOW", "BLOCK")
                or cascade["model2"]["status"] != "OK"):
            raise ValueError(f"Docker record mismatch: {cid}")
        features = model2.vector(text, artifact["feature_view"])
        score = model2.score(artifact, text)
        if abs(score - cascade["model2"]["p_block"]) > 1e-12:
            raise ValueError(f"CPU/gateway score mismatch: {cid}")
        observed_early = cascade["record"]["deciding_stage"] == "model2"
        if observed_early != (score >= 0.9):
            raise ValueError(f"CPU/gateway threshold mismatch: {cid}")
        enriched.append({"id": cid, "label": case["label"], "family": case["family"],
                         "component": case["component_id"], "features": features, "score": score,
                         "v5_decision": v5["v5"]["decision"]})

    scenarios = {}
    for name, guard in {
        "baseline_observed": lambda f: True,
        "ratio_guard_cpu": lambda f: f["symbol_ratio"] <= support["symbol_ratio_max"],
        "path_guard_cpu": lambda f: f["path_length"] >= support["path_length_min"],
        "both_guards_cpu": lambda f: (f["symbol_ratio"] <= support["symbol_ratio_max"]
                                      and f["path_length"] >= support["path_length_min"]),
    }.items():
        decisions, early, deferred = [], Counter(), []
        for row in enriched:
            block = row["score"] >= 0.9 and guard(row["features"])
            if block:
                early[row["label"]] += 1
            elif row["score"] >= 0.9:
                deferred.append(row["id"])
            decisions.append({"label": row["label"],
                              "decision": "BLOCK" if block else row["v5_decision"]})
        scenarios[name] = {"confusion": confusion(decisions),
                           "early_block_tp": early["BLOCK"], "early_block_fp": early["ALLOW"],
                           "newly_deferred_early_ids": sorted(deferred)}
    actual = confusion([{"label": r["label"],
                         "decision": "BLOCK" if r["record"]["applied"] == "DENY" else "ALLOW"}
                        for r in cascade_rows.values()])
    if scenarios["baseline_observed"]["confusion"] != actual:
        raise ValueError("baseline counterfactual differs from recorded gateway")

    errors = Counter((r["label"], r["family"], r["component"])
                     for r in enriched if r["v5_decision"] != r["label"])
    report = {
        "schema": "model2-support-docker-dev-diagnostic/v1", "scope": "KNOWN_DEV_CPU_COUNTERFACTUAL",
        "inputs": {"artifact_sha256": EXPECTED_ARTIFACT, "train_sha256": EXPECTED_TRAIN,
                   "docker_protocol_sha256": sha((DOCKER / "PROTOCOL.json").read_bytes()),
                   "docker_cases_sha256": sha((DOCKER / "cases.jsonl").read_bytes()),
                   "v5_rows_sha256": sha((DOCKER / "native-V5_ONLY.jsonl").read_bytes()),
                   "cascade_rows_sha256": sha((DOCKER / "native-CASCADE_ACTIVE.jsonl").read_bytes()),
                   "private_cases_sha256": sha(PRIVATE_CASES.read_bytes()),
                   "source_sha256": sha(Path(__file__).read_bytes())},
        "train_support": support, "root": root_terms(artifact), "scenarios": scenarios,
        "v5_known_errors_by_component": [
            {"label": label, "family": family, "component": component, "n": n}
            for (label, family, component), n in sorted(errors.items())],
        "candidate_selected": None,
        "warning": "Guard scenarios are CPU reconstructions on known DEV. They have no gateway, effect, latency or independent-test evidence."
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.output)
    print(json.dumps({"output": str(args.output), "support": result["train_support"],
                      "scenarios": result["scenarios"]}, sort_keys=True))
