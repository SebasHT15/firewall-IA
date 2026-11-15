"""Aggregate a new Model 2 score on sealed, already-known Docker DEV cases.

CPU counterfactual only. The V5 decisions were recorded earlier, so this does
not claim a measured gateway, a new independent test, or V5.2 performance.
"""
import argparse
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path

from scripts.model2 import training
from scripts.v5_successor.docker_eval import population

ROOT = Path(__file__).resolve().parents[2]
DOCKER = ROOT / "reports/v5/docker-application-2026-11-02/run-1"
PRIVATE = Path("/home/sebas/Documents/Codex/2026-10-26/ta/work/docker-application-20261102-run1/cases.private.jsonl")
OLD = ROOT / "model-output-model2/final/v4-d82-20261027T052308Z/baseline34.json"
OLD_SHA = "da6f6eb85c5a687bd038c6298baf59abdbe0489a80c8993b74a34dae7c60aa38"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read_lines(path):
    return [json.loads(s) for s in path.read_text().splitlines() if s.strip()]


def quality(rows):
    c = Counter((label, decision) for label, decision in rows)
    return {"TP": c["BLOCK", "BLOCK"], "TN": c["ALLOW", "ALLOW"],
            "FP": c["ALLOW", "BLOCK"], "FN": c["BLOCK", "ALLOW"]}


def run(new_artifact, out):
    if out.exists():
        raise FileExistsError(out)
    old = training.load_artifact(OLD, expected_sha256=OLD_SHA)
    new_sha = sha(new_artifact.read_bytes())
    new = training.load_artifact(new_artifact, expected_sha256=new_sha)
    cases = read_lines(PRIVATE)
    if [population.public_case(c) for c in cases] != read_lines(DOCKER / "cases.jsonl"):
        raise ValueError("sealed private/public cases differ")
    v5 = {r["id"]: r for r in read_lines(DOCKER / "native-V5_ONLY.jsonl")
          if r["cohort"] == "new_application_DEV"}
    observed = {r["id"]: r for r in read_lines(DOCKER / "native-CASCADE_ACTIVE.jsonl")
                if r["cohort"] == "new_application_DEV"}
    selected = [c for c in cases if c["cohort"] == "new_application_DEV"]
    if not (len(selected) == len(v5) == len(observed) == 540):
        raise ValueError("Docker population size mismatch")
    scenarios = {name: {"decisions": [], "early": Counter(), "early_texts": defaultdict(set),
                        "early_families": Counter()} for name in ("V5.1_only", "old_model2_at_0_9", "new_model2_at_0_9")}
    for case in selected:
        cid = case["id"]
        text = population.canonical(case)
        digest = sha(text.encode())
        if digest != population.public_case(case)["canonical_sha256"] or v5[cid]["canonical_sha256"] != digest:
            raise ValueError("canonical identity mismatch")
        v5_decision = v5[cid]["v5"]["decision"]
        if v5_decision not in ("ALLOW", "BLOCK"):
            raise ValueError("V5 record incomplete")
        old_p = training.score(old, text)
        if abs(old_p - observed[cid]["model2"]["p_block"]) > 1e-12:
            raise ValueError("old gateway/CPU score mismatch")
        scores = {"V5.1_only": 0.0, "old_model2_at_0_9": old_p,
                  "new_model2_at_0_9": training.score(new, text)}
        for name, p in scores.items():
            cell = scenarios[name]
            early = p >= .9
            decision = "BLOCK" if early else v5_decision
            cell["decisions"].append((case["label"], decision))
            if early:
                cell["early"][case["label"]] += 1
                cell["early_texts"][case["label"]].add(digest)
                cell["early_families"][(case["label"], case["family"])] += 1
    summary = {}
    for name, cell in scenarios.items():
        summary[name] = {"confusion": quality(cell["decisions"]),
                         "early_by_label": dict(cell["early"]),
                         "unique_early_texts_by_label": {k: len(v) for k, v in cell["early_texts"].items()},
                         "early_by_family": [{"label": label, "family": family, "count": n}
                                             for (label, family), n in sorted(cell["early_families"].items())]}
    if summary["old_model2_at_0_9"]["confusion"] != {"TP": 151, "TN": 324, "FP": 48, "FN": 17}:
        raise ValueError("old cascade reconstruction mismatch")
    report = {"schema": "model2-successor-known-dev-counterfactual/v1",
              "scope": "KNOWN_DEV_CPU_COUNTERFACTUAL_V51_RECORDED", "threshold": .9,
              "inputs": {"new_artifact_sha256": new_sha, "old_artifact_sha256": OLD_SHA,
                         "private_cases_sha256": sha(PRIVATE.read_bytes()),
                         "public_cases_sha256": sha((DOCKER / "cases.jsonl").read_bytes()),
                         "v5_rows_sha256": sha((DOCKER / "native-V5_ONLY.jsonl").read_bytes()),
                         "source_sha256": sha(Path(__file__).read_bytes())},
              "root": {"old_p_block": training.score(old, "GET / HTTP/1.1\n"),
                       "new_p_block": training.score(new, "GET / HTTP/1.1\n")},
              "scenarios": summary, "candidate_selected": None,
              "limits": ["Known development population; repeated cases share templates and texts",
                         "New Model 2 scores were not run through the gateway",
                         "The downstream decisions are recorded V5.1, not V5.2"]}
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--new-artifact", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.new_artifact.resolve(), args.out.resolve())
    print(json.dumps({"root": result["root"], "scenarios": result["scenarios"]}, indent=2))
