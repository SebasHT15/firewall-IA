"""Post-hoc selective Model 2 policy audit on two already-known DEV populations."""
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "data_plane"))
import model2_decider as decider  # noqa: E402
from scripts.v5_successor.docker_eval import population  # noqa: E402

ARTIFACT = ROOT / "model-output-model2/final/v4-d82-20261027T052308Z/baseline34.json"
ARTIFACT_SHA = "da6f6eb85c5a687bd038c6298baf59abdbe0489a80c8993b74a34dae7c60aa38"
POLICY = ROOT / "reports/v5/model2-guarded-2026-11-05/policy.LAB_EXPERIMENTAL.json"
OLD = ROOT / "reports/v5/successor-evaluation-2026-11-01"
DOCKER = ROOT / "reports/v5/docker-application-2026-11-02/run-1"
DOCKER_PRIVATE = Path("/home/sebas/Documents/Codex/2026-10-26/ta/work/docker-application-20261102-run1/cases.private.jsonl")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def rows(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def inspect(cases, model, old_scores, *, canonical):
    counts = Counter()
    unique = defaultdict(set)
    for case in cases:
        text = canonical(case)
        digest = sha(text.encode())
        if digest != case.get("canonical_sha256", digest) or digest != old_scores[case["id"]]["canonical_sha256"]:
            raise ValueError("canonical identity mismatch")
        result = model.decide(canonical_outcome="ACCEPT", canonical_text=text)
        if result.status != "OK" or result.p_block is None:
            raise ValueError("Model 2 failed to score a known DEV case")
        if abs(result.p_block - old_scores[case["id"]]["p_block"]) > 1e-12:
            raise ValueError("original Model 2 score changed")
        counts["scored"] += 1
        high = result.p_block >= .9
        if high:
            counts["high_" + case["label"]] += 1
        if result.decision == "BLOCK":
            if not high:
                raise ValueError("guard blocked below threshold")
            counts["early_" + case["label"]] += 1
            unique[case["label"]].add(digest)
        elif high:
            counts["guard_deferred_" + case["label"]] += 1
    return {"n": len(cases), "scored": counts["scored"],
            "counterfactual_unguarded_early": {k: counts["high_" + k] for k in ("BLOCK", "ALLOW")},
            "guarded_early": {k: counts["early_" + k] for k in ("BLOCK", "ALLOW")},
            "guard_deferred_high_score": {k: counts["guard_deferred_" + k] for k in ("BLOCK", "ALLOW")},
            "unique_guarded_early": {k: len(unique[k]) for k in ("BLOCK", "ALLOW")}}


def run(out):
    if out.exists():
        raise FileExistsError(out)
    model = decider.Model2Decider.from_policy_file(str(ARTIFACT), expected_sha256=ARTIFACT_SHA,
                                                   policy_path=str(POLICY))
    protocol_path = OLD / "cohorts/protocol.v2.json"
    protocol = json.loads(protocol_path.read_text())
    old_private_path = Path(protocol["cases_private"]["path"])
    if sha(old_private_path.read_bytes()) != protocol["cases_private"]["sha256"]:
        raise ValueError("old DEV private cases changed")
    old_cases = rows(old_private_path)
    public = rows(Path(protocol["cases_public"]["path"]))
    if [{k: v for k, v in c.items() if k != "canonical_text"} for c in old_cases] != public:
        raise ValueError("old DEV public/private mismatch")
    old_scores_path = OLD / "model2-baseline34/predictions.jsonl"
    old_scores = {r["id"]: r for r in rows(old_scores_path)}
    if not (len(old_cases) == len(old_scores) == 2514):
        raise ValueError("old DEV size mismatch")
    old_result = inspect(old_cases, model, old_scores, canonical=lambda c: c["canonical_text"])

    private_cases = rows(DOCKER_PRIVATE)
    if [population.public_case(c) for c in private_cases] != rows(DOCKER / "cases.jsonl"):
        raise ValueError("Docker public/private mismatch")
    selected = [c for c in private_cases if c["cohort"] == "new_application_DEV"]
    gateway_scores_path = DOCKER / "native-CASCADE_ACTIVE.jsonl"
    gateway_scores = {r["id"]: {"canonical_sha256": r["canonical_sha256"],
                                "p_block": r["model2"]["p_block"]}
                      for r in rows(gateway_scores_path) if r["cohort"] == "new_application_DEV"}
    docker_result = inspect(selected, model, gateway_scores, canonical=population.canonical)
    v5_path = DOCKER / "native-V5_ONLY.jsonl"
    v5 = {r["id"]: r for r in rows(v5_path) if r["cohort"] == "new_application_DEV"}
    if len(selected) != len(v5) or len(selected) != 540:
        raise ValueError("Docker population size mismatch")
    confusion = Counter()
    for case in selected:
        text = population.canonical(case)
        result = model.decide(canonical_outcome="ACCEPT", canonical_text=text)
        decision = "BLOCK" if result.decision == "BLOCK" else v5[case["id"]]["v5"]["decision"]
        confusion[(case["label"], decision)] += 1
    docker_result["cascade_with_recorded_v51"] = {
        "TP": confusion["BLOCK", "BLOCK"], "TN": confusion["ALLOW", "ALLOW"],
        "FP": confusion["ALLOW", "BLOCK"], "FN": confusion["BLOCK", "ALLOW"]}
    report = {"schema": "model2-selective-guard-known-dev/v1",
              "scope": "POST_HOC_KNOWN_DEV_CPU_COUNTERFACTUAL", "status": "LAB_CANDIDATE_NOT_SELECTED",
              "identity": {"artifact_sha256": ARTIFACT_SHA, "policy_file_sha256": sha(POLICY.read_bytes()),
                           "source_sha256": sha(Path(__file__).read_bytes()),
                           "old_protocol_sha256": sha(protocol_path.read_bytes()),
                           "old_scores_sha256": sha(old_scores_path.read_bytes()),
                           "docker_private_sha256": sha(DOCKER_PRIVATE.read_bytes()),
                           "docker_gateway_scores_sha256": sha(gateway_scores_path.read_bytes()),
                           "docker_v51_rows_sha256": sha(v5_path.read_bytes())},
              "old_dev": old_result, "docker_dev": docker_result,
              "warnings": ["Guard was designed after seeing these development errors",
                           "Zero FP here does not imply zero FP on a new application",
                           "V5.1 decisions are recorded, not rerun through this gateway"]}
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


if __name__ == "__main__":
    out = ROOT / "reports/v5/model2-guarded-2026-11-05/known-dev.json"
    print(json.dumps(run(out), indent=2))
