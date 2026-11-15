"""Aggregate the complete V5.2 training census without loading model weights.

Reads only the bound, unprotected parent and correction VALIDATION roles. The
trainer writes one greedy output per row; invalid outputs remain classification
errors in the principal matrix even when the gateway later denies them.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO))
from scripts.v52_correction.train_candidate import load, sha


def read_delta(package):
    manifest = json.loads(Path(package["delta_manifest"]["path"]).read_text())
    desc = manifest["delta_artifacts"]["VALIDATION"]
    raw = Path(desc["path"]).read_bytes()
    if sha(raw) != desc["sha256"] or len(raw) != desc["bytes"]:
        raise ValueError("delta validation changed")
    return [json.loads(line) for line in raw.splitlines()]


def measure(pairs):
    matrix = Counter()
    status = Counter()
    reasons = Counter()
    n = 0
    for row, result in pairs:
        n += 1
        expected = row["output"]
        true_block = expected.startswith("BLOCK | ")
        valid = result["status"] == "ok" and result["ended_with_eos"]
        generated = result["generated"].strip()
        predicted_block = generated.startswith("BLOCK | ") if valid else not true_block
        if not valid:
            status["invalid"] += 1
            status[str(result.get("invalid_reason"))] += 1
        else:
            status["valid"] += 1
        if true_block:
            matrix["TP" if valid and predicted_block else "FN"] += 1
            if valid and predicted_block:
                reasons["eligible"] += 1
                if generated == expected:
                    reasons["exact"] += 1
        else:
            matrix["FP" if (not valid or predicted_block) else "TN"] += 1
    return {"n": n, "principal_E5": {k: matrix[k] for k in ("TP", "TN", "FP", "FN")},
            "status": dict(status), "block_reason": dict(reasons)}


def run(package_path, run_record_path, output):
    package, _, _, rows = load(package_path)
    run_raw = run_record_path.read_bytes()
    record = json.loads(run_raw)
    if (record.get("schema") != "v52-experimental-run/v1"
            or record.get("outcome") != "TRAINED"
            or record.get("training_started") is not True
            or record.get("package_sha256") != sha(package_path.read_bytes())
            or record.get("protected_opened") is not False):
        raise ValueError("wrong or unfinished V5.2 training run")
    results = record["inference"]["results"]
    expected_rows = rows["VALIDATION"]
    if len(results) != len(expected_rows) or record["inference"]["n"] != len(expected_rows):
        raise ValueError("incomplete validation census")
    for index, (row, result) in enumerate(zip(expected_rows, results)):
        if (row["meta"]["text_sha256"] != result["text_sha256"]
                or row["output"] != result["expected"]):
            raise ValueError("validation order/identity mismatch at " + str(index))
    delta = read_delta(package)
    parent_count = len(expected_rows) - len(delta)
    if parent_count != 2080 or len(delta) != 210:
        raise ValueError("parent/delta boundary changed")
    slices = {"combined": measure(zip(expected_rows, results)),
              "parent": measure(zip(expected_rows[:parent_count], results[:parent_count])),
              "delta": measure(zip(expected_rows[parent_count:], results[parent_count:]))}
    for family in sorted({row["family"] for row in delta}):
        indices = [parent_count + i for i, row in enumerate(delta) if row["family"] == family]
        slices["delta_family_" + family] = measure((expected_rows[i], results[i]) for i in indices)
    for component in sorted({row["component_id"] for row in delta}):
        indices = [parent_count + i for i, row in enumerate(delta) if row["component_id"] == component]
        slices["delta_component_" + component] = measure((expected_rows[i], results[i]) for i in indices)
    report = {"schema": "v52-training-census-analysis/v1",
              "scope": "TRAINING_VALIDATION_ONLY_NOT_INDEPENDENT_TEST",
              "package_sha256": sha(package_path.read_bytes()),
              "run_record_sha256": hashlib.sha256(run_raw).hexdigest(),
              "slices": slices, "protected_opened": False,
              "candidate_selected": None,
              "note": "Invalid is an error in the true class; fail-closed derived blocking is separate."}
    with output.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
        handle.write("\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--run-record", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.package, args.run_record, args.output)
    print(json.dumps({"scope": result["scope"], "slices": {k: v for k, v in result["slices"].items()
                                                           if k in ("combined", "parent", "delta")}}, sort_keys=True))
