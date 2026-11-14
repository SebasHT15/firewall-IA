"""Paired V5.1/V5.2 census on the same unprotected parent VALIDATION rows."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

from .train_candidate import load, sha


def decision(result, label):
    valid = result["status"] == "ok" and result["ended_with_eos"]
    generated = result["generated"].strip()
    if not valid:
        return "INCORRECT"
    predicted = "BLOCK" if generated.startswith("BLOCK | ") else "ALLOW"
    return "CORRECT" if predicted == label else "INCORRECT"


def matrix(rows, results):
    c = Counter()
    for row, r in zip(rows, results, strict=True):
        label = row["meta"]["label"]
        valid = r["status"] == "ok" and r["ended_with_eos"]
        block = r["generated"].strip().startswith("BLOCK | ") if valid else label == "ALLOW"
        c[(label, block)] += 1
    return {"TP": c["BLOCK", True], "FN": c["BLOCK", False],
            "TN": c["ALLOW", False], "FP": c["ALLOW", True]}


def run(package_path, old_record_path, new_record_path, out):
    if out.exists():
        raise FileExistsError(out)
    _, _, _, rows = load(package_path)
    parent = rows["VALIDATION"][:2080]
    old_raw, new_raw = old_record_path.read_bytes(), new_record_path.read_bytes()
    old, new = json.loads(old_raw), json.loads(new_raw)
    if old.get("outcome") != "TRAINED" or new.get("outcome") != "TRAINED":
        raise ValueError("both runs must be complete")
    if new.get("package_sha256") != sha(package_path.read_bytes()) or new.get("protected_opened") is not False:
        raise ValueError("new run package/protection mismatch")
    earlier, later = old["inference"]["results"], new["inference"]["results"][:2080]
    if len(earlier) != len(later) or len(parent) != len(earlier):
        raise ValueError("parent census incomplete")
    pair = Counter()
    by_label = {"ALLOW": Counter(), "BLOCK": Counter()}
    for row, a, b in zip(parent, earlier, later, strict=True):
        if any(r["text_sha256"] != row["meta"]["text_sha256"] or r["expected"] != row["output"]
               for r in (a, b)):
            raise ValueError("parent row identity/order mismatch")
        label = row["meta"]["label"]
        old_ok, new_ok = decision(a, label), decision(b, label)
        pair[(old_ok, new_ok)] += 1
        by_label[label][(old_ok, new_ok)] += 1
    def cell(counter):
        return {"both_correct": counter["CORRECT", "CORRECT"],
                "v52_fixed": counter["INCORRECT", "CORRECT"],
                "v52_regressed": counter["CORRECT", "INCORRECT"],
                "both_incorrect": counter["INCORRECT", "INCORRECT"]}
    report = {"schema": "v52-parent-paired-validation/v1",
              "scope": "SHARED_PARENT_VALIDATION_NOT_INDEPENDENT_TEST",
              "inputs": {"package_sha256": sha(package_path.read_bytes()),
                         "v51_record_sha256": hashlib.sha256(old_raw).hexdigest(),
                         "v52_record_sha256": hashlib.sha256(new_raw).hexdigest(),
                         "source_sha256": sha(Path(__file__).read_bytes())},
              "v51": matrix(parent, earlier), "v52": matrix(parent, later),
              "paired": cell(pair), "paired_by_label": {k: cell(v) for k, v in by_label.items()},
              "protected_opened": False, "candidate_selected": None}
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--v51-record", type=Path, required=True)
    parser.add_argument("--v52-record", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.package.resolve(), args.v51_record.resolve(),
                         args.v52_record.resolve(), args.out.resolve()), indent=2))
