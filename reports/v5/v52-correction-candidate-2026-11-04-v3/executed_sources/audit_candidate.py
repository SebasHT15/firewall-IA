"""CPU audit of a V5.2 correction delta; never trains or opens protected roles."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys


REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO / "scripts" / "training"), str(REPO / "scripts" / "dataset"),
                str(REPO / "data_plane")]
import canonical_request as canonical
import v5_train_data as data
from transformers import AutoTokenizer


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def read(path):
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def run(manifest_path, output):
    if output.exists():
        raise FileExistsError(output)
    manifest = json.loads(manifest_path.read_text())
    if (manifest.get("schema") != "v52-correction-delta-candidate/v1"
            or manifest.get("training_authorized") is not False
            or manifest.get("protected_opened") is not False):
        raise ValueError("wrong candidate manifest")
    recipe_path = REPO / "reports/v5/successor-training-2026-10-31-reviewed/recipe.EXPERIMENTAL.json"
    if sha(recipe_path.read_bytes()) != manifest["source_sha256"][str(recipe_path.relative_to(REPO))]:
        raise ValueError("recipe changed")
    recipe, _ = data.load_recipe(str(recipe_path))
    base = recipe["base_model"]
    tok = AutoTokenizer.from_pretrained(base["name"], revision=base["revision"],
                                        local_files_only=True)
    contract, diags = data.measure_contract(tok, recipe)
    if diags:
        raise ValueError("token contract failed: " + ",".join(d.code for d in diags))
    vocabulary = set(data.recipe_vocabulary(recipe))
    result = {}
    for split in ("TRAIN", "VALIDATION"):
        desc = manifest["delta_artifacts"][split]
        path = Path(desc["path"])
        raw = path.read_bytes()
        if sha(raw) != desc["sha256"] or len(raw) != desc["bytes"]:
            raise ValueError("delta changed: " + split)
        rows = read(path)
        if len(rows) != desc["rows"]:
            raise ValueError("delta count changed")
        lengths = []
        for index, row in enumerate(rows):
            if row["split"] != split or sha(row["text"].encode()) != row["text_sha256"]:
                raise ValueError("row integrity failed")
            canonical.parse_canonical(row["text"])
            if row["output"] not in vocabulary:
                raise ValueError("output outside V5.1 vocabulary")
            example, err = data.build_example(tok, recipe, contract, row["text"], row["output"])
            if err:
                raise ValueError(f"{split}[{index}]: {err.code}: {err.detail}")
            lengths.append((len(example["input_ids"]), example["content_tokens"],
                            example["completion_tokens"]))
        result[split] = {"rows": len(rows), "labels": dict(Counter(r["label"] for r in rows)),
                         "max_sequence_tokens": max(x[0] for x in lengths),
                         "max_content_tokens": max(x[1] for x in lengths),
                         "max_completion_tokens": max(x[2] for x in lengths),
                         "canonical_parse_pass": len(rows), "tokenization_pass": len(rows),
                         "rejected": 0, "truncated": 0}
    report = {"schema": "v52-correction-delta-cpu-audit/v1",
              "scope": "PROPOSED_POLICY_DEFINED_DELTA_NO_TRAINING",
              "manifest_sha256": sha(manifest_path.read_bytes()),
              "recipe_sha256": sha(recipe_path.read_bytes()),
              "script_sha256": sha(Path(__file__).read_bytes()),
              "token_contract": {"B": contract.B, "max_length": contract.max_length,
                                 "overhead": contract.overhead, "label_budget": contract.label_budget},
              "splits": result, "protected_opened": False,
              "effect_evidence": "NOT_RUN", "candidate_selected": None}
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("x", encoding="utf-8") as handle:
        json.dump(report, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.manifest, args.output)
    print(json.dumps({"splits": result["splits"], "token_contract": result["token_contract"]},
                     sort_keys=True))
