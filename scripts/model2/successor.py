"""One experimental Model 2 correction with an explicit benign short-route cohort.

The original final dataset is read through its existing gated reader. The new
cohort is policy-defined engineering data, not an independently observed app.
No protected split or fwlab-notes route is used. This never creates a FINAL
artifact or approves an operating threshold.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path

from . import training
from .v5_fixture_integration import exchange

ROOT = Path(__file__).resolve().parents[2]
DATASET = ROOT / "datasets/v5_sources/final_source_2026-10-26-v4"
RECORDS = ROOT / "reports/v5/dataset-preregistration-v1/final-run-2026-10-26-v4"
METHODS = ("GET", "HEAD", "OPTIONS", "POST", "PUT", "DELETE", "PATCH")
# Distinct paths by split; the root itself is deliberately in TRAIN.
PATHS = {
    "TRAIN": ("/", "/a", "/api", "/ui", "/x", "/v1", "/hi", "/ok", "/me", "/go", "/id", "/r"),
    "VALIDATION": ("/b", "/app", "/web", "/v2", "/q", "/up"),
}
POLICY = "benign HTTP request with no attack-bearing input; route existence is not assumed"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(obj):
    return training.encode(obj)


def cohort(parent):
    """Generate declared variants, excluding any text seen in the parent."""
    prior = {r["text_sha256"] for rows in parent.values() for r in rows}
    result = {"TRAIN": [], "VALIDATION": []}
    for split, paths in PATHS.items():
        for path in paths:
            for method in METHODS:
                canonical = f"{method} {path} HTTP/1.1\n"
                training.vector(canonical, "baseline_34")
                digest = sha(canonical.encode())
                if digest in prior:
                    raise ValueError("new cohort overlaps parent or other split")
                prior.add(digest)
                result[split].append({"text": canonical, "text_sha256": digest,
                                      "label": "ALLOW", "label_status": "POLICY_DEFINED",
                                      "policy": POLICY, "path": path})
    return result


def to_example(row, split, index, manifest):
    text_hash = row["text_sha256"]
    prefix = "model2-short-route-" + split.lower() + "-"
    identities = {"text_sha256": text_hash,
                  "pair_id": prefix + row["path"] + "-" + text_hash[:12],
                  "payload_family_id": prefix + row["path"],
                  "payload_record_id": prefix + text_hash,
                  "struct_cluster_id": prefix + row["path"],
                  "template_id": prefix + row["path"], "value_entries": []}
    return {"split": split, "row_index": index, "text": row["text"],
            "output": "ALLOW | Normal HTTP request with no attack patterns detected.",
            "label": "ALLOW", "label_status": "POLICY_DEFINED",
            "label_basis": "short_route_policy_defined", "audit_type": "engineering",
            "row_contract": None, "label_status_basis": "policy_defined",
            "text_sha256": text_hash, "identities": identities,
            "manifest_sha256": manifest, "eligibility": {"trainable": True}}


def run(out_dir):
    if out_dir.exists():
        raise FileExistsError(out_dir)
    gated = exchange.load_final_examples(
        str(DATASET), dataset_prereg=str(RECORDS / "preregistration.json"),
        freeze_record=str(RECORDS / "freeze-record.json"),
        ai_audit_authorization=str(RECORDS / "v5-ai-audit-training-authorization.json"))
    parent = gated["examples"]
    delta = cohort(parent)
    recipe = copy.deepcopy(training.candidate_recipe())
    recipe.update(status="RATIFIED", owner_decision="Sebas chat authorization 2026-11-04: experimental Model 2 successor",
                  feature_view="baseline_34", max_iter=5000)
    composition = {"schema": "model2-short-route-composition/v1",
                   "scope": "EXPERIMENTAL_MODEL2_ONLY", "parent": gated["dataset_final_evidence"],
                   "new_cohort": {split: {"rows": len(delta[split]),
                                          "sha256": sha(encode(delta[split]))}
                                  for split in delta},
                   "policy": POLICY, "methods": METHODS, "paths": PATHS,
                   "recipe_sha256": sha(encode(recipe)),
                   "source_sha256": sha(Path(__file__).read_bytes()),
                   "protected_opened": False, "fwlab_notes_used": False}
    manifest = sha(encode(composition))
    examples = {split: [dict(row, manifest_sha256=manifest) for row in parent[split]]
                for split in ("TRAIN", "VALIDATION")}
    for split in examples:
        examples[split].extend(to_example(row, split, len(parent[split]) + i, manifest)
                               for i, row in enumerate(delta[split]))
    artifact, report = training._fit(examples, recipe, "EXPERIMENTAL")
    artifact["composition_sha256"] = manifest
    artifact["parent_manifest_sha256"] = gated["dataset_final_evidence"]["manifest_sha256"]
    artifact["successor_source_sha256"] = composition["source_sha256"]
    artifact["reader_source_sha256"] = {name: sha((ROOT / name).read_bytes())
                                         for name in training.READER_SOURCES}
    out_dir.mkdir(parents=True)
    (out_dir / "composition.json").write_bytes(encode(composition))
    (out_dir / "cohort.TRAIN.json").write_bytes(encode(delta["TRAIN"]))
    (out_dir / "cohort.VALIDATION.json").write_bytes(encode(delta["VALIDATION"]))
    (out_dir / "recipe.json").write_bytes(encode(recipe))
    artifact_sha = training.save_artifact(artifact, out_dir / "model2.json")
    training.load_artifact(out_dir / "model2.json", expected_sha256=artifact_sha)
    root_text = "GET / HTTP/1.1\n"
    report.update(schema="model2-short-route-run/v1", composition_sha256=manifest,
                  artifact_sha256=artifact_sha, root_probability=training.score(artifact, root_text),
                  protected_opened=False, candidate_selected=None,
                  note="Experimental policy-defined augmentation; validation is development data, not a final test")
    (out_dir / "report.json").write_bytes(encode(report))
    return {"artifact_sha256": artifact_sha, "root_probability": report["root_probability"],
            "rows": {k: len(v) for k, v in examples.items()}, "out_dir": str(out_dir)}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.output_dir.resolve()), indent=2))
