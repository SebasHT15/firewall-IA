"""Bind the V5.2 correction delta, recipe and protocol for owner review.

Only drafts an admission record. It cannot approve, commit or train.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path


REPO = Path(__file__).resolve().parents[2]
COORD = Path("/home/sebas/Documents/Codex/2026-10-26/ta/outputs/Coordinacion_modelos_arquitectura")
PARENT = REPO / "reports/v5/successor-training-2026-10-31-reviewed/dataset-manifest.EXPERIMENTAL.json"
OLD_RECIPE = REPO / "reports/v5/successor-training-2026-10-31-reviewed/recipe.EXPERIMENTAL.json"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def bound(path):
    path = Path(path).resolve()
    raw = path.read_bytes()
    return {"path": str(path), "sha256": sha(raw), "bytes": len(raw)}


def write(path, obj):
    with path.open("x", encoding="utf-8") as handle:
        json.dump(obj, handle, indent=2, ensure_ascii=False, sort_keys=True)
        handle.write("\n")


def run(delta_manifest_path, audit_path, output):
    if output.exists():
        raise FileExistsError(output)
    delta = json.loads(delta_manifest_path.read_text())
    audit = json.loads(audit_path.read_text())
    if (delta.get("schema") != "v52-correction-delta-candidate/v1"
            or delta.get("training_authorized") is not False
            or audit.get("manifest_sha256") != sha(delta_manifest_path.read_bytes())
            or audit.get("protected_opened") is not False):
        raise ValueError("delta/audit identity mismatch")
    if delta["summary"]["TRAIN"]["rows"] != 780 or delta["summary"]["VALIDATION"]["rows"] != 210:
        raise ValueError("delta size changed")
    pinned = json.loads((COORD / "CONTRATO_DE_TRABAJO.json").read_text())["immutable_model2_bound_sources"]
    for name, digest in pinned.items():
        if sha((REPO / name).read_bytes()) != digest:
            raise ValueError("immutable source changed: " + name)
    original = json.loads(OLD_RECIPE.read_text())
    recipe = copy.deepcopy(original)
    recipe["recipe_id"] = "v52-app-correction-experimental-20261104"
    recipe["status"] = "PROPOSED"
    recipe["note"] = ("Fresh LoRA from pinned base, V5.1 TRAIN/VALIDATION retained as immutable parents, "
                      "policy-defined application correction delta appended. Owner admission and commit required; "
                      "no FINAL or deployment authorization.")
    recipe["initialization"] = {"mode": "PINNED_BASE_WITH_NEW_LORA",
                                "continue_from_adapter": False,
                                "original_TRAIN_preserved": True, "status": "PROPOSED"}
    protocol = {
        "schema": "v52-correction-training-protocol/v1", "status": "PROPOSED",
        "scope": "EXPERIMENTAL_V52_ONLY", "protected_sets": "CLOSED",
        "parent_manifest_sha256": sha(PARENT.read_bytes()),
        "delta_manifest_sha256": sha(delta_manifest_path.read_bytes()),
        "delta_cpu_audit_sha256": sha(audit_path.read_bytes()),
        "parent_usage": "V5.1 TRAIN and VALIDATION revalidated through existing gate; no reserve",
        "delta_label_basis": "POLICY_DEFINED by disposable application behavior; no new effect controls yet",
        "split_rule": "Complete ALLOW/BLOCK pairs and template components assigned to one split; known DEV texts excluded",
        "checkpoint_selection": "Lowest combined parent-plus-delta VALIDATION loss; report delta performance separately",
        "max_initial_training_runs": 1,
        "required_post_training": [
            "Check complete binary/reason/invalid census on parent validation and new delta validation",
            "Check known Docker and authored DEV regressions without claiming independent quality",
            "Compare NF4 with and without double quantization and native versus verified decoder on new weights",
            "Select and calibrate only on newly declared selection data, separated by source/component/template",
            "Run final test only after candidate/profile/policy freeze and owner authorization",
        ],
        "known_limits": [
            "Delta is app-specific and not a general Internet distribution",
            "Effect controls were not run for each new delta case",
            "Benign search edge examples are unpaired and need shortcut review",
            "One GPU/training seed and development validation do not establish generalization",
            "No claim about JWT, CSRF, TLS, HTTP/2 or embedded hardware from model training",
        ],
    }
    sources = [
        "scripts/v52_correction/build_candidate.py",
        "scripts/v52_correction/audit_candidate.py",
        "scripts/v52_correction/train_candidate.py",
        "scripts/v52_correction/prepare_training_package.py",
        "scripts/v5_successor/successor_contract.py",
        "scripts/training/v5_train_data.py",
        "scripts/training/finetune_v5.py",
        "control_plane/v5_tokenization.py",
        "control_plane/v5_output_contract.py",
        "scripts/v5_successor/docker_eval/target.py",
    ]
    source_hashes = {name: sha((REPO / name).read_bytes()) for name in sources}
    output.mkdir(parents=True)
    recipe_path = output / "recipe.PROPOSED.json"
    protocol_path = output / "protocol.PROPOSED.json"
    write(recipe_path, recipe)
    write(protocol_path, protocol)
    package_path = output / "PACKAGE.PROPOSED.json"
    package = {
        "schema": "v52-experimental-training-package/v1", "status": "PROPOSED",
        "training_authorized": False, "candidate_selected": None,
        "recipe": bound(recipe_path), "protocol": bound(protocol_path),
        "parent_manifest": bound(PARENT), "delta_manifest": bound(delta_manifest_path),
        "cpu_audit": bound(audit_path), "delta_summary": delta["summary"],
        "source_sha256": source_hashes,
        "immutable_model2_sources_verified": len(pinned),
        "reserve_opened": False, "protected_opened": False,
    }
    write(package_path, package)
    admission = {
        "schema": "v52-experimental-training-admission/v1",
        "status": "DRAFT_PENDING_OWNER", "scope": "EXPERIMENTAL_V52_ONLY",
        "training_allowed": False, "owner_decision": "", "authorized_by": "", "date": "",
        "package_sha256": sha(package_path.read_bytes()),
        "recipe_sha256": package["recipe"]["sha256"],
        "protocol_sha256": package["protocol"]["sha256"],
        "delta_manifest_sha256": package["delta_manifest"]["sha256"],
        "note": "Review exact app policy, unpaired benign edge examples and limits before a separate approval."
    }
    write(output / "owner-admission.DRAFT.json", admission)
    return package


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--delta-manifest", type=Path, required=True)
    parser.add_argument("--cpu-audit", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.delta_manifest.resolve(), args.cpu_audit.resolve(), args.out.resolve())
    print(json.dumps({"status": result["status"], "delta": result["delta_summary"],
                      "immutable_sources_verified": result["immutable_model2_sources_verified"]},
                     ensure_ascii=False, sort_keys=True))
