"""Offline C1 logistic-regression training and portable JSON scoring.

SMOKE generates its own fixture; EXPERIMENTAL uses the shared authorized reader.
FINAL is exposed by final_training with separate, default-off owner gates.
No model selection, operating threshold or enforcement is implied.
"""
import argparse
from collections import Counter
import hashlib
import json
import math
from pathlib import Path
import sys
import tempfile
import warnings

from . import fixture_experiment as features
from .identity_groups import connected_groups, GROUP_DEFINITION
from .feature_views import PATH_VIEW
from .v5_fixture_integration import exchange
RC = exchange.D.RC

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = "model2-logistic-artifact/v1"
RECIPE_SCHEMA = "model2-training-recipe/proposal-v1"
VIEWS = ("baseline_34", PATH_VIEW)
SOURCES = ("data_plane/request_features.py", "data_plane/canonical_request.py",
           "scripts/model2/contracts.py", "scripts/model2/feature_views.py",
           "scripts/model2/fixture_experiment.py", "scripts/model2/identity_groups.py",
           "scripts/model2/training.py", "scripts/model2/final_training.py", "scripts/dataset/v5_row_contract.py")
READER_SOURCES = ("scripts/training/v5_example_exchange.py", "scripts/training/v5_train_data.py",
                  "scripts/training/v5_training_recipe_v1.json")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encode(obj):
    return (json.dumps(obj, ensure_ascii=False, sort_keys=True, allow_nan=False,
                       separators=(",", ":")) + "\n").encode("utf-8")


def source_hashes():
    return {name: digest((ROOT / name).read_bytes()) for name in SOURCES}


def candidate_recipe():
    return {"schema": RECIPE_SCHEMA, "status": "PROPOSED", "owner_decision": None,
            "representation": features.REPRESENTATION, "feature_view": "baseline_34",
            "learner": "LogisticRegression", "C": 1.0, "solver": "lbfgs",
            "max_iter": 500, "tol": 1e-6, "random_state": 0,
            "scaler": "StandardScaler(with_mean=False)", "fit_role": "TRAIN",
            "c1_extensions": "metadata_only", "operating_threshold": None}


def validate_recipe(recipe, mode):
    expected = candidate_recipe()
    if type(recipe) is not dict or set(recipe) != set(expected):
        raise ValueError("recipe fields differ from the explicit contract")
    for key in ("schema", "representation", "learner", "solver", "scaler", "fit_role",
                "c1_extensions", "operating_threshold"):
        if recipe[key] != expected[key]:
            raise ValueError(f"unsupported recipe field: {key}")
    if recipe["feature_view"] not in VIEWS:
        raise ValueError("unknown feature view")
    for key in ("C", "tol"):
        if type(recipe[key]) not in (int, float) or not math.isfinite(recipe[key]) or recipe[key] <= 0:
            raise ValueError(f"invalid recipe {key}")
    for key in ("max_iter", "random_state"):
        if type(recipe[key]) is not int or recipe[key] < (1 if key == "max_iter" else 0):
            raise ValueError(f"invalid recipe {key}")
    if mode not in ("SMOKE", "EXPERIMENTAL", "FINAL"):
        raise ValueError("unsupported training mode")
    if recipe["status"] not in ("PROPOSED", "RATIFIED"):
        raise ValueError("unknown recipe status")
    if mode in ("EXPERIMENTAL", "FINAL") and (recipe["status"] != "RATIFIED" or
            type(recipe["owner_decision"]) is not str or not recipe["owner_decision"].strip()):
        raise ValueError(f"{mode} requires a ratified recipe and owner decision")


def vector(text, view):
    # Both views reject malformed canonical input before feature extraction.
    features.cr.parse_canonical(text)
    return features.feature_dict(text, neutralize_path=view == PATH_VIEW)


def _validate_examples(examples):
    groups = connected_groups(examples)
    manifests = set()
    for split, rows in examples.items():
        for row in rows:
            reference = (row.get('row_contract') == RC.SCHEMA and row.get('label_status') == RC.TRAINING_REFERENCE
                         and row.get('audit_type') == 'ai_audited' and row.get('label_status_basis') == 'ai_audit'
                         and row.get('label') == 'BLOCK')
            if (row.get("eligibility") != {"trainable": True} or row.get("label") not in ("ALLOW", "BLOCK")
                    or (row.get("label_status") not in ("VERIFIED", "POLICY_DEFINED") and not reference)):
                raise ValueError("ineligible example")
            if type(row.get("text")) is not str or digest(row["text"].encode()) != row.get("text_sha256"):
                raise ValueError("example text integrity mismatch")
            if row["identities"]["text_sha256"] != row["text_sha256"]:
                raise ValueError("identity text hash mismatch")
            manifest = row.get("manifest_sha256")
            if type(manifest) is not str or len(manifest) != 64 or any(c not in "0123456789abcdef" for c in manifest):
                raise ValueError("manifest hash missing or invalid")
            manifests.add(manifest)
    if len(manifests) != 1:
        raise ValueError("mixed dataset manifests")
    if {r["label"] for r in examples["TRAIN"]} != {"ALLOW", "BLOCK"}:
        raise ValueError("TRAIN must contain both classes")
    return groups, next(iter(manifests))


def _fit(examples, recipe, mode, *, final_evidence=None):
    """Internal engine; callers must establish access through the public entry points."""
    import numpy as np
    import sklearn
    from sklearn.feature_extraction import DictVectorizer
    from sklearn.preprocessing import StandardScaler
    from sklearn.linear_model import LogisticRegression
    from sklearn.exceptions import ConvergenceWarning
    validate_recipe(recipe, mode)
    groups, manifest = _validate_examples(examples)
    if mode == "FINAL":
        from .final_training import validate_evidence
        validate_evidence(final_evidence, recipe, manifest)
    before = source_hashes()
    encoder = DictVectorizer(sparse=True, sort=True)
    scaler = StandardScaler(with_mean=False)
    view = recipe["feature_view"]
    train = examples["TRAIN"]
    validation = examples["VALIDATION"]
    x_train = scaler.fit_transform(encoder.fit_transform([vector(r["text"], view) for r in train]))
    x_val = scaler.transform(encoder.transform([vector(r["text"], view) for r in validation]))
    model = LogisticRegression(**{k: recipe[k] for k in ("C", "solver", "max_iter", "tol", "random_state")})
    with warnings.catch_warnings():
        warnings.simplefilter("error", ConvergenceWarning)
        model.fit(x_train, [r["label"] for r in train])
    if list(model.classes_) != ["ALLOW", "BLOCK"]:
        raise ValueError("unexpected class order")
    artifact = {
        "schema": SCHEMA, "mode": mode, "representation": features.REPRESENTATION,
        "feature_schema": features.rf.FEATURE_SCHEMA_VERSION, "feature_view": view,
        "feature_names": list(encoder.get_feature_names_out()),
        "scale": scaler.scale_.tolist(), "coefficients": model.coef_[0].tolist(),
        "intercept": float(model.intercept_[0]), "classes": list(model.classes_),
        "recipe": recipe, "recipe_sha256": digest(encode(recipe)),
        "dataset_manifest_sha256": manifest, "source_sha256": before,
        "versions": {"python": sys.version.split()[0], "sklearn": sklearn.__version__, "numpy": np.__version__},
        "operating_threshold": None, "operational_policy_approved": False,
        "population": "all_traffic_fast_path_ineligible", "group_definition": GROUP_DEFINITION,
        "metadata": {split: {"rows": len(rows),
            "components": len({groups[(split, r['row_index'])] for r in rows}),
            "labels": dict(Counter(r["label"] for r in rows)),
            "label_status": dict(Counter(r["label_status"] for r in rows)),
            "label_basis": dict(Counter(str(r.get("label_basis")) for r in rows)),
            "label_status_basis": dict(Counter(str(r.get("label_status_basis")) for r in rows)),
            "audit_type": dict(Counter(str(r.get("audit_type")) for r in rows)),
            "row_contract": dict(Counter(str(r.get("row_contract")) for r in rows))}
            for split, rows in examples.items()},
    }
    if mode == "FINAL":
        artifact["final_training_evidence"] = final_evidence
    check_artifact(artifact)
    native = model.predict_proba(x_val)[:, 1]
    portable = np.array([score(artifact, r["text"]) for r in validation])
    if not np.allclose(native, portable, atol=1e-12, rtol=1e-12):
        raise ValueError("portable probability fidelity failed")
    if before != source_hashes():
        raise RuntimeError("source changed during training")
    report = {"mode": mode, "metadata": artifact["metadata"],
              "max_probability_delta": float(np.max(np.abs(native - portable))),
              "threshold_selected": False, "operational_policy_approved": False,
              "validation_scores": [{"row_index": r["row_index"],
                  "group_id": groups[("VALIDATION", r["row_index"])], "reference_label": r["label"],
                  "label_status": r["label_status"], "label_basis": r.get("label_basis"),
                  "label_status_basis": r.get("label_status_basis"), "audit_type": r.get("audit_type"),
                  "row_contract": r.get("row_contract"),
                  "p_block": float(p)} for r,p in zip(validation,native,strict=True)]}
    return artifact, report


def check_artifact(a):
    if (a.get("schema") != SCHEMA or a.get("representation") != features.REPRESENTATION
            or a.get("feature_schema") != features.rf.FEATURE_SCHEMA_VERSION
            or a.get("feature_view") not in VIEWS or a.get("classes") != ["ALLOW", "BLOCK"]
            or a.get("operating_threshold") is not None or a.get("operational_policy_approved") is not False):
        raise ValueError("artifact contract mismatch")
    validate_recipe(a.get("recipe"), a.get("mode"))
    if a["recipe"]["feature_view"] != a["feature_view"] or a.get("recipe_sha256") != digest(encode(a["recipe"])):
        raise ValueError("artifact recipe mismatch")
    if a.get("mode") == "FINAL":
        from .final_training import validate_evidence
        validate_evidence(a.get("final_training_evidence"), a["recipe"], a.get("dataset_manifest_sha256"))
    names = a.get("feature_names")
    if type(names) is not list or not names or any(type(n) is not str for n in names) or len(set(names)) != len(names):
        raise ValueError("invalid encoder vocabulary")
    allowed = set(features.FEATURES) - (features.DIRECT_PATH_FIELDS if a["feature_view"] == PATH_VIEW else set())
    for name in names:
        if name.split("=", 1)[0] not in allowed:
            raise ValueError("unapproved learned feature")
    for key in ("scale", "coefficients"):
        values = a.get(key)
        if type(values) is not list or len(values) != len(names):
            raise ValueError("artifact dimensions mismatch")
        if any(type(v) not in (int, float) or not math.isfinite(v) or (key == "scale" and v <= 0) for v in values):
            raise ValueError("invalid numeric artifact")
    if type(a.get("intercept")) not in (int, float) or not math.isfinite(a["intercept"]):
        raise ValueError("invalid intercept")
    if a.get("source_sha256") != source_hashes():
        raise ValueError("artifact extraction/training source mismatch")


def score(artifact, canonical_text):
    """Raw fitted probability only; never emits an ALLOW/BLOCK policy decision."""
    values = vector(canonical_text, artifact["feature_view"])
    encoded = {f"{k}={v}" if type(v) is str else k: 1.0 if type(v) is str else float(v)
               for k, v in values.items()}
    terms = [encoded.get(n, 0.0) / s * c for n, s, c in
             zip(artifact["feature_names"], artifact["scale"], artifact["coefficients"], strict=True)]
    z = math.fsum([artifact["intercept"], *terms])
    if not math.isfinite(z):
        raise ValueError("nonfinite model score")
    return 1 / (1 + math.exp(-z)) if z >= 0 else math.exp(z) / (1 + math.exp(z))


def save_artifact(artifact, path):
    check_artifact(artifact)
    raw = encode(artifact)
    with Path(path).open("xb") as f:
        f.write(raw)
    return digest(raw)


def load_artifact(path, *, expected_sha256):
    # No pickle/deserialization with executable content. Verify exactly the bytes parsed.
    raw = Path(path).read_bytes()
    if type(expected_sha256) is not str or digest(raw) != expected_sha256:
        raise ValueError("artifact hash mismatch")
    a = json.loads(raw)
    check_artifact(a)
    return a


def train_smoke(recipe=None):
    from .v5_fixture_integration import build_fixture, exchange
    recipe = candidate_recipe() if recipe is None else recipe
    validate_recipe(recipe, "SMOKE")
    with tempfile.TemporaryDirectory(prefix="model2-trainer-smoke-") as directory:
        build_fixture(directory)
        return _fit(exchange.load_examples(directory), recipe, "SMOKE")


def train_experimental(dataset, recipe, *, authorization, v5_recipe):
    validate_recipe(recipe, "EXPERIMENTAL")  # Refuse unratified recipe before data access.
    if not authorization:
        raise ValueError("dataset authorization required")
    from .v5_fixture_integration import exchange
    # Shared access/provenance gates run before row reads; no second dataset pipeline.
    reader_before = {name: digest((ROOT/name).read_bytes()) for name in READER_SOURCES}
    manifest, expected_manifest = exchange.D.load_manifest(str(dataset))
    if exchange._is_fixture_manifest(manifest):
        raise ValueError("EXPERIMENTAL refuses fixtures")
    examples = exchange.load_examples(str(dataset), authorization=str(authorization), recipe_path=str(v5_recipe))
    if any(r["manifest_sha256"] != expected_manifest for rows in examples.values() for r in rows):
        raise ValueError("dataset manifest changed during access")
    artifact, report = _fit(examples, recipe, "EXPERIMENTAL")
    if reader_before != {name: digest((ROOT/name).read_bytes()) for name in READER_SOURCES}:
        raise RuntimeError("shared reader source changed during consumption")
    artifact["reader_source_sha256"] = reader_before
    return artifact, report


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--mode", choices=("smoke", "experimental"), required=True)
    ap.add_argument("--output", type=Path, required=True, help="new JSON artifact; existing files are refused")
    ap.add_argument("--recipe", type=Path)
    ap.add_argument("--dataset", type=Path)
    ap.add_argument("--authorization", type=Path)
    ap.add_argument("--v5-recipe", type=Path)
    args = ap.parse_args()
    if args.output.exists():
        ap.error("output already exists")
    recipe = json.loads(args.recipe.read_bytes()) if args.recipe else candidate_recipe()
    if args.mode == "smoke":
        if args.dataset or args.authorization or args.v5_recipe:
            ap.error("SMOKE only accepts the built-in generated fixture")
        artifact, report = train_smoke(recipe)
    else:
        if not all((args.recipe, args.dataset, args.authorization, args.v5_recipe)):
            ap.error("EXPERIMENTAL requires recipe, dataset, authorization and v5-recipe")
        artifact, report = train_experimental(args.dataset, recipe, authorization=args.authorization,
                                              v5_recipe=args.v5_recipe)
    sha = save_artifact(artifact, args.output)
    load_artifact(args.output, expected_sha256=sha)
    print(json.dumps({**report, "artifact_sha256": sha, "artifact": str(args.output)}, indent=2))


if __name__ == "__main__":
    main()
