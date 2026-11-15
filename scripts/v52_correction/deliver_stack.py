"""Bind a completed V5.2 run and experimental Model 2 to local-stack files.

This writes an experimental manifest, an offline identity check, and pinned
V5_ONLY/CASCADE_ACTIVE configurations. It does not select or approve a policy,
start services, read protected data, or change the GPU hand-off.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from . import train_candidate as T

ROOT = Path(__file__).resolve().parents[2]
PYTHON = ROOT / ".venv-dataplane/bin/python"


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def execute(*args):
    subprocess.run([str(PYTHON), "-B", *map(str, args)], cwd=ROOT, check=True)


def run(package_path, auth_path, record_path, model2_artifact, model2_policy, base_config, out):
    if out.exists():
        raise FileExistsError(out)
    package_path, auth_path, record_path = map(Path, (package_path, auth_path, record_path))
    preview = json.loads(package_path.read_text())
    T.require_owner(preview, package_path, auth_path)
    package, recipe, _, _ = T.load(package_path)
    T.require_owner(package, package_path, auth_path)
    record = json.loads(record_path.read_text())
    if (record.get("schema") != "v52-experimental-run/v1" or record.get("outcome") != "TRAINED"
            or record.get("scope") != "EXPERIMENTAL_V52_NOT_FINAL"
            or record.get("package_sha256") != sha(package_path)
            or record.get("protected_opened") is not False):
        raise ValueError("V5.2 run is not a completed matching experimental run")
    adapter = ROOT / record["adapter"]["path"]
    weights = adapter / "adapter_model.safetensors"
    if sha(weights) != record["adapter"]["files"]["adapter_model.safetensors"]["sha256"]:
        raise ValueError("adapter weights differ from training record")
    recipe_path = Path(package["recipe"]["path"])
    if sha(recipe_path) != record["recipe_sha256"]:
        raise ValueError("recipe differs from training record")
    from scripts.model2 import training as model2
    if str(ROOT / "data_plane") not in sys.path:
        sys.path.insert(0, str(ROOT / "data_plane"))
    import model2_policy as policy
    artifact = model2.load_artifact(model2_artifact, expected_sha256=sha(model2_artifact))
    decision = policy.load_policy(model2_policy)
    if not decision.binds(feature_view=artifact["feature_view"], artifact_sha256=sha(model2_artifact)):
        raise ValueError("Model 2 policy is not bound to this artifact")
    out.mkdir(parents=True)
    tokens = out / "token-measurement.json"
    tokens.write_text(json.dumps({"schema": "v52-token-measurement/v1",
                                  "package_sha256": sha(package_path),
                                  "run_record_sha256": sha(record_path),
                                  "measured": record["token_contract"],
                                  "protected_opened": False}, indent=2, sort_keys=True) + "\n")
    manifest = out / "candidate.EXPERIMENTAL.json"
    execute("scripts/gateway_ops/make_candidate_manifest.py", "--out", manifest,
            "--manifest-id", "v52-short-route-cascade-20261105",
            "--adapter-dir", adapter, "--recipe", recipe_path,
            "--token-measurement", tokens, "--model2-artifact", model2_artifact,
            "--model2-policy", model2_policy, "--native-runtime")
    check = out / "candidate.CHECK.json"
    execute("scripts/gateway_ops/candidate_check.py", "--manifest", manifest, "--out", check)
    checked = json.loads(check.read_text())
    if checked.get("status") != "IDENTITY_CONSISTENT" or checked.get("failed"):
        raise ValueError("candidate identity check failed")
    configs = {}
    for mode, name in (("V5_ONLY", "v52-v5only.stack.json"),
                       ("CASCADE_ACTIVE", "v52-cascade.stack.json")):
        path = out / name
        execute("scripts/local_stack/stack.py", "pin", "--config", base_config,
                "--manifest", manifest, "--mode", mode, "--out", path)
        configs[mode] = {"path": str(path), "sha256": sha(path)}
    delivery = {"schema": "v52-local-stack-delivery/v1", "status": "EXPERIMENTAL_IDENTITY_ONLY",
                "package_sha256": sha(package_path), "owner_admission_sha256": sha(auth_path),
                "run_record_sha256": sha(record_path), "v5_adapter_sha256": sha(weights),
                "model2_artifact_sha256": sha(model2_artifact),
                "model2_policy_sha256": decision.sha256,
                "manifest_sha256": sha(manifest), "check_sha256": sha(check),
                "configs": configs, "runtime": "native", "protected_opened": False,
                "candidate_selected": None, "gpu_handoff_changed": False}
    (out / "DELIVERY.json").write_text(json.dumps(delivery, indent=2, sort_keys=True) + "\n")
    return delivery


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--authorization", type=Path, required=True)
    parser.add_argument("--run-record", type=Path, required=True)
    parser.add_argument("--model2-artifact", type=Path, required=True)
    parser.add_argument("--model2-policy", type=Path, required=True)
    parser.add_argument("--base-config", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(run(*(p.resolve() for p in (args.package, args.authorization, args.run_record,
                                                args.model2_artifact, args.model2_policy,
                                                args.base_config, args.out))), indent=2))
