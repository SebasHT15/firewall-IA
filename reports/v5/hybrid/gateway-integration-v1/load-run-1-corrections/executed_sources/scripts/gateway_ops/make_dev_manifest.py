"""
Write a `firewall-cascade-model-manifest/v1` for the CURRENT development artifacts.

    .venv-dataplane/bin/python scripts/gateway_ops/make_dev_manifest.py --out <manifest.json>

A real fixture for development, marked EXPERIMENTAL. It reads the recipe and hashes files, without
loading a model or touching the GPU. Its Model 2 policy is the lab policy: the 0.9 threshold is
LAB_EXPERIMENTAL, not an approved operating point. A successor candidate brings its own manifest;
this script is not how one is produced.
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path[:0] = [os.path.join(REPO, "data_plane"), os.path.join(REPO, "control_plane"), REPO]

import cascade_manifest as CM   # noqa: E402
import model2_policy as mp      # noqa: E402
import v5_inference_core as core  # noqa: E402

ADAPTER_DIR = "model-output-v5/final/v5-final-v4-20261027T022649Z/adapter"
MODEL2_DIR = "model-output-model2/final/v4-d82-20261027T052308Z"
POLICIES = "reports/v5/hybrid/cascade-lab/policies"
CANDIDATES = {"baseline34": ("baseline34.json", "model2_lab_baseline34.json"),
              "path-ablation32": ("path-ablation32.json", "model2_lab_path-ablation32.json")}
MAX_BYTES_PER_TOKEN = 48       # data-plane reverse bound, canonical spec §5.5


def build(candidate: str, runtime_profile=None) -> dict:
    contract = core.load_contract()
    artifact, policy_file = CANDIDATES[candidate]
    artifact_path = os.path.join(MODEL2_DIR, artifact)
    policy_path = os.path.join(POLICIES, policy_file)
    policy = mp.load_policy(os.path.join(REPO, policy_path))
    budget = contract.token_budget_B
    document = {
        "schema": CM.MANIFEST_SCHEMA,
        "manifest_id": f"dev-fixture-v5-final-v4-{candidate}",
        "status": "EXPERIMENTAL",
        "note": "Development fixture of the current artifacts. Model 2 threshold is LAB_EXPERIMENTAL.",
        "canonical": {"contract": "canonical-request/v1",
                      "max_decoded_body": MAX_BYTES_PER_TOKEN * budget,
                      "token_budget_B": budget, "max_bytes_per_token": MAX_BYTES_PER_TOKEN},
        "v5": {"adapter_sha256": core.adapter_fingerprint(os.path.join(REPO, ADAPTER_DIR)),
               "recipe_sha256": contract.recipe_sha256,
               "template_fingerprint": contract.template_fingerprint,
               "vocabulary": list(contract.vocabulary), "token_budget_B": budget},
        "model2": {"artifact_path": artifact_path,
                   "artifact_sha256": CM.sha256_file(os.path.join(REPO, artifact_path)),
                   "feature_view": policy.feature_view, "policy_path": policy_path,
                   "policy_sha256": policy.sha256},
    }
    if runtime_profile:
        document["manifest_id"] += "-" + os.path.basename(runtime_profile).split(".")[0]
        document["v5"]["runtime_profile_sha256"] = CM.sha256_file(runtime_profile)
    return document


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--candidate", choices=tuple(CANDIDATES), default="baseline34")
    parser.add_argument("--runtime-profile", help="an experimental V5 profile file to bind to")
    args = parser.parse_args()
    document = build(args.candidate, args.runtime_profile)
    CM.parse_manifest(document)            # never write a manifest the gateway would refuse
    with open(args.out, "x", encoding="utf-8") as fh:
        json.dump(document, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(args.out)


if __name__ == "__main__":
    main()
