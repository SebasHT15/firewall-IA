"""
Write a `firewall-cascade-model-manifest/v2` for a delivered model candidate.

    .venv-dataplane/bin/python scripts/gateway_ops/make_candidate_manifest.py --out <manifest.json> \
        --manifest-id <id> --adapter-dir <dir> --recipe <recipe.json> --token-measurement <json> \
        --model2-artifact <artifact.json> --model2-policy <policy.json> \
        (--native-runtime | --runtime-profile <profile.json> [--verification-evidence <evidence.json>])

No model is loaded and the GPU is not touched. Identity comes from the files of THIS candidate: the
recipe gives the template, vocabulary and B, the adapter gives its digest, and the token measurement
gives what only the tokenizer knows. A value of an earlier candidate is never a default.

THE RUNTIME IS A DECISION. There is no default: either `--native-runtime`, or a profile that binds this
adapter and this recipe. A profile written for earlier weights is refused, so a fast profile has to be
produced and verified again on the new weights before a manifest can name it. A profile with a verified
decoder also needs the evidence of that verification.

The manifest is EXPERIMENTAL. This tool cannot write anything else, and writing one approves nothing.
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path[:0] = [HERE, os.path.join(REPO, "data_plane"), os.path.join(REPO, "control_plane"), REPO]

import cascade_manifest as CM        # noqa: E402
import make_dev_manifest as dev      # noqa: E402
import model2_policy as mp           # noqa: E402
import v5_inference_core as core     # noqa: E402


def relative(path):
    """Inside the repository a path stays relative, so the manifest survives a move of the checkout."""
    absolute = os.path.abspath(path)
    inside = absolute.startswith(REPO + os.sep)
    return os.path.relpath(absolute, REPO) if inside else absolute


def measured_tokens(path):
    with open(path, encoding="utf-8") as fh:
        document = json.load(fh)
    measured = document.get("measured")
    if not isinstance(measured, dict):
        raise CM.ManifestError("the token measurement has no `measured` section")
    missing = [k for k in ("max_length", "margin", "overhead", "label_budget", "B") if k not in measured]
    if missing:
        raise CM.ManifestError(f"the token measurement lacks {missing}")
    return measured


def runtime_section(profile, evidence):
    if profile is None:
        return None
    return {"profile_path": relative(profile), "profile_sha256": CM.sha256_file(profile),
            "verification_evidence_path": relative(evidence) if evidence else None,
            "verification_evidence_sha256": CM.sha256_file(evidence) if evidence else None}


def build(args) -> dict:
    contract = core.load_contract(args.recipe)
    measured = measured_tokens(args.token_measurement)
    if measured["B"] != contract.token_budget_B:
        raise CM.ManifestError("the token measurement is of another B than the recipe")
    policy = mp.load_policy(args.model2_policy)
    budget = contract.token_budget_B
    return {
        "schema": CM.CANDIDATE_SCHEMA, "manifest_id": args.manifest_id, "status": "EXPERIMENTAL",
        "note": "Delivered candidate. Experimental: not approved for any deployment.",
        "canonical": {"contract": "canonical-request/v1",
                      "max_decoded_body": args.max_bytes_per_token * budget, "token_budget_B": budget,
                      "max_bytes_per_token": args.max_bytes_per_token},
        "v5": {"adapter_path": relative(args.adapter_dir),
               "adapter_sha256": core.adapter_fingerprint(args.adapter_dir),
               "recipe_path": relative(args.recipe), "recipe_sha256": contract.recipe_sha256,
               "template_fingerprint": contract.template_fingerprint,
               "base_model": contract.base_model, "base_revision": contract.base_revision,
               "vocabulary": list(contract.vocabulary), "token_budget_B": budget,
               "max_length": measured["max_length"], "margin": measured["margin"],
               "overhead": measured["overhead"], "label_budget": measured["label_budget"],
               "max_new_tokens": measured["label_budget"] + 4,
               "runtime": runtime_section(args.runtime_profile, args.verification_evidence)},
        "model2": {"artifact_path": relative(args.model2_artifact),
                   "artifact_sha256": CM.sha256_file(args.model2_artifact),
                   "feature_view": policy.feature_view, "policy_path": relative(args.model2_policy),
                   "policy_sha256": policy.sha256}}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--manifest-id", required=True)
    parser.add_argument("--adapter-dir", required=True)
    parser.add_argument("--recipe", required=True)
    parser.add_argument("--token-measurement", required=True)
    parser.add_argument("--model2-artifact", required=True)
    parser.add_argument("--model2-policy", required=True)
    parser.add_argument("--max-bytes-per-token", type=int, default=dev.MAX_BYTES_PER_TOKEN)
    runtime = parser.add_mutually_exclusive_group(required=True)
    runtime.add_argument("--native-runtime", action="store_true", help="the recipe's own runtime")
    runtime.add_argument("--runtime-profile", help="a profile bound to this adapter and recipe")
    parser.add_argument("--verification-evidence", help="required for a verified decoder")
    args = parser.parse_args(argv)
    try:
        document = build(args)
        manifest = CM.parse_manifest(document)         # never write what the gateway would refuse
        problems = CM.candidate_file_problems(manifest)
    except (CM.ManifestError, OSError, ValueError) as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2
    if problems:
        print(f"REFUSED: {','.join(problems)}", file=sys.stderr)
        return 2
    with open(args.out, "x", encoding="utf-8") as fh:
        json.dump(document, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
