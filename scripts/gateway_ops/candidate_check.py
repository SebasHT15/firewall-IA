"""
Is a delivered candidate what its manifest says? Offline, and against a running V5 service if there is
one. It starts nothing, loads no model and does not touch the GPU, so it can run while the GPU belongs
to someone else.

    .venv-dataplane/bin/python scripts/gateway_ops/candidate_check.py --manifest <manifest.json> \
        [--gateway-config <gateway.yaml>] [--previous <manifest.json> ...] [--v5-url <url>] --out <file>

Exit 0 only when every check passed. `IDENTITY_CONSISTENT` says the files, the recipe and the service
describe one candidate. It says nothing about quality, latency or safety, and it approves nothing.
"""
import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path[:0] = [HERE, os.path.join(REPO, "data_plane"), os.path.join(REPO, "control_plane"), REPO]

import cascade_manifest as CM        # noqa: E402
import live_stack as L               # noqa: E402
import v5_inference_core as core     # noqa: E402


class Report:
    def __init__(self):
        self.checks = []

    def add(self, name, passed, **detail):
        self.checks.append({"check": name, "passed": bool(passed), **detail})

    @property
    def failed(self):
        return [c["check"] for c in self.checks if not c["passed"]]


def recipe_matches(report, manifest):
    """The recipe file is the source of the template, vocabulary and B. Tokenizer-measured values are
    the service's to report, so those are compared online."""
    v5 = manifest.v5
    try:
        contract = core.load_contract(v5.recipe_path)
    except (OSError, ValueError, KeyError) as exc:
        report.add("recipe readable as a V5 contract", False, error=type(exc).__name__)
        return
    report.add("recipe readable as a V5 contract", True)
    for name, ours, theirs in (("template fingerprint", v5.template_fingerprint, contract.template_fingerprint),
                               ("vocabulary", list(v5.vocabulary), list(contract.vocabulary)),
                               ("token budget B", v5.token_budget_B, contract.token_budget_B),
                               ("max_length", v5.token_contract.max_length, contract.max_length),
                               ("margin", v5.token_contract.margin, contract.margin),
                               ("base model", v5.base_model, contract.base_model),
                               ("base revision", v5.base_revision, contract.base_revision)):
        report.add(f"manifest {name} equals the recipe", ours == theirs)


def against_previous(report, manifest, paths):
    for path in paths:
        previous = CM.load_manifest(path)
        name = os.path.basename(path)
        report.add(f"another identifier than {name}", previous.manifest_id != manifest.manifest_id)
        report.add(f"new weights compared with {name}",
                   previous.v5.adapter_sha256 != manifest.v5.adapter_sha256)
        report.add(f"no runtime profile carried over from {name}",
                   manifest.v5.runtime_profile_sha256 is None
                   or manifest.v5.runtime_profile_sha256 != previous.v5.runtime_profile_sha256)


def against_service(report, manifest, url):
    url = url.rstrip("/")
    status, health = L.http_get(f"{url}/health")
    contract_status, contract = L.http_get(f"{url}/contract")
    report.add("V5 service answers", status == 200, status=status)
    if status != 200:
        return
    problems = CM.v5_contract_problems(manifest, json.loads(health),
                                       json.loads(contract) if contract_status == 200 else None)
    report.add("V5 service serves exactly this manifest", not problems, problems=list(problems))


def check(args):
    report = Report()
    try:
        manifest = CM.load_manifest(args.manifest)
    except CM.ManifestError as exc:
        report.add("manifest accepted", False, error=str(exc))
        return report, None
    report.add("manifest accepted", True)
    report.add("manifest is a v2 candidate", manifest.is_candidate, schema=manifest.schema)
    if not manifest.is_candidate:
        return report, manifest
    problems = CM.candidate_file_problems(manifest)
    report.add("adapter, recipe and decoder bytes match", not problems, problems=list(problems))
    recipe_matches(report, manifest)
    report.add("Model 2 and its policy are named", manifest.model2 is not None)
    if args.previous:
        against_previous(report, manifest, args.previous)
    if args.gateway_config:
        problems = CM.validate_consistency(CM.load_gateway_config(args.gateway_config), manifest)
        report.add("fits the gateway configuration", not problems, problems=list(problems))
    if args.v5_url:
        against_service(report, manifest, args.v5_url)
    return report, manifest


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--gateway-config")
    parser.add_argument("--previous", action="append", default=[])
    parser.add_argument("--v5-url")
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    report, manifest = check(args)
    runtime = manifest.v5.runtime if manifest else None
    document = {
        "schema": "firewall-candidate-check/v1", "utc": time.time(),
        "status": "REFUSED" if report.failed else "IDENTITY_CONSISTENT",
        "not_an_approval": "Identity only: says nothing about quality, latency or safety.",
        "manifest_id": manifest.manifest_id if manifest else None,
        "manifest_sha256": manifest.sha256 if manifest else None,
        "adapter_sha256": manifest.v5.adapter_sha256 if manifest else None,
        "runtime": {"profile_id": runtime.profile_id, "status": runtime.status, "decoder": runtime.decoder,
                    "profile_sha256": runtime.profile_sha256} if runtime else None,
        "service_compared": bool(args.v5_url), "checks": report.checks, "failed": report.failed}
    with open(args.out, "x", encoding="utf-8") as fh:
        json.dump(document, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(document["status"], "failed:", report.failed)
    return 1 if report.failed else 0


if __name__ == "__main__":
    sys.exit(main())
