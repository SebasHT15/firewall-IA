"""
Run the affected test modules and record what this integration changed and did not change.

    .venv-dataplane/bin/python scripts/gateway_ops/collect_evidence.py --out reports/v5/hybrid/gateway-integration-v1

Writes `unit_tests.json` and `code_manifest.json`. Refuses to overwrite either: a new run is a new
directory. CPU only, no model service.
"""
import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
DATA_PLANE = os.path.join(REPO, ".venv-dataplane", "bin", "python")
ANALYZER = os.path.join(REPO, ".venv-analyzer", "bin", "python")
CONTRACT = ("/home/sebas/Documents/Codex/2026-10-26/ta/outputs/Coordinacion_modelos_arquitectura/"
            "CONTRATO_DE_TRABAJO.json")
EXPERIMENTS = os.path.join(REPO, "reports/v5/hybrid/experiments-2026-10-30")

SERVED = ("control_plane/classifier_api.py", "control_plane/inference_core.py",
          "control_plane/v5_classifier_api.py", "control_plane/v5_inference_core.py",
          "control_plane/v5_output_contract.py", "control_plane/v5_runtime_profile.py",
          "control_plane/v5_tokenization.py", "scripts/v5_successor/verified_suffix.py",
          "reports/v5/successor-2026-10-30/verified-suffix/service-final/verified-suffix.EXPERIMENTAL.json",
          "reports/v5/successor-2026-10-30/verified-suffix/service-final/cascade-manifest.EXPERIMENTAL.json",
          "model-output-v5/final/v5-final-v4-20261027T022649Z/adapter/adapter_model.safetensors",
          "model-output-model2/final/v4-d82-20261027T052308Z/baseline34.json",
          "reports/v5/hybrid/cascade-lab/policies/model2_lab_baseline34.json",
          "reports/v5/hybrid/cascade-lab/policies/fast_path_lab_app.json",
          "reports/v5/successor-2026-10-30/runtime/profiles/nf4.EXPERIMENTAL.json",
          "reports/v5/hybrid/gateway-integration-v1/manifests/dev_fixture_baseline34.json",
          "reports/v5/hybrid/gateway-integration-v1/manifests/dev_fixture_baseline34_nf4_profile.json")
NEW_MODULES = ("test_cascade_manifest.py", "test_cascade_ops.py", "test_gateway_framing.py",
               "test_cascade_workers.py", "test_data_plane_cascade.py", "test_load_lib.py")
REGRESSION_DATA_PLANE = (
    "test_data_plane.py", "test_data_plane_fast_path.py", "test_data_plane_canonical_observer.py",
    "test_data_plane_framing_observer.py", "test_data_plane_shadow_integration.py",
    "test_data_plane_shadow_analyzer.py", "test_canonical_observer.py", "test_canonical_adapter.py",
    "test_framing_evidence.py", "test_fast_path.py")
REGRESSION_ANALYZER = ("test_cascade_router.py", "test_cascade_lab.py", "test_cascade_metrics.py",
                       "test_cascade_experiment_metrics.py", "test_http1_wire.py",
                       "test_model2_policy.py")
NEW_FILES = (
    "config.cascade.example.yaml", "docs/cascade_gateway.md",
    "data_plane/cascade_addon.py", "data_plane/cascade_canonical.py",
    "data_plane/cascade_canonical_worker.py", "data_plane/cascade_gateway.py",
    "data_plane/cascade_manifest.py", "data_plane/cascade_ops.py", "data_plane/fast_path_audit.py",
    "data_plane/gateway_framing.py", "data_plane/model2_client.py", "data_plane/model2_worker.py",
    "scripts/gateway_ops/__init__.py", "scripts/gateway_ops/collect_evidence.py",
    "scripts/gateway_ops/fixtures/after_hook_mutation_addon.py",
    "scripts/gateway_ops/fixtures/guard_fault_addon.py",
    "scripts/gateway_ops/load_analyze.py", "scripts/gateway_ops/load_check.py",
    "scripts/gateway_ops/load_lib.py", "scripts/gateway_ops/run_load.sh",
    "scripts/gateway_ops/independent_sink.py", "scripts/gateway_ops/launch.py",
    "scripts/gateway_ops/live_check.py", "scripts/gateway_ops/live_stack.py",
    "scripts/gateway_ops/make_dev_manifest.py", "scripts/gateway_ops/real_check.py",
    "scripts/gateway_ops/real_perf.py", "scripts/gateway_ops/run_real.sh",
    "scripts/gateway_ops/service_doubles.py",
    "tests/test_cascade_manifest.py", "tests/test_cascade_ops.py", "tests/test_cascade_workers.py",
    "tests/test_data_plane_cascade.py", "tests/test_gateway_framing.py", "tests/test_load_lib.py")


def digest(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def run_module(python, module):
    started = time.time()
    proc = subprocess.run([python, "-B", "-m", "unittest", "discover", "-s", "tests", "-p", module],
                          cwd=REPO, capture_output=True, text=True, timeout=300)
    tail = proc.stderr.strip().splitlines()[-3:]
    ran = re.search(r"Ran (\d+) test", proc.stderr)
    skipped = re.search(r"skipped=(\d+)", tail[-1] if tail else "")
    return {"module": module, "python": os.path.relpath(python, REPO), "tests": int(ran.group(1)) if ran else 0,
            "skipped": int(skipped.group(1)) if skipped else 0, "ok": proc.returncode == 0,
            "seconds": round(time.time() - started, 2)}


def code_manifest():
    with open(CONTRACT, encoding="utf-8") as fh:
        immutable = json.load(fh)["immutable_model2_bound_sources"]
    with open(os.path.join(EXPERIMENTS, "measurement_source_hashes.json"), encoding="utf-8") as fh:
        measured = json.load(fh)["files"]
    skipped = ("/experiments/analyze.py", "/experiments/figures.py", "/experiments/report.py")
    changed_measured = [path for path, record in measured.items()
                        if not path.endswith(skipped)
                        and digest(os.path.join(REPO, path)) != record["sha256"]]
    return {
        "schema": "firewall-gateway-code-manifest/v1", "utc": time.time(),
        "git_head": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=REPO, text=True).strip(),
        "git_branch": subprocess.check_output(["git", "rev-parse", "--abbrev-ref", "HEAD"], cwd=REPO,
                                              text=True).strip(),
        "git_staged_nothing": subprocess.run(["git", "diff", "--cached", "--quiet"],
                                             cwd=REPO).returncode == 0,
        "new_files": {path: digest(os.path.join(REPO, path)) for path in NEW_FILES},
        "served_sources_and_artifacts": {path: digest(os.path.join(REPO, path)) for path in SERVED},
        "immutable_sources_checked": len(immutable),
        "immutable_sources_changed": [p for p, h in immutable.items()
                                      if digest(os.path.join(REPO, p)) != h],
        "measurement_sources_checked": len(measured),
        "measurement_sources_changed": changed_measured,
        "measurement_sources_changed_note": "control_plane/v5_* belong to the parallel model work.",
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    os.makedirs(args.out, exist_ok=True)
    groups = {
        "new": [run_module(DATA_PLANE, m) for m in NEW_MODULES],
        "regression_data_plane": [run_module(DATA_PLANE, m) for m in REGRESSION_DATA_PLANE],
        "regression_analyzer": [run_module(ANALYZER, m) for m in REGRESSION_ANALYZER],
    }
    rows = [row for group in groups.values() for row in group]
    results = {"schema": "firewall-gateway-unit-tests/v1", "groups": groups,
               "tests": sum(r["tests"] for r in rows), "skipped": sum(r["skipped"] for r in rows),
               "modules_failed": [r["module"] for r in rows if not r["ok"]],
               "scope": "doubles for V4 and V5; real Model 2 artifact on CPU in test_cascade_workers"}
    for name, payload in (("unit_tests.json", results), ("code_manifest.json", code_manifest())):
        with open(os.path.join(args.out, name), "x", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
            fh.write("\n")
    print(json.dumps({k: results[k] for k in ("tests", "skipped", "modules_failed")}))
    return 1 if results["modules_failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
