"""Isolate quantization and decoding on known legacy DEV case dev-00236.

This is a single-case mechanism check, never a quality or parity estimate.
"""
import argparse
import gc
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO / "control_plane"), str(REPO / "scripts" / "v5_successor")]
import v5_inference_core as core
from verified_suffix import candidates_for, classify_verified

GPU_STATUS = Path("/home/sebas/Documents/Codex/2026-10-26/ta/outputs/Coordinacion_modelos_arquitectura/GPU_STATUS.json")
INPUTS = Path("/home/sebas/Documents/Codex/2026-10-26/ta/work/metrics-2026-10-30/inputs.private.jsonl")
ADAPTER = REPO / "model-output-v5/experimental/v51-policy-20261101T210119Z/adapter"
RECIPE = REPO / "reports/v5/successor-training-2026-10-31-reviewed/recipe.EXPERIMENTAL.json"
NO_DQ = REPO / "reports/v5/successor-post-training-2026-11-01/profiles/nf4-native.EXPERIMENTAL.json"
CASE_HASH = "445f6d7d1dd6d690b19cc37a7f69a77eb47d37a354671bd78623950fb57da1f3"


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def case_text():
    matches = [json.loads(line) for line in INPUTS.read_text().splitlines()
               if line.strip() and json.loads(line).get("id") == "dev-00236"]
    if len(matches) != 1:
        raise ValueError("dev-00236 not unique")
    row = matches[0]
    if row["cohort"] != "legacy_dev" or row["canonical_outcome"] != "ACCEPT":
        raise ValueError("case provenance changed")
    text = row["canonical_text"]
    if hashlib.sha256(text.encode()).hexdigest() != CASE_HASH or row["canonical_sha256"] != CASE_HASH:
        raise ValueError("case bytes changed")
    return text


def claim_gpu():
    status = json.loads(GPU_STATUS.read_text())
    processes = subprocess.check_output(
        ["nvidia-smi", "--query-compute-apps=pid,process_name", "--format=csv,noheader"],
        text=True).splitlines()
    if status.get("owner") not in (None, "none") or status.get("state") != "AVAILABLE":
        raise RuntimeError("GPU is not available for Codex")
    if any(line.strip() and "/usr/bin/ptyxis" not in line for line in processes):
        raise RuntimeError("another GPU compute process is running")
    GPU_STATUS.write_text(json.dumps({"owner": "Codex", "state": "IN_USE_BY_CODEX",
                                      "pid": os.getpid(), "UTC": time.time(),
                                      "task": "dev-00236 precision/decoder diagnosis"}, indent=2) + "\n")


def release_gpu():
    status = json.loads(GPU_STATUS.read_text())
    if status.get("owner") == "Codex" and status.get("pid") == os.getpid():
        GPU_STATUS.write_text(json.dumps({"owner": None, "state": "AVAILABLE",
                                          "UTC": time.time(),
                                          "note": "dev-00236 diagnosis ended"}, indent=2) + "\n")


def measure(parsed, detail):
    raw = detail.pop("raw_text", "")
    return {"status": parsed.status, "decision": parsed.decision,
            "reason": parsed.reason, "invalid_reason": parsed.invalid_reason,
            "ended_with_eos": detail.get("ended_with_eos"),
            "generated_tokens": detail.get("generated_tokens"),
            "verified": detail.get("suffix_verified"), "fallback": detail.get("fallback"),
            "raw_output": raw, "raw_sha256": hashlib.sha256(raw.encode()).hexdigest()}


def run(output, repeats):
    if output.exists():
        raise FileExistsError(output)
    text = case_text()
    claim_gpu()
    try:
        def interrupted(signum, frame):
            raise KeyboardInterrupt("GPU diagnosis interrupted")
        signal.signal(signal.SIGTERM, interrupted)
        records = {"native_nf4_double_quant": [], "native_nf4_no_double_quant": [],
                   "verified_nf4_no_double_quant": []}
        loaded = []
        m = core.load_v5(str(ADAPTER), str(RECIPE))
        loaded.append({"configuration": "native_nf4_double_quant", "settings": m.runtime_settings})
        for _ in range(repeats):
            parsed, detail = core.classify_canonical(m, text)
            records["native_nf4_double_quant"].append(measure(parsed, detail))
        del m
        gc.collect()
        import torch
        torch.cuda.empty_cache()

        m = core.load_v5(str(ADAPTER), str(RECIPE), runtime_profile_path=str(NO_DQ),
                         runtime_profile_sha256=digest(NO_DQ), allow_experimental_runtime=True)
        loaded.append({"configuration": "nf4_no_double_quant", "settings": m.runtime_settings})
        candidates = candidates_for(m)
        for _ in range(repeats):
            parsed, detail = core.classify_canonical(m, text)
            records["native_nf4_no_double_quant"].append(measure(parsed, detail))
            parsed, detail = classify_verified(m, text, candidates)
            records["verified_nf4_no_double_quant"].append(measure(parsed, detail))
        del candidates, m
        gc.collect()
        torch.cuda.empty_cache()
        report = {
            "schema": "v51-dev236-mechanism-diagnostic/v1", "case_id": "dev-00236",
            "scope": "KNOWN_LEGACY_DEV_SINGLE_CASE_NOT_QUALITY_ESTIMATE",
            "canonical_sha256": CASE_HASH, "repeats_per_configuration": repeats,
            "adapter_sha256": "f101b2f1a8e849220adb0bd7948a4ab681579f0b3fac24629cdc1831c127c20c",
            "inputs": {"case_file_sha256": digest(INPUTS), "recipe_sha256": digest(RECIPE),
                       "no_dq_profile_sha256": digest(NO_DQ),
                       "script_sha256": digest(Path(__file__)),
                       "core_sha256": digest(REPO / "control_plane/v5_inference_core.py"),
                       "decoder_sha256": digest(REPO / "scripts/v5_successor/verified_suffix.py")},
            "loaded": loaded, "records": records,
            "candidate_selected": None,
            "warning": "One known case cannot establish runtime equivalence or security quality."
        }
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("x", encoding="utf-8") as handle:
            json.dump(report, handle, indent=2, ensure_ascii=False, sort_keys=True)
            handle.write("\n")
        return report
    finally:
        release_gpu()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repeats", type=int, default=3)
    args = parser.parse_args()
    if not 1 <= args.repeats <= 10:
        parser.error("repeats must be between 1 and 10")
    result = run(args.output, args.repeats)
    print(json.dumps({"output": str(args.output), "signatures": {
        key: [(r["status"], r["decision"], r["reason"], r["invalid_reason"], r["raw_sha256"])
              for r in rows] for key, rows in result["records"].items()}}, ensure_ascii=False))
