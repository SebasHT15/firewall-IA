"""Paired real V5.1 gateway classification on the sealed 434-case authored DEV."""
import argparse
from collections import Counter
import json
from pathlib import Path
import secrets
import subprocess
import time

from .real_guard_probe import ROOT, STATUS, command, digest, gpu_busy

INPUTS = Path("/home/sebas/Documents/Codex/2026-10-26/ta/work/metrics-2026-10-30/inputs.private.jsonl")
MANIFESTS = {
    "defer_only": ROOT / "reports/v5/model2-defer-only-2026-11-05/manifest.EXPERIMENTAL.json",
    "guarded": ROOT / "reports/v5/model2-guarded-2026-11-05/manifest.EXPERIMENTAL.json",
}


def readlines(path):
    return [json.loads(s) for s in path.read_text().splitlines() if s.strip()]


def run(out, work):
    if out.exists() or work.exists():
        raise FileExistsError("new output and private work directories required")
    before = json.loads(STATUS.read_text())
    if before.get("state") != "AVAILABLE" or before.get("owner") not in (None, "none") or gpu_busy():
        raise RuntimeError("GPU not free for owner-authorized V5.1 census")
    out.mkdir(parents=True)
    work.mkdir(parents=True)
    (out / "GPU_STATUS.before.json").write_text(json.dumps(before, indent=2) + "\n")
    nonce = secrets.token_hex(12)
    STATUS.write_text(json.dumps({"owner": None, "state": "AVAILABLE_FOR_CLAUDE", "handoff_id": nonce,
                                  "UTC": time.time(), "note": "Sebas authorized temporary real V5.1 test; "
                                                            "Codex runs Claude gateway stack, 2026-11-05"}, indent=2) + "\n")
    try:
        arms = {}
        for name, manifest in MANIFESTS.items():
            arm_out, arm_work = out / name, work / name
            log = out / f"{name}.stdout.txt"
            with log.open("x") as handle:
                proc = subprocess.run(command("scripts/gateway_ops/candidate_walkthrough.py",
                                              "--manifest", manifest, "--out", arm_out, "--work", arm_work,
                                              "--inputs", INPUTS, "--group", "classification"),
                                      cwd=ROOT, stdout=handle, stderr=subprocess.STDOUT, timeout=1200)
            if proc.returncode != 0:
                raise RuntimeError(f"{name} candidate walkthrough failed; see {log}")
            walkthrough = json.loads((arm_out / "walkthrough.json").read_text())
            if (walkthrough["layers"]["classification"]["status"] != "MEASURED_ON_DEV"
                    or walkthrough["v5"] != "real"):
                raise RuntimeError(f"{name} real classification incomplete")
            rows = readlines(arm_out / "classification_rows.jsonl")
            if len(rows) != 434:
                raise RuntimeError(f"{name} case count {len(rows)} != 434")
            arms[name] = {"rows": rows, "manifest_sha256": digest(manifest),
                          "walkthrough_sha256": digest(arm_out / "walkthrough.json"),
                          "rows_sha256": digest(arm_out / "classification_rows.jsonl"),
                          "log_sha256": digest(log),
                          "classification": walkthrough["layers"]["classification"]["summary"]}
        a = {r["case"]: r for r in arms["defer_only"]["rows"]}
        b = {r["case"]: r for r in arms["guarded"]["rows"]}
        if a.keys() != b.keys():
            raise RuntimeError("paired case identities differ")
        changes = Counter()
        for cid in a:
            old, new = a[cid], b[cid]
            if old["reference"] != new["reference"]:
                raise RuntimeError("reference changed between arms")
            if new["deciding_stage"] == "model2":
                changes["early_model2"] += 1
                changes["early_" + new["reference"]] += 1
            if old["reference"] == "ALLOW" and new["L1_decision"] == "BLOCK" and old["L1_decision"] != "BLOCK":
                changes["added_fp"] += 1
            if old["reference"] == "BLOCK" and new["L1_decision"] == "BLOCK" and old["L1_decision"] != "BLOCK":
                changes["rescued_attack"] += 1
            if old["reference"] == "BLOCK" and new["L1_decision"] != "BLOCK" and old["L1_decision"] == "BLOCK":
                changes["new_fn"] += 1
        report = {"schema": "model2-guarded-real-v51-paired-dev/v1",
                  "scope": "KNOWN_AUTHORED_DEV_NOT_INDEPENDENT", "status": "COMPLETE",
                  "cases": len(a), "changes": dict(changes),
                  "arms": {k: {field: value for field, value in v.items() if field != "rows"}
                           for k, v in arms.items()},
                  "inputs_sha256": digest(INPUTS), "source_sha256": digest(Path(__file__)),
                  "protected_opened": False, "candidate_selected": None}
        (out / "PAIRED.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
        return report
    finally:
        current = json.loads(STATUS.read_text())
        if current.get("handoff_id") == nonce:
            STATUS.write_text(json.dumps({"owner": None, "state": "AVAILABLE", "UTC": time.time(),
                                          "note": "Owner-authorized real V5.1 paired DEV ended; GPU released"}, indent=2) + "\n")
        (out / "GPU_STATUS.after.json").write_text(STATUS.read_text())


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(run(args.out.resolve(), args.work.resolve()), indent=2))
