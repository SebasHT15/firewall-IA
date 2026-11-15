"""Review, gate or train one owner-admitted V5.2 experimental correction.

The old V5.1 TRAIN/VALIDATION are read through their existing gated package;
only the bound V5.2 delta is appended. No protected role is opened. Training
requires a separate committed owner admission for this exact manifest.
"""
import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


REPO = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(REPO / "scripts" / "v5_successor"),
                str(REPO / "scripts" / "training"), str(REPO / "scripts" / "dataset")]
import successor_contract as parent_contract
import v5_train_data as data
import finetune_v5 as fit

GPU_STATUS = Path("/home/sebas/Documents/Codex/2026-10-26/ta/outputs/Coordinacion_modelos_arquitectura/GPU_STATUS.json")
PACKAGE_SCHEMA = "v52-experimental-training-package/v1"
AUTH_SCHEMA = "v52-experimental-training-admission/v1"


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def capture(desc):
    path = Path(desc["path"])
    data.C.assert_not_protected(str(path))
    raw = path.read_bytes()
    if sha(raw) != desc["sha256"] or ("bytes" in desc and len(raw) != desc["bytes"]):
        raise ValueError("bound file changed: " + str(path))
    return raw


def parse_jsonl(raw):
    return [json.loads(line) for line in raw.splitlines() if line.strip()]


def load(package_path):
    package_path = package_path.resolve()
    package = json.loads(package_path.read_text())
    if package.get("schema") != PACKAGE_SCHEMA or package.get("status") != "PROPOSED":
        raise ValueError("wrong V5.2 package")
    if package.get("training_authorized") is not False:
        raise ValueError("package cannot self-authorize training")
    for name, digest in package["source_sha256"].items():
        if sha((REPO / name).read_bytes()) != digest:
            raise ValueError("bound code changed: " + name)
    capture(package["recipe"])
    recipe, recipe_sha = data.load_recipe(package["recipe"]["path"])
    if recipe_sha != package["recipe"]["sha256"] or recipe["recipe_id"] != "v52-app-correction-experimental-20261104":
        raise ValueError("recipe identity mismatch")
    protocol = json.loads(capture(package["protocol"]))
    if (protocol.get("schema") != "v52-correction-training-protocol/v1"
            or protocol.get("scope") != "EXPERIMENTAL_V52_ONLY"
            or protocol.get("protected_sets") != "CLOSED"):
        raise ValueError("protocol mismatch")
    delta_manifest = json.loads(capture(package["delta_manifest"]))
    audit = json.loads(capture(package["cpu_audit"]))
    if (audit.get("manifest_sha256") != package["delta_manifest"]["sha256"]
            or audit.get("protected_opened") is not False
            or delta_manifest.get("training_authorized") is not False):
        raise ValueError("delta/audit binding mismatch")
    parent_path = Path(package["parent_manifest"]["path"])
    if sha(parent_path.read_bytes()) != package["parent_manifest"]["sha256"]:
        raise ValueError("V5.1 parent package changed")
    _, parent_sha, old, _, _ = parent_contract.prepare(parent_path, training=False)
    if parent_sha != package["parent_manifest"]["sha256"]:
        raise ValueError("V5.1 parent revalidation mismatch")
    if {split: len(old[split]) for split in ("TRAIN", "VALIDATION")} != {"TRAIN": 5166, "VALIDATION": 2080}:
        raise ValueError("V5.1 parent row count changed")
    rows = {split: list(old[split]) for split in ("TRAIN", "VALIDATION")}
    new_hashes = {}
    for split in ("TRAIN", "VALIDATION"):
        bound = delta_manifest["delta_artifacts"][split]
        raw = capture(bound)
        new = parse_jsonl(raw)
        if len(new) != bound["rows"] or len(new) != audit["splits"][split]["rows"]:
            raise ValueError("delta count mismatch")
        for index, row in enumerate(new):
            if (row["split"] != split or row["label_status"] != "POLICY_DEFINED"
                    or row["text_sha256"] != sha(row["text"].encode())
                    or row["label"] not in ("ALLOW", "BLOCK")
                    or row["output"].split(" ", 1)[0] != row["label"]):
                raise ValueError("delta row mismatch")
            rows[split].append({"split": split, "index": len(old[split]) + index,
                                "text": row["text"], "output": row["output"],
                                "meta": {"text_sha256": row["text_sha256"],
                                         "label": row["label"],
                                         "label_status": row["label_status"]}})
        new_hashes[split] = {r["text_sha256"] for r in new}
        if len(new_hashes[split]) != len(new):
            raise ValueError("duplicate delta text")
    if new_hashes["TRAIN"] & new_hashes["VALIDATION"]:
        raise ValueError("delta split overlap")
    if delta_manifest["summary"] != package["delta_summary"]:
        raise ValueError("delta summary changed")
    return package, recipe, protocol, rows


def committed(path):
    path = Path(path).resolve()
    if not path.is_relative_to(REPO):
        return False
    return data.git_committed_unmodified(str(path))


def require_owner(package, package_path, authorization):
    if authorization is None or not committed(authorization):
        raise ValueError("committed owner admission required")
    auth = json.loads(Path(authorization).read_text())
    if (auth.get("schema") != AUTH_SCHEMA or auth.get("status") != "APPROVED_EXPERIMENTAL"
            or auth.get("scope") != "EXPERIMENTAL_V52_ONLY"
            or auth.get("training_allowed") is not True):
        raise ValueError("owner admission not approved for V5.2")
    for field in ("owner_decision", "authorized_by", "date"):
        if not isinstance(auth.get(field), str) or not auth[field].strip():
            raise ValueError("owner admission incomplete: " + field)
    expected = {"package_sha256": sha(Path(package_path).read_bytes()),
                "recipe_sha256": package["recipe"]["sha256"],
                "protocol_sha256": package["protocol"]["sha256"],
                "delta_manifest_sha256": package["delta_manifest"]["sha256"]}
    if any(auth.get(key) != value for key, value in expected.items()):
        raise ValueError("owner admission hash mismatch")
    required = [package_path, package["recipe"]["path"], package["protocol"]["path"],
                package["delta_manifest"]["path"], package["cpu_audit"]["path"],
                package["parent_manifest"]["path"]]
    required += [str(REPO / name) for name in package["source_sha256"]]
    if any(not committed(path) for path in required):
        raise ValueError("bound code and records must be committed and unchanged")
    return auth


def claim_gpu():
    state = json.loads(GPU_STATUS.read_text())
    lines = subprocess.check_output(["nvidia-smi", "--query-compute-apps=pid,process_name",
                                     "--format=csv,noheader"], text=True).splitlines()
    if state.get("state") != "AVAILABLE" or state.get("owner") not in (None, "none"):
        raise ValueError("GPU has another owner")
    if any(line.strip() and "/usr/bin/ptyxis" not in line for line in lines):
        raise ValueError("another GPU compute process is running")
    GPU_STATUS.write_text(json.dumps({"owner": "Codex", "state": "IN_USE_BY_CODEX",
                                      "pid": os.getpid(), "UTC": time.time(),
                                      "task": "V5.2 owner-admitted experimental training"}, indent=2) + "\n")


def release_gpu():
    state = json.loads(GPU_STATUS.read_text())
    if state.get("owner") == "Codex" and state.get("pid") == os.getpid():
        GPU_STATUS.write_text(json.dumps({"owner": None, "state": "AVAILABLE", "UTC": time.time(),
                                          "note": "V5.2 training ended; inspect run record"}, indent=2) + "\n")


def run(args):
    if args.report_dir.exists():
        raise FileExistsError(args.report_dir)
    if args.mode in ("gate", "train"):
        # Admission and committed-code gates precede private row access.
        preview = json.loads(args.package.read_text())
        require_owner(preview, args.package, args.authorization)
    package, recipe, protocol, rows = load(args.package)
    if args.mode in ("gate", "train"):
        require_owner(package, args.package, args.authorization)
    from transformers import AutoTokenizer
    base = recipe["base_model"]
    tok = AutoTokenizer.from_pretrained(base["name"], revision=base["revision"],
                                        local_files_only=True)
    contract, diags = data.measure_contract(tok, recipe)
    if diags:
        raise ValueError("token contract failed: " + ",".join(d.code for d in diags))
    examples = {}
    for split in ("TRAIN", "VALIDATION"):
        examples[split], diags = data.build_examples(tok, recipe, contract, rows[split])
        if diags:
            raise ValueError("example build failed: " + ",".join(d.code for d in diags[:10]))
    record = {"schema": "v52-experimental-run/v1", "mode": args.mode,
              "scope": "EXPERIMENTAL_V52_NOT_FINAL", "package_sha256": sha(args.package.read_bytes()),
              "recipe_sha256": package["recipe"]["sha256"],
              "rows": {split: len(rows[split]) for split in rows},
              "labels": {split: dict(Counter(r["meta"]["label"] for r in rows[split])) for split in rows},
              "examples": {split: len(examples[split]) for split in examples},
              "max_sequence_tokens": max(len(e["input_ids"]) for ss in examples.values() for e in ss),
              "token_contract": contract.__dict__, "training_started": False,
              "protected_opened": False, "candidate_selected": None}
    args.report_dir.mkdir(parents=True)
    if args.mode != "train":
        record["outcome"] = "TECHNICAL_REVIEW_PASS_PENDING_OWNER" if args.mode == "review" else "OWNER_GATE_PASS_NO_TRAINING"
        (args.report_dir / "run_record.json").write_text(json.dumps(record, indent=2) + "\n")
        return record
    if args.run_id is None or "/" in args.run_id or args.run_id in (".", ".."):
        raise ValueError("new run ID required")
    out = REPO / "model-output-v5/experimental" / args.run_id
    if out.exists():
        raise FileExistsError(out)
    claim_gpu()
    try:
        signal.signal(signal.SIGTERM, lambda *_: (_ for _ in ()).throw(KeyboardInterrupt()))
        record["training_started"] = True
        record["schedule"] = fit.compute_schedule(recipe, len(examples["TRAIN"]))
        (args.report_dir / "run_record.json").write_text(json.dumps(record, indent=2) + "\n")
        prep = data.PreparedData(data.EXPERIMENTAL, package, sha(args.package.read_bytes()),
                                 rows["TRAIN"], rows["VALIDATION"],
                                 gate_evidence={"owner_admission": True,
                                                "parent_v51_revalidated": True,
                                                "delta_cpu_audited": True})
        params = argparse.Namespace(max_steps=None, report_dir=str(args.report_dir))
        started = time.perf_counter()
        return fit.train_and_verify(params, data.EXPERIMENTAL, recipe, prep, tok, contract,
                                    examples["TRAIN"], examples["VALIDATION"], str(out), record, started)
    finally:
        release_gpu()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("review", "gate", "train"), required=True)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--authorization", type=Path)
    parser.add_argument("--report-dir", type=Path, required=True)
    parser.add_argument("--run-id")
    args = parser.parse_args()
    result = run(args)
    if args.mode != "train":
        print(json.dumps(result, indent=2))
