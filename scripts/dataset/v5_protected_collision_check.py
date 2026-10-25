#!/usr/bin/env python3
"""Count-only V5 text collisions with the registered consumed sets (L7/L7a).

Never prints, stores, or exposes a protected case, id, text, or hash. An unsupported
registry extractor is UNCHECKED and prevents an overall PASS; it is never treated as zero.
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts/dataset"))
from parse_dataset_v4 import canonical_key  # noqa: E402

SPLIT_ROLES = {"TRAIN": "v5_train", "VALIDATION": "v5_validation",
               "INTERNAL_TEST": "v5_internal_test"}
JSONL_FIELDS = {
    "v4_clean_train": "input", "v4_clean_eval": "input",
    "external_v1_frozen": "request_text", "external_v1_prefreeze_pool": "request_text",
    "real_http_fp_v1": "text", "v4_analyzer_disagreement_v1": "text",
    "paired_dev_v1": "BY_FILE", "minimal_pair_probe_v1": "text",
    "minimal_pair_probe_v2": "text", "historical_root_corpus": "input",
}


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _keys(lines, field: str) -> tuple[set[str], set[str], int]:
    exact, canon, missing = set(), set(), 0
    for line in lines:
        if not line.strip():
            continue
        row = json.loads(line)
        value = row.get(field)
        if not isinstance(value, str):
            missing += 1
            continue
        exact.add(value)
        canon.add(canonical_key(value))
    return exact, canon, missing


def _registered_paths(entry: dict) -> list[Path]:
    paths = sorted({Path(p) for pat in entry.get("path_globs", [])
                    for p in glob.glob(str(ROOT / pat), recursive=True) if Path(p).is_file()})
    return paths


def run(dataset: Path) -> dict:
    registry = json.loads((ROOT / "reports/v5/freeze-prep/consumed_sets.json").read_text())
    v5 = {}
    for split in SPLIT_ROLES:
        path = dataset / f"rows.{split}.jsonl"
        rows = (json.loads(line) for line in path.open(encoding="utf-8") if line.strip())
        exact = {row["text"] for row in rows}
        v5[split] = (exact, {canonical_key(x) for x in exact})
    out = {"schema": "v5-protected-collision-counts/v1", "dataset_manifest_sha256": digest(dataset / "manifest.json"),
           "registry_sha256": digest(ROOT / "reports/v5/freeze-prep/consumed_sets.json"),
           "count_only": True, "entries": [], "blocking_pass": True}
    for entry in registry:
        eid = entry["id"]
        policy = entry.get("collision_policy", {})
        roles = {sp: policy.get(role, "UNSPECIFIED") for sp, role in SPLIT_ROLES.items()}
        if all(not str(v).startswith(("BLOCK_ANY", "REPORT_COUNT", "WARN_RULING")) for v in roles.values()):
            continue
        paths = _registered_paths(entry)
        field = JSONL_FIELDS.get(eid)
        result = {"id": eid, "files": len(paths), "status": "CHECKED", "counts": {},
                  "policies": roles, "missing_text_rows": 0}
        if eid == "legacy_manual_suite_135":
            # Registry identifies the 135 S2 texts as a subset of this recorded JSONL.
            paths = [ROOT / "reports/hybrid/v4-analyzer-disagreement-v1/records.jsonl"]
            field = "DERIVED_S2"
            result["files"] = 1
        elif eid == "docker_smoke_fixtures":
            field = "SMOKE_FUNCTION"
        if not paths or field is None:
            result["status"] = "UNCHECKED_EXTRACTOR_OR_SOURCE"
            if any(str(v).startswith("BLOCK_ANY") for v in roles.values()):
                out["blocking_pass"] = False
            out["entries"].append(result)
            continue
        if entry.get("sha256") and len(paths) == 1 and digest(paths[0]) != entry["sha256"]:
            result["status"] = "SOURCE_SHA256_MISMATCH"
            out["blocking_pass"] = False
            out["entries"].append(result)
            continue
        protected_exact, protected_canon = set(), set()
        try:
            if field == "SMOKE_FUNCTION":
                sys.path.insert(0, str(ROOT / "scripts/external"))
                import phase_d_gate  # noqa: E402
                protected_exact = {row["text"] for row in phase_d_gate.load_smoke()}
                protected_canon = {canonical_key(x) for x in protected_exact}
            else:
                for path in paths:
                    with path.open(encoding="utf-8") as fh:
                        if field == "DERIVED_S2":
                            exact, canon, missing = _keys(
                                (line for line in fh if json.loads(line).get("source") == "S2"), "text")
                        else:
                            actual_field = ("request_text" if path.name == "cases.jsonl" else "text") \
                                if field == "BY_FILE" else field
                            exact, canon, missing = _keys(fh, actual_field)
                    protected_exact.update(exact)
                    protected_canon.update(canon)
                    result["missing_text_rows"] += missing
        except (OSError, UnicodeError, json.JSONDecodeError):
            result["status"] = "SOURCE_PARSE_ERROR"
            out["blocking_pass"] = False
            out["entries"].append(result)
            continue
        if result["missing_text_rows"]:
            result["status"] = "MISSING_TEXT_ROWS"
            out["blocking_pass"] = False
        for split, (v_exact, v_canon) in v5.items():
            e = len(v_exact & protected_exact)
            c = len(v_canon & protected_canon)
            result["counts"][split] = {"exact": e, "canonical": c}
            if str(roles[split]).startswith("BLOCK_ANY") and (e or c):
                out["blocking_pass"] = False
        out["entries"].append(result)
    return out


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("dataset", type=Path)
    p.add_argument("--out", type=Path, required=True)
    args = p.parse_args()
    report = run(args.dataset)
    args.out.write_text(json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"blocking_pass": report["blocking_pass"], "entries": len(report["entries"]),
                      "unchecked": sum(e["status"] != "CHECKED" for e in report["entries"])}))


if __name__ == "__main__":
    main()
