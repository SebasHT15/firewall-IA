"""
firewall-IA — builder of `hybrid_analyzer_v1` (Hybrid Architecture Phase 2B, Issue #53).

Derives the Lightweight Request Analyzer's dataset from V4-clean exactly as frozen in
Phase 2A (D46-D51, reports/hybrid/phase2a-analyzer-design/ section 10):

  source        datasets/v4_clean/{train,eval}.jsonl, SHA-256 verified against
                datasets/manifest_v4_clean.json; never modified
  roles         V4 train -> TRAIN + VALIDATION (grouped 80/20); V4 eval -> INTERNAL TEST
  group (D51)   connected components over V4 train of "same canonical request OR same
                feature vector"; group key = smallest canonical request in the component
  VALIDATION    sha256("hybrid-analyzer-v1-validation" NUL group_key)[:8] % 10000 < 2000
  targets       attack (ALLOW 0 / BLOCK 1) and category (D47/D49); JWT -> slice
                `unsupported_jwt`, never a fitting target (D48)
  test views    no row removed: eval rows carry `meta_feature_vector_in_train` and
                `meta_canonical_request_in_train` (both against TRAIN u VALIDATION, JWT out)

The reason -> category mapping, the VALIDATION bucket and the D1-text parser are imported
from the Phase 2A analysis script, so builder and frozen design cannot drift apart.

Per row: `row_id` (SHA-256 of the V4 `input`; the text is not copied), `role`, `slice`,
`features` (the 34 RequestFeatures v2 values — the ONLY model input), `target_attack`,
`target_category`, and offline metadata prefixed `meta_` (never a model input).

Standard library only. Deterministic: same bytes across runs and PYTHONHASHSEED values.
The output is never overwritten: if it exists, the build is compared byte for byte.

RUN (repository root):
    python3.12 scripts/dataset/build_hybrid_analyzer_v1.py
"""

import argparse
import dataclasses
import hashlib
import json
import os
import subprocess
import sys
from collections import Counter, defaultdict

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO_ROOT, "data_plane"))
sys.path.insert(0, os.path.join(REPO_ROOT, "scripts", "dataset"))

import analyze_analyzer_targets as design  # noqa: E402  (frozen Phase 2A helpers)
import parse_dataset_v4 as gen  # noqa: E402  (canonical_key, reason -> V4 category)
import request_features as rf  # noqa: E402

DATASET_NAME = "hybrid_analyzer_v1"
TARGET_SCHEMA = "analyzer-targets/v1"
OUT_DIR = os.path.join(REPO_ROOT, "datasets", DATASET_NAME)
OUT_FILE = os.path.join(OUT_DIR, f"{DATASET_NAME}.jsonl")
MANIFEST_OUT = os.path.join(REPO_ROOT, "datasets", f"manifest_{DATASET_NAME}.json")

FEATURE_FIELDS = tuple(f.name for f in dataclasses.fields(rf.RequestFeatures)
                       if f.name != "schema_version")
UNSUPPORTED_JWT = "unsupported_jwt"

# Counts the frozen design published (Phase 2A README section 10, analysis.json).
# A build that does not reproduce them is not hybrid_analyzer_v1.
EXPECTED = {
    "groups": 18_720,
    "largest_group_rows": 417,
    "train_rows": 20_141,
    "validation_rows": 4_993,
    "train_fitted_rows": 20_059,
    "validation_fitted_rows": 4_980,
    "internal_test_full_rows": 6_190,
    "internal_test_feature_disjoint_rows": 5_456,
    "unsupported_jwt_eval_rows": 16,
    "flag_feature_vector_in_train": 734,
    "flag_canonical_request_in_train": 127,
    "validation_vectors_in_train": 0,
    "validation_canonical_requests_in_train": 0,
}


def sha256_hex(data):
    return hashlib.sha256(data if isinstance(data, bytes) else data.encode("utf-8")).hexdigest()


def feature_vector(features):
    return tuple(getattr(features, name) for name in FEATURE_FIELDS)


def vector_hash(vec):
    return sha256_hex(json.dumps(list(vec), ensure_ascii=False))


def connected_groups(rows):
    """D51 group key of each V4-train row: union-find over the relation "same
    canonical request OR same feature vector"; key = smallest canonical request of
    the component. Same algorithm as the Phase 2A grouping check."""
    parent = {}

    def find(x):
        while parent.setdefault(x, x) != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for r in rows:
        a, b = find(("c", r["_canon"])), find(("v", r["_vec"]))
        if a != b:
            parent[max(a, b, key=repr)] = min(a, b, key=repr)
    members = defaultdict(list)
    for r in rows:
        members[find(("c", r["_canon"]))].append(r)
    for ms in members.values():
        key = min(m["_canon"] for m in ms)
        for m in ms:
            m["_group"] = key
    return len(members), max(len(ms) for ms in members.values())


def git_state():
    def run(*args):
        return subprocess.run(["git", "-C", REPO_ROOT, *args], capture_output=True,
                              text=True).stdout.strip()
    rel = os.path.relpath(os.path.abspath(__file__), REPO_ROOT)
    return {"head": run("rev-parse", "HEAD"),
            "builder_path": rel,
            "builder_committed_unchanged": run("status", "--porcelain", "--", rel) == ""}


def build():
    """(jsonl bytes, statistics) of hybrid_analyzer_v1."""
    v4_manifest = json.load(open(design.MANIFEST))
    rows = design.load(v4_manifest)                   # verifies V4-clean SHA-256
    reason_to_cat = {r: c for c, (r, _) in {**gen.CATEGORY_SHAPES, **gen.HARDCODED_SHAPES}.items()}
    shape_paths = defaultdict(set)
    for name, shape in gen.SHAPES.items():
        for p in shape["paths"]:
            shape_paths[p].add(name)

    line_no = Counter()
    for r in rows:
        r["_line"] = line_no[r["split"]]
        line_no[r["split"]] += 1
        decision, _, reason = r["output"].partition(" | ")
        r["_decision"], r["_reason"] = decision, reason
        r["_v4_category"] = "BENIGN" if decision == "ALLOW" else reason_to_cat[reason]
        r["_attack"], r["_category"], r["_slice"] = design.analyzer_target(r["_v4_category"])
        method, path, query, ctype, body = design.parse_text(r["input"])
        r["_canon"] = gen.canonical_key(f"{method} {path}?{query}\n{ctype}\n{body}")
        r["_source"] = ("shape" if path in shape_paths and path != "/" else
                        "ambiguous('/')" if path == "/" else "csic")
        r["_shape"] = "|".join(sorted(shape_paths.get(path, {"<csic>"})))
        r["_features"] = rf.extract_features(r["input"])
        r["_vec"] = feature_vector(r["_features"])

    train = [r for r in rows if r["split"] == "train"]
    evals = [r for r in rows if r["split"] == "eval"]
    n_groups, largest = connected_groups(train)
    for r in train:
        r["_role"] = "validation" if design.in_validation(r["_group"]) else "train"
    for r in evals:
        r["_role"] = "internal_test"

    # Reference set of both INTERNAL TEST flags: every V4-train row available to the
    # Analyzer (TRAIN u VALIDATION, JWT excluded) — D51.
    used = [r for r in train if r["_slice"] is None]
    used_vec = {r["_vec"] for r in used}
    used_canon = {r["_canon"] for r in used}
    for r in evals:
        r["_vec_in_train"] = r["_vec"] in used_vec
        r["_canon_in_train"] = r["_canon"] in used_canon

    lines = []
    for r in rows:
        is_eval = r["split"] == "eval"
        out = {
            "row_id": sha256_hex(r["input"]),
            "role": r["_role"],
            "slice": r["_slice"],
            "features": {name: getattr(r["_features"], name) for name in FEATURE_FIELDS},
            "target_attack": r["_attack"],
            "target_category": r["_category"],
            "meta_v4_split": r["split"],
            "meta_v4_line": r["_line"],
            "meta_v4_decision": r["_decision"],
            "meta_v4_reason": r["_reason"],
            "meta_v4_category": r["_v4_category"],
            "meta_source": r["_source"],
            "meta_shape": r["_shape"],
            "meta_group_id": None if is_eval else sha256_hex(r["_group"]),
            "meta_canonical_request_sha256": sha256_hex(r["_canon"]),
            "meta_feature_vector_sha256": vector_hash(r["_vec"]),
            "meta_feature_vector_in_train": r["_vec_in_train"] if is_eval else None,
            "meta_canonical_request_in_train": r["_canon_in_train"] if is_eval else None,
        }
        lines.append(json.dumps(out, ensure_ascii=False, sort_keys=False))
    data = ("\n".join(lines) + "\n").encode("utf-8")

    def fitted(role):
        return [r for r in rows if r["_role"] == role and r["_slice"] is None]

    trn, val = fitted("train"), fitted("validation")
    trn_vec, trn_canon = {r["_vec"] for r in trn}, {r["_canon"] for r in trn}
    full = fitted("internal_test")
    disjoint = [r for r in full if not r["_vec_in_train"]]
    jwt_eval = [r for r in evals if r["_slice"] == UNSUPPORTED_JWT]

    def target_mix(rs):
        return dict(sorted(Counter(r["_category"] or "BENIGN" for r in rs).items()))

    stats = {
        "groups": n_groups,
        "largest_group_rows": largest,
        "train_rows": sum(r["_role"] == "train" for r in rows),
        "validation_rows": sum(r["_role"] == "validation" for r in rows),
        "train_fitted_rows": len(trn),
        "validation_fitted_rows": len(val),
        "internal_test_full_rows": len(full),
        "internal_test_feature_disjoint_rows": len(disjoint),
        "unsupported_jwt_eval_rows": len(jwt_eval),
        "flag_feature_vector_in_train": sum(r["_vec_in_train"] for r in full),
        "flag_canonical_request_in_train": sum(r["_canon_in_train"] for r in full),
        "validation_vectors_in_train": sum(r["_vec"] in trn_vec for r in val),
        "validation_canonical_requests_in_train": sum(r["_canon"] in trn_canon for r in val),
    }
    detail = {
        "unsupported_jwt_rows_by_role": dict(Counter(r["_role"] for r in rows
                                                     if r["_slice"] == UNSUPPORTED_JWT)),
        "validation_share_of_v4_train": round(stats["validation_rows"] / len(train), 4),
        "targets": {"train": target_mix(trn), "validation": target_mix(val),
                    "internal_test_full": target_mix(full),
                    "internal_test_feature_disjoint": target_mix(disjoint)},
        "attack": {name: dict(sorted(Counter(r["_attack"] for r in rs).items()))
                   for name, rs in (("train", trn), ("validation", val),
                                    ("internal_test_full", full),
                                    ("internal_test_feature_disjoint", disjoint))},
        "v4_reasons": {name: dict(sorted(Counter(r["_v4_category"] for r in rs).items()))
                       for name, rs in (("train", trn), ("validation", val),
                                        ("internal_test_full", full),
                                        ("internal_test_feature_disjoint", disjoint))},
    }
    return data, stats, detail, v4_manifest


def manifest(data, stats, detail, v4_manifest):
    return {
        "dataset_name": DATASET_NAME,
        "status": "frozen (D51); immutable once a model is trained on it — any change is "
                  "hybrid_analyzer_v2",
        "issue": 53,
        "feature_schema": rf.FEATURE_SCHEMA_VERSION,
        "feature_fields": list(FEATURE_FIELDS),
        "target_schema": TARGET_SCHEMA,
        "source": {
            "dataset": "datasets/v4_clean",
            "manifest": "datasets/manifest_v4_clean.json",
            "sha256": v4_manifest["artifact_sha256"],
            "v4_generator_git_commit": v4_manifest["generator_git_commit"],
            "modified": False,
        },
        "builder": git_state(),
        "external_test_v1": "not read",
        "mapping": {
            "attack": {"ALLOW": 0, "BLOCK": 1},
            "category": {**design.ANALYZER_CATEGORY, "<every other BLOCK category>": "other_attack"},
            "not_fitted": dict(design.UNSUPPORTED),
        },
        "grouping": "connected components over V4 train of 'same canonical request OR same "
                    "feature vector'; canonical request = parse_dataset_v4.canonical_key("
                    "f'{method} {path}?{query}\\n{content_type}\\n{body}'); feature vector = "
                    "the 34 RequestFeatures v2 values in field order; group key = smallest "
                    "canonical request in the component",
        "validation": {"salt": design.VALIDATION_SALT, "fraction": design.VALIDATION_FRACTION,
                       "rule": "int.from_bytes(sha256(salt + '\\x00' + group_key)[:8], 'big') "
                               "% 10000 < 2000"},
        "views": {
            "internal_test_full": "role == internal_test and slice is null",
            "internal_test_feature_disjoint": "internal_test_full and not meta_feature_vector_in_train",
            "unsupported_jwt": "slice == unsupported_jwt (never fitted; eval rows are the slice)",
            "flag_reference_set": "TRAIN u VALIDATION, JWT excluded",
        },
        "model_inputs": "only the `features` object; every `meta_` field, `role`, `slice` and "
                        "`row_id` is offline metadata",
        "counts": stats,
        "counts_expected_from_phase2a": EXPECTED,
        **detail,
        "artifact": {"path": os.path.relpath(OUT_FILE, REPO_ROOT),
                     "rows": data.count(b"\n"), "bytes": len(data), "sha256": sha256_hex(data)},
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--check", action="store_true",
                    help="build in memory and compare with the existing output; write nothing")
    args = ap.parse_args()

    data, stats, detail, v4_manifest = build()
    mismatches = {k: (stats[k], v) for k, v in EXPECTED.items() if stats[k] != v}
    if mismatches:
        raise SystemExit(f"FATAL: build does not reproduce the frozen design: {mismatches}")
    digest = sha256_hex(data)

    if os.path.exists(OUT_FILE):
        existing = sha256_hex(open(OUT_FILE, "rb").read())
        if existing != digest:
            raise SystemExit(f"FATAL: {OUT_FILE} exists with SHA-256 {existing}, rebuild gives "
                             f"{digest}; datasets are never overwritten")
        print(f"identical: {OUT_FILE} sha256 {digest}")
        return
    if args.check:
        raise SystemExit(f"FATAL: --check but {OUT_FILE} does not exist")
    os.makedirs(OUT_DIR, exist_ok=True)
    with open(OUT_FILE, "xb") as f:
        f.write(data)
    with open(MANIFEST_OUT, "x", encoding="utf-8") as f:
        json.dump(manifest(data, stats, detail, v4_manifest), f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"wrote {OUT_FILE} ({data.count(b'\n')} rows, sha256 {digest})")
    print(json.dumps(stats, indent=2))


if __name__ == "__main__":
    main()
