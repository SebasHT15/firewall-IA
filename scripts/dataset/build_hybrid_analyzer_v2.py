"""
firewall-IA — builder of `hybrid_analyzer_v2` (Hybrid Architecture Phase 2B run-002,
Issue #53; decision D54, which amends D51 for v2).

Same source, targets, feature schema and INTERNAL TEST views as `hybrid_analyzer_v1`
(D46-D51). What changes is the GROUP that keeps TRAIN and VALIDATION apart:

  v1 (D51)  connected components of "same canonical request OR same feature vector"
  v2 (D54)  connected components of "same canonical request OR same feature vector OR
            same V4 GENERATOR GROUP"

The generator group is the unit the V4 generator itself used to split train / eval
(D16): one canonical attack payload with its augmentation variant(s), one CSIC request
shape with digits collapsed, or one synthetic benign template value. It is not stored in
V4-clean; it is RECOVERED exactly by re-running the unmodified generator and checking that
its output is byte-identical to V4-clean (`recover_v4_provenance.py`). After the run-001
post-test finding (13.0% of v1 VALIDATION rows had a generator sibling in TRAIN), this
makes VALIDATION as independent of TRAIN as V4 eval is of V4 train.

VALIDATION (D54): stratified by group target, groups never split. Each group's stratum
is the target of its rows (BENIGN, one of the 8 categories, unsupported_jwt) or `mixed`.
Inside a stratum, groups are ordered by sha256("hybrid-analyzer-v2-validation" NUL
group_key) and visited in that order; a group joins VALIDATION when that brings the
stratum's VALIDATION rows closer to 20% of the stratum's rows. Deterministic,
order-independent, independent of PYTHONHASHSEED.

Known, accepted properties (independent audit, run-002):
  - VALIDATION shares no canonical request, vector or generator group with TRAIN, while
    INTERNAL TEST full does share 127 canonical requests and 734 vectors with the
    development set. VALIDATION therefore mirrors `internal_test_feature_disjoint`, the
    generalization view, and is pessimistic relative to `internal_test_full`.
  - A group joins VALIDATION only if its size is below twice its stratum's 20% target, so
    the two large `mixed` CSIC components (223 and 216 rows, benign + sql_injection with
    shared vectors) always stay in TRAIN; the `mixed` stratum is 5% VALIDATION.

INTERNAL TEST: unchanged views (full = V4 eval without JWT; feature-disjoint = vector not
in TRAIN u VALIDATION), plus a third flag `meta_generator_family_in_train`. Eval rows also
get a group id (components of the same relation inside V4 eval) for group-weighted
metrics.

Runs where the V4 generator runs (ML environment, `python3.12`: the generator reads the CSIC
CSV with pandas); otherwise standard library. The output is never overwritten (compared
byte for byte instead).

RUN (repository root; needs csic_database.csv and ~/PayloadsAllTheThings at the V4
manifest commit, as the V4 generator does):
    python3.12 scripts/dataset/build_hybrid_analyzer_v2.py [--check]
"""

import argparse
import hashlib
import json
import os
import sys
from collections import Counter, defaultdict

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO_ROOT, "data_plane"))
sys.path.insert(0, os.path.join(REPO_ROOT, "scripts", "dataset"))

import analyze_analyzer_targets as design  # noqa: E402  (frozen Phase 2A helpers)
import build_hybrid_analyzer_v1 as v1  # noqa: E402  (feature order, hashing helpers)
import parse_dataset_v4 as gen  # noqa: E402
import recover_v4_provenance as provenance  # noqa: E402
import request_features as rf  # noqa: E402

DATASET_NAME = "hybrid_analyzer_v2"
TARGET_SCHEMA = "analyzer-targets/v1"
OUT_DIR = os.path.join(REPO_ROOT, "datasets", DATASET_NAME)
OUT_FILE = os.path.join(OUT_DIR, f"{DATASET_NAME}.jsonl")
MANIFEST_OUT = os.path.join(REPO_ROOT, "datasets", f"manifest_{DATASET_NAME}.json")
VALIDATION_SALT = "hybrid-analyzer-v2-validation"
VALIDATION_FRACTION = 0.20
UNSUPPORTED_JWT = "unsupported_jwt"

# INTERNAL TEST views depend only on V4 eval and on TRAIN u VALIDATION as a whole, which
# are the same rows in v1 and v2, so they must not change.
EXPECTED_TEST = {"internal_test_full_rows": 6_190, "internal_test_feature_disjoint_rows": 5_456,
                 "unsupported_jwt_eval_rows": 16, "flag_feature_vector_in_train": 734,
                 "flag_canonical_request_in_train": 127,
                 "flag_generator_family_in_train": 0}


def components(rows):
    """Union-find over the D54 relation; sets r["_group"] = smallest canonical request of
    the component. Returns the number of components."""
    parent = {}

    def find(x):
        while parent.setdefault(x, x) != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        a, b = find(a), find(b)
        if a != b:
            parent[max(a, b, key=repr)] = min(a, b, key=repr)

    for r in rows:
        c = ("c", r["_canon"])
        union(c, ("v", r["_vec"]))
        union(c, ("g", r["_gid"]))
    members = defaultdict(list)
    for r in rows:
        members[find(("c", r["_canon"]))].append(r)
    for ms in members.values():
        key = min(m["_canon"] for m in ms)
        for m in ms:
            m["_group"] = key
    return members


def target_label(r):
    return r["_slice"] or r["_category"] or "BENIGN"


def stratified_validation(members):
    """Set of group keys in VALIDATION (see module docstring)."""
    strata = defaultdict(list)
    for ms in members.values():
        labels = {target_label(m) for m in ms}
        stratum = labels.pop() if len(labels) == 1 else "mixed"
        strata[stratum].append((ms[0]["_group"], len(ms)))
    chosen, report = set(), {}
    for stratum, groups in sorted(strata.items()):
        total = sum(n for _, n in groups)
        target = VALIDATION_FRACTION * total
        order = sorted(groups, key=lambda g: (hashlib.sha256(
            f"{VALIDATION_SALT}\x00{g[0]}".encode()).hexdigest(), g[0]))
        val = 0
        for key, n in order:
            if abs(val + n - target) < abs(val - target):
                chosen.add(key)
                val += n
        report[stratum] = {"groups": len(groups), "rows": total,
                           "validation_rows": val,
                           "validation_share": round(val / total, 4) if total else None}
    return chosen, report


def size_distribution(sizes):
    c = Counter(sizes)
    bands = {"1": 0, "2": 0, "3-5": 0, "6-10": 0, "11-50": 0, "51-200": 0, ">200": 0}
    for s, n in c.items():
        band = ("1" if s == 1 else "2" if s == 2 else "3-5" if s <= 5 else "6-10" if s <= 10
                else "11-50" if s <= 50 else "51-200" if s <= 200 else ">200")
        bands[band] += n
    return {"groups": len(sizes), "largest": max(sizes), "groups_by_size": bands,
            "rows_in_groups_of_10_or_more": sum(s for s in sizes if s >= 10)}


def within_split(rows):
    """Internal duplication of one split (NOT leakage)."""
    return {"rows": len(rows),
            "distinct_canonical_requests": len({r["_canon"] for r in rows}),
            "distinct_feature_vectors": len({r["_vec"] for r in rows}),
            "distinct_generator_groups": len({r["_gid"] for r in rows}),
            "distinct_d54_groups": len({r["_group"] for r in rows}),
            "rows_sharing_a_vector_with_another_row":
                sum(n for n in Counter(r["_vec"] for r in rows).values() if n > 1)}


def build():
    v4_manifest = json.load(open(design.MANIFEST))
    rows = design.load(v4_manifest)                     # V4-clean, SHA-256 verified
    prov, prov_check = provenance.recover()             # byte-identical regeneration
    prov_by = {(p["split"], p["line"]): p for p in prov}
    reason_to_cat = {r: c for c, (r, _) in {**gen.CATEGORY_SHAPES, **gen.HARDCODED_SHAPES}.items()}
    shape_paths = defaultdict(set)
    for name, shape in gen.SHAPES.items():
        for p in shape["paths"]:
            shape_paths[p].add(name)

    line_no = Counter()
    for r in rows:
        r["_line"] = line_no[r["split"]]
        line_no[r["split"]] += 1
        p = prov_by[(r["split"], r["_line"])]
        row_id = v1.sha256_hex(r["input"])
        if p["row_id"] != row_id:
            raise SystemExit(f"FATAL: provenance misaligned at {r['split']}:{r['_line']}")
        r["_gid"], r["_gsrc"] = p["generator_group_id"], p["generator_source"]
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
        r["_vec"] = v1.feature_vector(r["_features"])

    train = [r for r in rows if r["split"] == "train"]
    evals = [r for r in rows if r["split"] == "eval"]
    dev_members = components(train)
    eval_members = components(evals)
    chosen, strata = stratified_validation(dev_members)
    for r in train:
        r["_role"] = "validation" if r["_group"] in chosen else "train"
    for r in evals:
        r["_role"] = "internal_test"

    used = [r for r in train if r["_slice"] is None]   # TRAIN u VALIDATION, JWT out
    used_vec = {r["_vec"] for r in used}
    used_canon = {r["_canon"] for r in used}
    used_gid = {r["_gid"] for r in used}
    for r in evals:
        r["_vec_in"], r["_canon_in"], r["_gid_in"] = (r["_vec"] in used_vec,
                                                      r["_canon"] in used_canon,
                                                      r["_gid"] in used_gid)

    lines = []
    for r in rows:
        is_eval = r["split"] == "eval"
        lines.append(json.dumps({
            "row_id": v1.sha256_hex(r["input"]),
            "role": r["_role"],
            "slice": r["_slice"],
            "features": {n: getattr(r["_features"], n) for n in v1.FEATURE_FIELDS},
            "target_attack": r["_attack"],
            "target_category": r["_category"],
            "meta_v4_split": r["split"],
            "meta_v4_line": r["_line"],
            "meta_v4_decision": r["_decision"],
            "meta_v4_reason": r["_reason"],
            "meta_v4_category": r["_v4_category"],
            "meta_source": r["_source"],
            "meta_shape": r["_shape"],
            "meta_generator_group_id": r["_gid"],
            "meta_generator_source": r["_gsrc"],
            "meta_group_id": v1.sha256_hex(("eval\x00" if is_eval else "dev\x00") + r["_group"]),
            "meta_canonical_request_sha256": v1.sha256_hex(r["_canon"]),
            "meta_feature_vector_sha256": v1.vector_hash(r["_vec"]),
            "meta_feature_vector_in_train": r["_vec_in"] if is_eval else None,
            "meta_canonical_request_in_train": r["_canon_in"] if is_eval else None,
            "meta_generator_family_in_train": r["_gid_in"] if is_eval else None,
        }, ensure_ascii=False))
    data = ("\n".join(lines) + "\n").encode("utf-8")

    def fitted(role):
        return [r for r in rows if r["_role"] == role and r["_slice"] is None]

    trn_all = [r for r in train if r["_role"] == "train"]
    val_all = [r for r in train if r["_role"] == "validation"]
    trn, val = fitted("train"), fitted("validation")
    full = fitted("internal_test")
    disjoint = [r for r in full if not r["_vec_in"]]

    def keys(rs, k):
        return {r[k] for r in rs}

    leakage = {  # TRAIN <-> VALIDATION, every row of both roles (JWT included)
        "canonical_request": len(keys(trn_all, "_canon") & keys(val_all, "_canon")),
        "feature_vector": len(keys(trn_all, "_vec") & keys(val_all, "_vec")),
        "generator_family": len(keys(trn_all, "_gid") & keys(val_all, "_gid")),
        "d54_group": len(keys(trn_all, "_group") & keys(val_all, "_group")),
    }

    def mix(rs, f):
        return dict(sorted(Counter(f(r) for r in rs).items()))

    stats = {
        "train_rows": len(trn_all), "validation_rows": len(val_all),
        "train_fitted_rows": len(trn), "validation_fitted_rows": len(val),
        "validation_share_of_v4_train": round(len(val_all) / len(train), 4),
        "internal_test_full_rows": len(full),
        "internal_test_feature_disjoint_rows": len(disjoint),
        "unsupported_jwt_eval_rows": sum(r["_slice"] == UNSUPPORTED_JWT for r in evals),
        "flag_feature_vector_in_train": sum(r["_vec_in"] for r in full),
        "flag_canonical_request_in_train": sum(r["_canon_in"] for r in full),
        "flag_generator_family_in_train": sum(r["_gid_in"] for r in full),
        "train_validation_overlap": leakage,
    }
    detail = {
        "provenance": prov_check,
        "groups": {
            "development (V4 train)": size_distribution([len(m) for m in dev_members.values()]),
            "internal_test (V4 eval)": size_distribution([len(m) for m in eval_members.values()]),
            "train": size_distribution(list(Counter(r["_group"] for r in trn_all).values())),
            "validation": size_distribution(list(Counter(r["_group"] for r in val_all).values())),
            "generator_groups_in_development": len({r["_gid"] for r in train}),
            "generator_groups_split_across_train_validation": leakage["generator_family"],
        },
        "strata": strata,
        "within_split_duplication (not leakage)": {
            "train": within_split(trn_all), "validation": within_split(val_all),
            "internal_test": within_split(evals)},
        "unsupported_jwt_rows_by_role": dict(Counter(r["_role"] for r in rows
                                                     if r["_slice"] == UNSUPPORTED_JWT)),
        "targets": {n: mix(rs, lambda r: r["_category"] or "BENIGN") for n, rs in
                    (("train", trn), ("validation", val), ("internal_test_full", full),
                     ("internal_test_feature_disjoint", disjoint))},
        "attack": {n: mix(rs, lambda r: r["_attack"]) for n, rs in
                   (("train", trn), ("validation", val), ("internal_test_full", full),
                    ("internal_test_feature_disjoint", disjoint))},
        "v4_reasons": {n: mix(rs, lambda r: r["_v4_category"]) for n, rs in
                       (("train", trn), ("validation", val), ("internal_test_full", full),
                        ("internal_test_feature_disjoint", disjoint))},
        "generator_source": {n: mix(rs, lambda r: r["_gsrc"]) for n, rs in
                             (("train", trn), ("validation", val), ("internal_test_full", full))},
    }
    return data, stats, detail, v4_manifest


def git_state():
    import subprocess

    def run(*args):
        return subprocess.run(["git", "-C", REPO_ROOT, *args], capture_output=True,
                              text=True).stdout.strip()
    paths = [os.path.relpath(os.path.join(REPO_ROOT, "scripts", "dataset", f), REPO_ROOT)
             for f in ("build_hybrid_analyzer_v2.py", "recover_v4_provenance.py",
                       "build_hybrid_analyzer_v1.py", "analyze_analyzer_targets.py",
                       "parse_dataset_v4.py")]
    return {"head": run("rev-parse", "HEAD"),
            "code_sha256": {p: v1.sha256_hex(open(os.path.join(REPO_ROOT, p), "rb").read())
                            for p in paths},
            "committed_unchanged": run("status", "--porcelain", "--", *paths) == ""}


def manifest(data, stats, detail, v4_manifest):
    return {
        "dataset_name": DATASET_NAME,
        "status": "D54; immutable once a model is trained on it — any change is hybrid_analyzer_v3",
        "supersedes_for_development": "hybrid_analyzer_v1 (D51), kept unchanged with run-001",
        "issue": 53,
        "feature_schema": rf.FEATURE_SCHEMA_VERSION,
        "feature_fields": list(v1.FEATURE_FIELDS),
        "target_schema": TARGET_SCHEMA,
        "source": {"dataset": "datasets/v4_clean", "manifest": "datasets/manifest_v4_clean.json",
                   "sha256": v4_manifest["artifact_sha256"],
                   "v4_generator_git_commit": v4_manifest["generator_git_commit"],
                   "modified": False},
        "builder": git_state(),
        "external_test_v1": "not read",
        "mapping": {"attack": {"ALLOW": 0, "BLOCK": 1},
                    "category": {**design.ANALYZER_CATEGORY,
                                 "<every other BLOCK category>": "other_attack"},
                    "not_fitted": dict(design.UNSUPPORTED)},
        "grouping": "connected components over V4 train of 'same canonical request OR same "
                    "feature vector OR same V4 generator group'; canonical request = "
                    "parse_dataset_v4.canonical_key(f'{method} {path}?{query}\\n{content_type}"
                    "\\n{body}'); feature vector = the 34 RequestFeatures v2 values; generator "
                    "group = the generator's in-memory _gid, recovered by byte-identical "
                    "regeneration (scripts/dataset/recover_v4_provenance.py); group key = "
                    "smallest canonical request of the component",
        "validation": {"salt": VALIDATION_SALT, "fraction": VALIDATION_FRACTION,
                       "rule": "per stratum (group target or 'mixed'), groups ordered by "
                               "sha256(salt NUL group_key); a group joins VALIDATION when that "
                               "brings the stratum's VALIDATION rows closer to fraction x rows"},
        "views": {"internal_test_full": "role == internal_test and slice is null",
                  "internal_test_feature_disjoint": "internal_test_full and not "
                                                    "meta_feature_vector_in_train",
                  "unsupported_jwt": "slice == unsupported_jwt",
                  "flag_reference_set": "TRAIN u VALIDATION (development set), JWT excluded",
                  "meta_group_id": "D54 component id; for eval rows, components of the same "
                                   "relation inside V4 eval (used for group-weighted metrics)"},
        "model_inputs": "only the `features` object; every other field is offline metadata",
        "counts": stats,
        "counts_expected_unchanged_from_v1": EXPECTED_TEST,
        **detail,
        "artifact": {"path": os.path.relpath(OUT_FILE, REPO_ROOT), "rows": data.count(b"\n"),
                     "bytes": len(data), "sha256": v1.sha256_hex(data)},
    }


def check(stats):
    problems = {k: (stats[k], v) for k, v in EXPECTED_TEST.items() if stats[k] != v}
    problems.update({f"overlap:{k}": v for k, v in stats["train_validation_overlap"].items() if v})
    if problems:
        raise SystemExit(f"FATAL: hybrid_analyzer_v2 invariants violated: {problems}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--check", action="store_true",
                    help="build in memory and compare with the existing output; write nothing")
    args = ap.parse_args()
    data, stats, detail, v4_manifest = build()
    check(stats)
    digest = v1.sha256_hex(data)
    if os.path.exists(OUT_FILE):
        existing = v1.sha256_hex(open(OUT_FILE, "rb").read())
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
