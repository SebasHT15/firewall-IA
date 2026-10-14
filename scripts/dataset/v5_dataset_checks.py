#!/usr/bin/env python3
"""
firewall-IA — V5 dataset checks (Issue #64, Workstream B).  READ-ONLY, standard library only.

Small, generic checks for a V5 dataset builder and for the owner who freezes it. Nothing here
generates, mutates or trains anything, and every result is a plain JSON-serialisable dict of
COUNTS, row indices and group identifiers. A result never contains request text, so it is safe to
run against a protected set (External Test v1, development diagnostics) without exposing its
cases.

Why a new file (searched first; see reports/v5/freeze-prep/B_dataset_engineering_audit.md §8):
  * check_dataset.py is E0: one monolithic main(), V4 train/eval, exact-match leakage only,
    envelope shortcuts only. It is IMPORTED here for load_jsonl() and sha256().
  * phase_d_gate.collision_check/internal_duplicates are hard-wired to External candidate dicts
    (case_id, request_sha256, payload_decoded) and V4/diag/smoke paths.
  * build_hybrid_analyzer_v2.within_split/check and paired_dev_set.dependency_components are
    specific to their own row schemas.
  * hybrid_analyzer.load_dataset verifies exactly one manifest layout inline.
  * parse_dataset_v4.canonical_key (D16) is IMPORTED, never re-implemented.

Checks
  find_duplicates            exact and canonical-key duplicates within / across splits
  check_group_disjointness   arbitrary group-key fields (or composites) disjoint across splits
  check_label_consistency    one canonical key never carries two labels
  verify_manifest            recompute SHA-256 (and size) of the artifacts a manifest lists
  check_protected_collisions candidate rows vs protected / consumed JSONL sets, exact + canonical

CLI (exit codes follow check_dataset.py: 0 PASS, 2 FAIL, 3 could not run)
  python3 scripts/dataset/v5_dataset_checks.py duplicates  --split train=a.jsonl --split val=b.jsonl
  python3 scripts/dataset/v5_dataset_checks.py groups      --split ... --key provider_family --key template_id
  python3 scripts/dataset/v5_dataset_checks.py labels      --split ... --label-field label
  python3 scripts/dataset/v5_dataset_checks.py manifest    --manifest datasets/manifest_x.json
  python3 scripts/dataset/v5_dataset_checks.py collisions  --candidate c.jsonl --protected name=path[:field]
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import defaultdict
from itertools import combinations
from typing import Callable, Iterable, Mapping, Sequence

_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

import check_dataset  # noqa: E402  (load_jsonl, sha256)
from parse_dataset_v4 import canonical_key  # noqa: E402,F401  (D16 canonical identity)

REPO_ROOT = os.path.dirname(os.path.dirname(_HERE))
EXAMPLE_LIMIT = 5

Rows = Sequence[Mapping]


# ── helpers ─────────────────────────────────────────────────────────────────
def read_jsonl(path: str) -> list[dict]:
    """check_dataset.load_jsonl with ValueError instead of SystemExit (library-friendly)."""
    try:
        return check_dataset.load_jsonl(path)
    except SystemExit as e:
        raise ValueError(str(e)) from None


def sha256_file(path: str) -> str:
    return check_dataset.sha256(path)


def _texts(rows: Rows, field: str, where: str) -> list[str]:
    out = []
    for i, r in enumerate(rows):
        t = r.get(field)
        if not isinstance(t, str):
            raise ValueError(f"{where}[{i}]: field {field!r} is missing or not a string")
        out.append(t)
    return out


def _hashable(v):
    try:
        hash(v)
        return v
    except TypeError:
        return json.dumps(v, sort_keys=True, ensure_ascii=False)


def _first_index(seq: Sequence[str]) -> dict[str, int]:
    first: dict[str, int] = {}
    for i, s in enumerate(seq):
        first.setdefault(s, i)
    return first


# ── (a) exact and canonical duplicates ──────────────────────────────────────
def find_duplicates(splits: Mapping[str, Rows], text_field: str = "input",
                    key_fn: Callable[[str], str] = canonical_key,
                    fail_on_within_exact: bool = False) -> dict:
    """Duplicates WITHIN each split and SHARED KEYS across every pair of splits.

    Cross-split sharing (exact or canonical) always fails: D16 forbids one logical identity in two
    splits. Within-split canonical duplicates are reported but never fail (augmentation variants of
    one group legitimately collapse); within-split EXACT duplicates fail only when
    `fail_on_within_exact` is set. `exact` equality implies `canonical` equality.
    """
    exact: dict[str, list[str]] = {}
    canon: dict[str, list[str]] = {}
    within = {}
    for name, rows in splits.items():
        exact[name] = _texts(rows, text_field, name)
        canon[name] = [key_fn(t) for t in exact[name]]
        within[name] = {"rows": len(rows),
                        "exact_duplicate_rows": len(rows) - len(set(exact[name])),
                        "canonical_duplicate_rows": len(rows) - len(set(canon[name]))}
    across = {}
    for a, b in combinations(list(splits), 2):
        ex = set(exact[a]) & set(exact[b])
        ca = set(canon[a]) & set(canon[b])
        fa, fb = _first_index(canon[a]), _first_index(canon[b])
        across[f"{a}|{b}"] = {
            "exact_shared_keys": len(ex),
            "canonical_shared_keys": len(ca),
            "exact_rows": {a: sum(1 for t in exact[a] if t in ex),
                           b: sum(1 for t in exact[b] if t in ex)},
            "canonical_rows": {a: sum(1 for k in canon[a] if k in ca),
                               b: sum(1 for k in canon[b] if k in ca)},
            "examples": [{a: fa[k], b: fb[k]} for k in sorted(ca)[:EXAMPLE_LIMIT]],
        }
    ok = all(v["canonical_shared_keys"] == 0 for v in across.values())
    if fail_on_within_exact:
        ok = ok and all(v["exact_duplicate_rows"] == 0 for v in within.values())
    return {"check": "duplicates", "ok": ok, "text_field": text_field,
            "within": within, "across": across}


# ── (b) group-key disjointness ──────────────────────────────────────────────
def check_group_disjointness(splits: Mapping[str, Rows],
                             keys: Iterable[str | Sequence[str]]) -> dict:
    """For each key (a field name, or a tuple of fields forming a composite key) the set of key
    values must be pairwise disjoint across splits. A row missing any field of a key counts as
    `missing` and fails the check: an unattributable row cannot be shown to be disjoint.
    Intended for identifier fields (provider_family, template_id, family_id, value_pool_id...)."""
    result = {}
    ok_all = True
    for key in keys:
        fields = (key,) if isinstance(key, str) else tuple(key)
        label = "+".join(fields)
        values: dict[str, set] = {}
        missing: dict[str, int] = {}
        for name, rows in splits.items():
            vs, m = set(), 0
            for r in rows:
                if any(f not in r or r[f] is None for f in fields):
                    m += 1
                    continue
                vs.add(tuple(_hashable(r[f]) for f in fields))
            values[name], missing[name] = vs, m
        inter = {}
        for a, b in combinations(list(splits), 2):
            shared = values[a] & values[b]
            inter[f"{a}|{b}"] = {"count": len(shared),
                                 "examples": [str(v if len(v) > 1 else v[0])[:80]
                                              for v in sorted(shared, key=repr)[:EXAMPLE_LIMIT]]}
        ok = not any(missing.values()) and all(v["count"] == 0 for v in inter.values())
        ok_all = ok_all and ok
        result[label] = {"ok": ok, "distinct_values": {n: len(v) for n, v in values.items()},
                         "missing_rows": missing, "intersections": inter}
    return {"check": "group_disjointness", "ok": ok_all, "keys": result}


# ── (c) label consistency ───────────────────────────────────────────────────
def check_label_consistency(splits: Mapping[str, Rows], text_field: str = "input",
                            label_field: str = "label",
                            label_fn: Callable[[Mapping], str] | None = None,
                            key_fn: Callable[[str], str] = canonical_key) -> dict:
    """The same canonical key (and a fortiori the same exact text) never carries two labels,
    inside a split or across splits. `label_fn(row)` overrides `label_field` (e.g.
    check_dataset.label_of for V4's 'ALLOW | reason' outputs)."""
    get = label_fn or (lambda r: r.get(label_field))
    by_canon: dict[str, dict] = defaultdict(lambda: defaultdict(list))
    by_exact: dict[str, dict] = defaultdict(lambda: defaultdict(list))
    n = 0
    for name, rows in splits.items():
        texts = _texts(rows, text_field, name)
        for i, (r, t) in enumerate(zip(rows, texts)):
            lab = get(r)
            if lab is None:
                raise ValueError(f"{name}[{i}]: no label (field {label_field!r})")
            by_canon[key_fn(t)][lab].append((name, i))
            by_exact[t][lab].append((name, i))
            n += 1

    def conflicts(groups):
        return {k: v for k, v in groups.items() if len(v) > 1}

    cc, ce = conflicts(by_canon), conflicts(by_exact)
    spanning = sum(1 for v in cc.values()
                   if len({s for locs in v.values() for s, _ in locs}) > 1)
    examples = [{lab: [{"split": s, "row": i} for s, i in locs[:EXAMPLE_LIMIT]]
                 for lab, locs in v.items()} for _, v in sorted(cc.items())[:EXAMPLE_LIMIT]]
    return {"check": "label_consistency", "ok": not cc, "rows": n,
            "distinct_canonical_keys": len(by_canon),
            "canonical_conflicts": len(cc), "exact_conflicts": len(ce),
            "conflicts_spanning_splits": spanning, "examples": examples}


# ── (d) manifest integrity ──────────────────────────────────────────────────
def manifest_artifacts(manifest: Mapping, paths: Mapping[str, str] | None = None) -> list[dict]:
    """Normalise the artifact listings found in this repository's manifests:
      V5 proposal  {"artifacts": [{"path", "sha256", "bytes"?}, ...]}
      hybrid       {"artifact": {"path", "sha256", "bytes"?}}        (manifest_hybrid_analyzer_v*)
      V4           {"artifact_sha256": {name: hex}, "artifact_bytes": {name: n}}  (no paths:
                   pass `paths={name: path}`; without it the entry is 'unresolved')."""
    paths = paths or {}
    out = []
    if isinstance(manifest.get("artifacts"), list):
        for a in manifest["artifacts"]:
            out.append({"name": a.get("path"), "path": a.get("path"),
                        "sha256": a.get("sha256"), "bytes": a.get("bytes"), "declared": True})
    if isinstance(manifest.get("artifact"), dict):
        a = manifest["artifact"]
        out.append({"name": "artifact", "path": a.get("path"), "sha256": a.get("sha256"),
                    "bytes": a.get("bytes"), "declared": True})
    if isinstance(manifest.get("artifact_sha256"), dict):
        sizes = manifest.get("artifact_bytes") or {}
        for name, digest in manifest["artifact_sha256"].items():
            out.append({"name": name, "path": paths.get(name), "sha256": digest,
                        "bytes": sizes.get(name), "declared": False})
    if not out:
        raise ValueError("manifest lists no artifacts (expected 'artifacts', 'artifact' or "
                         "'artifact_sha256')")
    return out


def _is_hex64(s) -> bool:
    return isinstance(s, str) and len(s) == 64 and all(c in "0123456789abcdef" for c in s.lower())


def verify_manifest(manifest: str | Mapping, base_dir: str = REPO_ROOT,
                    paths: Mapping[str, str] | None = None) -> dict:
    """Recompute the SHA-256 (and byte size when listed) of every artifact the manifest lists.
    Paths DECLARED by a manifest must stay inside `base_dir`; paths passed via `paths` are
    explicit operator input and are used as given. Statuses: ok, sha_mismatch, bytes_mismatch,
    missing, unresolved (no path known), malformed (expected digest not 64 hex), unsafe_path."""
    if isinstance(manifest, str):
        with open(manifest, encoding="utf-8") as f:
            manifest = json.load(f)
    root = os.path.realpath(base_dir)
    checked = []
    for a in manifest_artifacts(manifest, paths):
        rec = {"name": a["name"], "path": a["path"], "expected_sha256": a["sha256"],
               "actual_sha256": None, "expected_bytes": a["bytes"], "actual_bytes": None}
        if not _is_hex64(a["sha256"]):
            rec["status"] = "malformed"
        elif not a["path"]:
            rec["status"] = "unresolved"
        else:
            full = a["path"] if (not a["declared"] and os.path.isabs(a["path"])) \
                else os.path.join(root, a["path"])
            real = os.path.realpath(full)
            if a["declared"] and os.path.commonpath([root, real]) != root:
                rec["status"] = "unsafe_path"
            elif not os.path.isfile(real):
                rec["status"] = "missing"
            else:
                rec["actual_sha256"] = sha256_file(real)
                rec["actual_bytes"] = os.path.getsize(real)
                if rec["actual_sha256"] != a["sha256"].lower():
                    rec["status"] = "sha_mismatch"
                elif a["bytes"] is not None and rec["actual_bytes"] != a["bytes"]:
                    rec["status"] = "bytes_mismatch"
                else:
                    rec["status"] = "ok"
        checked.append(rec)
    return {"check": "manifest", "ok": all(c["status"] == "ok" for c in checked),
            "artifacts": checked}


# ── (e) collision with protected / consumed sets ────────────────────────────
def check_protected_collisions(candidate: Rows, protected: Sequence[Mapping],
                               text_field: str = "input",
                               key_fn: Callable[[str], str] = canonical_key) -> dict:
    """Candidate rows whose text equals (exact) or canonicalises to (D16 canonical_key) a text of
    a protected set. Each protected entry: {"name", "text_field"?, and "rows" or "path"}. The
    result holds counts and CANDIDATE row indices only, never text of either side. Resolve a
    collision by dropping the candidate row; protected sets are immutable (D39)."""
    cand = _texts(candidate, text_field, "candidate")
    cand_canon = [key_fn(t) for t in cand]
    result = {}
    for p in protected:
        name = p["name"]
        field = p.get("text_field", text_field)
        rows = p["rows"] if "rows" in p else read_jsonl(p["path"])
        texts = _texts(rows, field, name)
        ex = set(texts)
        ca = {key_fn(t) for t in texts}
        ex_idx = [i for i, t in enumerate(cand) if t in ex]
        ca_idx = [i for i, k in enumerate(cand_canon) if k in ca]
        result[name] = {"protected_rows": len(texts),
                        "exact_collision_rows": len(ex_idx),
                        "canonical_collision_rows": len(ca_idx),
                        "candidate_row_indices": ca_idx}
    return {"check": "protected_collisions", "ok": all(
        v["canonical_collision_rows"] == 0 for v in result.values()),
        "candidate_rows": len(cand), "protected": result}


# ── CLI ─────────────────────────────────────────────────────────────────────
def _kv(items: Sequence[str], what: str) -> list[tuple[str, str]]:
    out = []
    for it in items:
        name, sep, rest = it.partition("=")
        if not sep or not name or not rest:
            raise ValueError(f"--{what} expects name=value, got {it!r}")
        out.append((name, rest))
    return out


def _load_splits(items: Sequence[str]) -> dict[str, list[dict]]:
    splits = {n: read_jsonl(p) for n, p in _kv(items, "split")}
    if len(splits) < 2:
        raise ValueError("need at least two --split name=path arguments")
    return splits


def main(argv: Sequence[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="V5 dataset checks (read-only)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add_splits(p):
        p.add_argument("--split", action="append", default=[], metavar="NAME=PATH")
        p.add_argument("--text-field", default="input")

    p = sub.add_parser("duplicates")
    add_splits(p)
    p.add_argument("--fail-on-within-exact", action="store_true")
    p = sub.add_parser("groups")
    add_splits(p)
    p.add_argument("--key", action="append", required=True,
                   help="field name, or f1+f2 for a composite key")
    p = sub.add_parser("labels")
    add_splits(p)
    p.add_argument("--label-field", default="label")
    p = sub.add_parser("manifest")
    p.add_argument("--manifest", required=True)
    p.add_argument("--base-dir", default=REPO_ROOT)
    p.add_argument("--path", action="append", default=[], metavar="NAME=PATH")
    p = sub.add_parser("collisions")
    p.add_argument("--candidate", required=True)
    p.add_argument("--text-field", default="input")
    p.add_argument("--protected", action="append", required=True, metavar="NAME=PATH[:FIELD]")
    args = ap.parse_args(argv)

    try:
        if args.cmd == "duplicates":
            res = find_duplicates(_load_splits(args.split), args.text_field,
                                  fail_on_within_exact=args.fail_on_within_exact)
        elif args.cmd == "groups":
            res = check_group_disjointness(_load_splits(args.split),
                                           [tuple(k.split("+")) for k in args.key])
        elif args.cmd == "labels":
            res = check_label_consistency(_load_splits(args.split), args.text_field,
                                          args.label_field)
        elif args.cmd == "manifest":
            res = verify_manifest(args.manifest, args.base_dir, dict(_kv(args.path, "path")))
        else:
            prot = []
            for name, rest in _kv(args.protected, "protected"):
                path, _, field = rest.partition(":")
                prot.append({"name": name, "path": path, **({"text_field": field} if field else {})})
            res = check_protected_collisions(read_jsonl(args.candidate), prot, args.text_field)
    except (ValueError, OSError) as e:
        print(f"FATAL: {e}", file=sys.stderr)
        return 3
    print(json.dumps(res, indent=2, sort_keys=True, ensure_ascii=False))
    return 0 if res["ok"] else 2


if __name__ == "__main__":
    sys.exit(main())
