#!/usr/bin/env python3
"""V5 stage 3 — split invariants SPL-1…SPL-9, the synthetic fixture and the CLI (issue #72).

Stdlib only, plus the stage-2/3 modules and the existing `v5_dataset_checks` (reused for duplicates
and group disjointness; never re-implemented). Every gate returns a JSON-serialisable dict with an
`ok` flag and counts; a gate never removes anything.

  SPL-1 order independence            spl1_order_independence (rebuild on shuffled inputs)
  SPL-2 PYTHONHASHSEED independence   spl2_hashseed_independence (fresh processes, other cwd)
  SPL-3 identity disjointness         gate_spl3 (assignment table; rows via check_group_disjointness)
  SPL-4 row membership                gate_spl4 (SplitAssignment.assert_row, asserted)
  SPL-5 identities only, no renderer  gate_spl5 (static import list of v5_split.py)
  SPL-6 exact / canonical duplicates  gate_spl6 (rows: text, payload, values; pools; attack records)
  SPL-7 E6 reserve never in a split   gate_spl7
  SPL-8 evaluability from counts      gate_spl8 (independent recomputation)
  SPL-9 cross-split near-duplicates   gate_spl9 (exact Jaccard >= 0.60 over pre-merge family keys)

CLI
  python3 scripts/dataset/v5_split_checks.py fixture     --out DIR
  python3 scripts/dataset/v5_split_checks.py determinism --out DIR
  python3 scripts/dataset/v5_split_checks.py census      --attack-pool P --benign-dir D --out FILE [--summary MD]

`fixture` and `determinism` use synthetic identities only. `census` reads the stage-2 pools and
writes COUNTS ONLY: it persists no split assignment of any real identity (the real split needs the
post-filter audit, the final deny-list, `names_family` and the preregistration first).
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import random
import subprocess
import sys
import tempfile
import unicodedata
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import v5_identities as I  # noqa: E402
import v5_pools_common as C  # noqa: E402
import v5_split as S  # noqa: E402
from v5_dataset_checks import canonical_key, check_group_disjointness, find_duplicates  # noqa: E402

CENSUS_SCHEMA = "v5-stage3-census/v3"     # v3: identity admissibility counts, hybrid I-8 flags, value policy B
CODE_FILES = ("v5_identities.py", "v5_split.py", "v5_split_checks.py", "v5_pools_common.py", "v5_dataset_checks.py")
STAGE2_OUTPUT_DIRS = ("attack", "benign", "raw")


def guard_output(path: str) -> str:
    """Refuse to write over stage-2 outputs or protected material."""
    real = os.path.realpath(path)
    for d in STAGE2_OUTPUT_DIRS:
        base = os.path.realpath(os.path.join(C.DEFAULT_OUT_DIR, d))
        if real == base or real.startswith(base + os.sep):
            raise SystemExit(f"REFUSED: {path} is inside the stage-2 output directory {d}/")
    C.assert_not_protected(path)
    return path


# ───────────────────────────── synthetic fixture (identities only; invented strings) ─────────────────────────────
def _letters(i: int, width: int = 4) -> str:
    out = []
    for _ in range(width):
        i, r = divmod(i, 26)
        out.append(chr(ord("a") + r))
    return "".join(reversed(out))


FIXTURE_CATEGORIES = (("fx_alpha", 400), ("fx_beta", 200), ("fx_gamma", 60), ("fx_delta", 2))
FIXTURE_SHARED = 10           # alpha families that also occur in fx_beta
FIXTURE_NATIVE = 6            # alpha families with a native held-out form (ENC-5)
FIXTURE_STRATA = (("form", 2), ("json", 7), ("query", 12))
FIXTURE_POOLS = (("fx_names", 250), ("fx_streets", 300))


def fixture_word(tag: str, i: int, width: int = 12) -> str:
    """Letters derived from sha256: distinct synthetic words share no 4-gram by construction, so
    families are not near-duplicates of each other unless a test makes them so."""
    return "".join(chr(ord("a") + int(c, 16)) for c in hashlib.sha256(f"{tag}|{i}".encode()).hexdigest()[:width])


def fixture_payload(cat: str, i: int, variant: int = 0) -> str:
    """Variants of one synthetic family differ by encoding, digit value and host only."""
    w = fixture_word(cat, i)
    if variant == 1:
        return f"fx {w} ({i % 7 + 1}) //hbase.example/".replace(" ", "%20")
    if variant == 2:
        return f"fx {w} ({i % 7 + 2}) //h{_letters(i, 3)}.example/"
    return f"fx {w} ({i % 7 + 3}) //hbase.example/"


def fixture_config(**over) -> dict:
    cfg = {
        "schema": S.SCHEMA_CONFIG, "salt": "v5-split-v1", "master_seed": "FIXTURE-ONLY-not-a-real-seed",
        "shares_percent": {"INTERNAL_TEST": 20, "VALIDATION": 10, "TRAIN": 70},
        "carrier_strata": [s for s, _ in FIXTURE_STRATA], "pools": [p for p, _ in FIXTURE_POOLS],
        "category_vocabulary": {"source": "stage2_dedup_scope", "order": "python_str_code_point",
                                "categories": [c for c, _ in FIXTURE_CATEGORIES]},
        "evaluability": {"min_families": 100, "min_internal_test_families": 30},
        "e6": {"reserve_percent": 8, "min_reserve_families": 30, "forced_overflow_policy": None},
        "value_min_per_split": 20, "near_duplicate_jaccard": "0.60",
        "pfid_rules_version": I.PFID_RULES_VERSION,
        "family_merges": [[I.payload_family_id(fixture_payload("fx_gamma", 3)),
                           I.payload_family_id(fixture_payload("fx_gamma", 4))]],
        "cluster_merges": [["fx-query-aaab", "fx-query-aaac"]],
        "cluster_share": {"warn": "0.02", "block": "0.05", "status": "PROPOSED"},
        "value_equivalence": I.VALUE_EQUIVALENCE,
        "value_pool_precedence": ["fx_names", "fx_streets"], "value_equivalence_semantic_notes": {},
    }
    cfg.update(over)
    return cfg


def fixture_template_decls() -> list:
    decls = []
    for stratum, ncl in FIXTURE_STRATA:
        for c in range(ncl):
            L = _letters(c)
            for t in range(1 + c % 3):
                sk = I.TemplateSkeleton(
                    method="GET" if stratum == "query" else "POST", carrier=stratum,
                    media_type=None if stratum == "query" else f"fx/{stratum}",
                    path=("fx", f"{stratum}-{L}", f"res-{L}-{_letters(t)}", f"leaf-{L}-{_letters(t)}"),
                    slots=(((0,), "string"), ((1,), "int"))[: 1 + t % 2])
                decls.append(I.TemplateDecl(I.template_id(sk), f"fx-{stratum}-{L}", stratum, I.template_tokens(sk)))
    return decls


def fixture_records() -> list:
    recs, n = [], 0
    for cat, count in FIXTURE_CATEGORIES:
        for i in range(count):
            for v in range(1 + i % 3):
                wire = fixture_payload(cat, i, v)
                native = ["double_encoding"] if cat == "fx_alpha" and i < FIXTURE_NATIVE else []
                scopes = [cat] + (["fx_beta"] if cat == "fx_alpha" and FIXTURE_NATIVE <= i < FIXTURE_NATIVE + FIXTURE_SHARED else [])
                for scope in scopes:
                    n += 1
                    recs.append({"record_id": f"fx{n:06d}", "status": C.ACCEPTED, "payload_wire": wire,
                                 "canonical_key": canonical_key(wire), "dedup_scope": scope, "native_forms": native})
    return recs


FIXTURE_VALUE_DUPLICATES = 2     # one case variant inside fx_names, one fx_names value repeated in fx_streets


def fixture_pool_values() -> dict:
    """Raw synthetic pools (before deduplication), with two deliberate equivalence duplicates."""
    pv = {pool: [f"{'O’' if i % 17 == 0 else ''}{pool[3:].capitalize()} {_letters(i)}" for i in range(n)]
          for pool, n in FIXTURE_POOLS}
    pv["fx_names"].append(pv["fx_names"][5].upper())
    pv["fx_streets"].append(pv["fx_names"][6])
    return pv


def pool_records(pool_values: dict) -> dict:
    return {p: [{"value": v, "value_entry_id": I.value_entry_id(p, v), "source_ref": f"{p}#{i}"}
                for i, v in enumerate(vs)] for p, vs in pool_values.items()}


def check_code_versions(cfg: dict) -> None:
    """The config must name the identity rules and the value equivalence this code implements."""
    if cfg["pfid_rules_version"] != I.PFID_RULES_VERSION:
        raise S.InvalidConfig(f"pfid_rules_version {cfg['pfid_rules_version']!r} != code {I.PFID_RULES_VERSION!r}")
    if cfg["value_equivalence"] != I.VALUE_EQUIVALENCE:
        raise S.InvalidConfig(f"value_equivalence {cfg['value_equivalence']!r} != code {I.VALUE_EQUIVALENCE!r}")


def fixture_inputs(cfg: dict | None = None) -> dict:
    cfg = cfg or fixture_config()
    check_code_versions(cfg)
    table = I.resolve_clusters(fixture_template_decls(), cfg["cluster_merges"])
    records = fixture_records()
    families = I.build_families(records, cfg["family_merges"])
    dedup = I.dedup_value_pools(pool_records(fixture_pool_values()), cfg["value_pool_precedence"],
                                cfg["value_equivalence_semantic_notes"])
    pool_values = {p: [r["value"] for r in rs] for p, rs in dedup["kept"].items()}
    values = {p: [r["value_entry_id"] for r in rs] for p, rs in dedup["kept"].items()}
    return {"config": cfg, "table": table, "records": records, "families": families,
            "pool_values": pool_values, "values": values, "value_dedup": dedup}


def pre_render_value_check(a: S.SplitAssignment, pool_values: dict) -> dict:
    """Owner ruling D-3: before anything is rendered, no exact (NFC) or equivalent (NFC + casefold)
    value group may span two splits. Raises StopBuild; returns the counts when clean."""
    g = gate_spl6(a, pool_values=pool_values)["pool_values"]
    if g["unassigned_values"] or g["exact_groups_spanning_splits"] or g["equivalent_groups_spanning_splits"]:
        raise S.StopBuild([{"code": "VALUE_EQUIVALENCE_SPANS_SPLITS", "detail": json.dumps(g, sort_keys=True)}])
    return g


def build_from(inputs: dict) -> S.SplitAssignment:
    return S.build(inputs["config"], inputs["table"], inputs["families"].values(), inputs["values"])


# ───────────────────────────── gates ─────────────────────────────
def _assignment_sha(a: S.SplitAssignment) -> str:
    return hashlib.sha256(S.assignment_bytes(a)).hexdigest()


def spl1_order_independence(raw: dict, permutations: int = 5) -> dict:
    """Rebuild from shuffled declarations, records, merge groups and pool values (fixed shuffle
    seeds); every assignment table must hash identically."""
    def run(shuffle_seed):
        rnd = random.Random(f"spl1|{shuffle_seed}")
        cfg = json.loads(json.dumps(raw["config"]))

        def sh(xs):
            xs = list(xs)
            if shuffle_seed is not None:
                rnd.shuffle(xs)
            return xs
        cfg["family_merges"] = [sh(g) for g in sh(cfg["family_merges"])]
        cfg["cluster_merges"] = [sh(g) for g in sh(cfg["cluster_merges"])]
        table = I.resolve_clusters(sh(raw["decls"]), cfg["cluster_merges"])
        fams = I.build_families(sh(raw["records"]), cfg["family_merges"])
        values = {p: sh(raw["values"][p]) for p in sh(raw["values"])}
        return _assignment_sha(S.build(cfg, table, sh(fams.values()), values))
    ref = run(None)
    shas = [run(k) for k in range(permutations)]
    return {"invariant": "SPL-1", "ok": all(s == ref for s in shas), "reference": ref,
            "permutations": permutations, "distinct": len(set(shas + [ref]))}


def spl2_hashseed_independence(seeds=("0", "1", "4242", "random"), script: str | None = None) -> dict:
    """Run a builder in fresh interpreters with different PYTHONHASHSEED values and working
    directories; its artifacts must be byte-identical. `script` (default: this module's `fixture`
    command) must accept `--out DIR` and write assignment.jsonl and manifest.json there; tests pass a
    deliberately seed-dependent builder to show the check fails (it never ships in production code)."""
    out = {}
    argv = [os.path.abspath(script)] if script else [os.path.abspath(__file__), "fixture", "--quiet"]
    with tempfile.TemporaryDirectory() as tmp:
        for k, seed in enumerate(seeds):
            od, cwd = os.path.join(tmp, f"out{k}"), os.path.join(tmp, f"cwd{k}")
            os.makedirs(cwd)
            env = dict(os.environ, PYTHONHASHSEED=seed)
            subprocess.run([sys.executable, *argv, "--out", od], cwd=cwd, env=env, check=True,
                           capture_output=True, timeout=600)
            out[seed] = {n: C.sha256_file(os.path.join(od, n)) for n in ("assignment.jsonl", "manifest.json")}
    first = next(iter(out.values()))
    return {"invariant": "SPL-2", "ok": all(v == first for v in out.values()), "runs": out,
            "distinct_assignments": len({v["assignment.jsonl"] for v in out.values()}),
            "python": sys.version.split()[0]}


ROW_REQUIRED = ("struct_cluster_id", "template_id", "pair_id")


def gate_spl3(a: S.SplitAssignment, rows=None) -> dict:
    """No identity in two splits. Table level: every cluster, template, family and value entry is in
    exactly one partition (the three splits' `partition()` plus E6 for families), and templates are
    in their cluster's partition. Row level: check_group_disjointness per identity kind; cluster,
    template and pair are required on every row (a missing one fails), value entries are exploded."""
    count = Counter()
    for split in S.SPLITS:
        p = a.partition(split)
        count.update(("cluster", c) for c in p.clusters)
        count.update(("template", t) for t in p.templates)
        count.update(("family", f) for f in {x for xs in p.families_by_category.values() for x in xs})
        count.update(("value", (pool, v)) for pool, vs in p.values_by_pool.items() for v in vs)
    count.update(("family", f) for f, s in a.families.items() if s == S.E6_RESERVE)
    expected = ([("cluster", c) for c in a.clusters] + [("template", t) for t in a.template_cluster]
                + [("family", f) for f in a.families] + [("value", k) for k in a.values])
    bad = [k for k in expected if count[k] != 1] + [k for k in count if k not in set(expected)]
    res = {"invariant": "SPL-3", "identities_not_in_exactly_one_partition": len(bad)}
    ok = not bad
    if rows is not None:
        by = defaultdict(list)
        for r in rows:
            by[r["split"]].append(r)
        checks = {k: check_group_disjointness(by, [k]) for k in ROW_REQUIRED}
        sub = {s: [r for r in rs if r.get("payload_family_id") is not None] for s, rs in by.items()}
        checks["payload_family_id"] = check_group_disjointness(sub, ["payload_family_id"])
        exploded = {s: [{"value_entry": f"{p}\0{v}"} for r in rs for p, v in r.get("value_entries", ())]
                    for s, rs in by.items()}
        checks["value_entry"] = check_group_disjointness(exploded, ["value_entry"])
        res["rows"] = {k: {"ok": v["ok"], "missing": v["keys"][k]["missing_rows"],
                           "intersections": {p: x["count"] for p, x in v["keys"][k]["intersections"].items()}}
                       for k, v in checks.items()}
        res["splits_with_rows"] = sorted(by)
        ok = ok and all(v["ok"] for v in checks.values())
    res["ok"] = ok
    return res


def gate_spl4(a: S.SplitAssignment, rows) -> dict:
    violations = []
    for i, r in enumerate(rows):
        try:
            a.assert_row(r)
        except S.SplitMembershipError as e:
            violations.append({"row": i, "violations": e.violations})
    return {"invariant": "SPL-4", "ok": not violations, "rows": len(rows),
            "rows_violating": len(violations), "examples": violations[:5]}


SPLIT_MODULE_ALLOWED_IMPORTS = {"__future__", "hashlib", "json", "os", "re", "collections", "dataclasses",
                                "fractions", "typing"}
FORBIDDEN_IMPORTS = {"canonical_request", "v5_tokenization", "v5_output_contract", "parse_dataset_v4",
                     "transformers", "torch", "v5_identities", "v5_dataset_checks"}


def module_imports(path: str) -> set:
    with open(path, encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom):
            names.add((node.module or "").split(".")[0])
    return names


def gate_spl5(path: str | None = None) -> dict:
    """The split module imports only the listed stdlib modules: no renderer, tokenizer, template,
    canonical_key or identity builder (assignment receives identities, never text)."""
    imports = module_imports(path or os.path.join(HERE, "v5_split.py"))
    ident = module_imports(os.path.join(HERE, "v5_identities.py"))
    return {"invariant": "SPL-5", "imports": sorted(imports),
            "unexpected": sorted(imports - SPLIT_MODULE_ALLOWED_IMPORTS),
            "identities_module_renderer_imports": sorted(ident & {"canonical_request", "v5_tokenization"}),
            "ok": imports <= SPLIT_MODULE_ALLOWED_IMPORTS and not (imports & FORBIDDEN_IMPORTS)
            and not (ident & {"canonical_request", "v5_tokenization"})}


def _groups_spanning(items, key_fn) -> list:
    """items: (split, value). Groups by key_fn(value) that span more than one split."""
    by = defaultdict(set)
    for split, v in items:
        by[key_fn(v)].add(split)
    return sorted(k for k, s in by.items() if len(s) > 1)


def gate_spl6(a: S.SplitAssignment, rows=None, pool_values=None, records=None) -> dict:
    """Exact and canonical duplicates stay in one split: full text, payload, value."""
    res, ok = {"invariant": "SPL-6"}, True
    if rows is not None:
        by = defaultdict(list)
        for r in rows:
            by[r["split"]].append(r)
        # every row needs its text, and its value strings aligned with its value entries: a row the
        # check cannot read is a failure, never a skip
        unreadable = sum(1 for r in rows if not isinstance(r.get("text"), str)
                         or len(r.get("values", ())) != len(r.get("value_entries", ())))
        d = find_duplicates({s: [r for r in rs if isinstance(r.get("text"), str)] for s, rs in by.items()},
                            text_field="text")
        res["rows_text"] = {"ok": d["ok"], "unreadable_rows": unreadable,
                            "canonical_shared": {k: v["canonical_shared_keys"] for k, v in d["across"].items()}}
        pay = {s: [r for r in rs if r.get("payload") is not None] for s, rs in by.items()}
        dp = find_duplicates(pay, text_field="payload")
        res["rows_payload"] = {"ok": dp["ok"], "canonical_shared": {k: v["canonical_shared_keys"] for k, v in dp["across"].items()}}
        vals = {s: [{"v": v} for r in rs for v in r.get("values", ())] for s, rs in by.items()}
        dx = find_duplicates(vals, text_field="v", key_fn=C.nfc)
        dc = find_duplicates(vals, text_field="v", key_fn=I.value_equivalence_key)
        res["rows_values"] = {"ok": dx["ok"] and dc["ok"]}
        ok = ok and not unreadable and d["ok"] and dp["ok"] and dx["ok"] and dc["ok"]
    if pool_values is not None:
        items, missing = [], 0
        for pool, vs in pool_values.items():
            for v in vs:
                s = a.values.get((pool, I.value_entry_id(pool, v)))
                if s is None:
                    missing += 1
                else:
                    items.append((s, v))
        exact = _groups_spanning(items, C.nfc)
        equiv = _groups_spanning(items, I.value_equivalence_key)
        res["pool_values"] = {"unassigned_values": missing, "exact_groups_spanning_splits": len(exact),
                              "equivalent_groups_spanning_splits": len(equiv), "equivalence": I.VALUE_EQUIVALENCE}
        ok = ok and not missing and not exact and not equiv
    if records is not None:
        fam_of = _family_of_payload(a)
        items = [(a.families[fam_of[I.payload_family_id(r["payload_wire"])]], r["payload_wire"]) for r in records]
        exact = _groups_spanning(items, lambda x: x)
        canon = _groups_spanning(items, canonical_key)
        res["attack_records"] = {"exact_groups_spanning": len(exact), "canonical_groups_spanning": len(canon)}
        ok = ok and not exact and not canon
    res["ok"] = ok
    return res


def _family_of_payload(a: S.SplitAssignment) -> dict:
    root = {}
    for f, keys in a.family_member_keys.items():
        for k in keys:
            root[k] = f
    return root


def gate_spl7(a: S.SplitAssignment, rows=None) -> dict:
    """No reserve family in a partition or a row. A row carrying an attack payload must name the
    family its payload belongs to (recomputed), so a mislabelled or unlabelled reserve payload fails."""
    reserve = {p for p, s in a.families.items() if s == S.E6_RESERVE}
    leaked = []
    for split in S.SPLITS:
        part = a.partition(split)
        leaked += [p for ps in part.families_by_category.values() for p in ps if p in reserve]
    root = _family_of_payload(a)
    row_hits, mislabelled = [], []
    for i, r in enumerate(rows or ()):
        pf = r.get("payload_family_id")
        if r.get("payload") is not None:
            actual = root.get(I._family_key(r["payload"]))
            if actual != pf:
                mislabelled.append(i)
            pf = actual if actual is not None else pf
        if pf in reserve:
            row_hits.append(i)
    return {"invariant": "SPL-7", "ok": not leaked and not row_hits and not mislabelled, "reserve": len(reserve),
            "reserve_in_partitions": len(leaked), "rows_with_reserve_family": len(row_hits),
            "rows_payload_family_mismatch": len(mislabelled),
            "note": "near-duplicates between reserve and split families are checked by SPL-9 (E6 is a partition there)"}


def gate_spl8(a: S.SplitAssignment) -> dict:
    """Recompute every category's flag from the assignment table alone and compare."""
    ev, by_cat = S.FROZEN["evaluability"], defaultdict(Counter)
    for r in a.assignment_records():
        if r["kind"] == "payload_family":
            for c in r["categories"]:
                by_cat[c][r["split"]] += 1
    mismatches = []
    for c, cnt in sorted(by_cat.items()):
        total = sum(cnt[s] for s in S.SPLITS)
        flag = S.EVALUABLE if total >= ev["min_families"] and cnt[S.INTERNAL_TEST] >= ev["min_internal_test_families"] else S.NOT_EVALUABLE
        if a.evaluability[c]["flag"] != flag:
            mismatches.append(c)
    # I-8 (hybrid): the step-2 outcome uses the same counts, so it may not contradict the final flag
    diverging = sorted(c for c, d in a.outcome_vs_flag().items() if d["diverges"])
    return {"invariant": "SPL-8", "ok": not mismatches and not diverging and set(by_cat) == set(a.evaluability),
            "categories": len(by_cat), "mismatches": mismatches, "outcome_flag_divergences": diverging}


def gate_spl9(a: S.SplitAssignment) -> dict:
    """0 near-duplicate family pairs (Jaccard >= 0.60 between 4-gram sets of pre-merge family keys)
    whose families are in different partitions (TRAIN / VALIDATION / INTERNAL_TEST / E6_RESERVE).
    Keys shorter than 4 code points cannot be compared: the gate does not pass while any exists
    (status BLOCKED_UNOBSERVABLE: an open owner decision, never a silent pass)."""
    fams = {p: I.Family(p, a.fams[p].categories, a.fams[p].native_forms, (), a.family_member_keys[p])
            for p in a.families}
    pairs = I.family_near_duplicate_pairs(fams, a.families)
    short = I.unobservable_keys(fams)
    status = "FAIL" if pairs else "BLOCKED_UNOBSERVABLE" if short else "PASS"
    return {"invariant": "SPL-9", "ok": status == "PASS", "status": status,
            "cross_partition_family_pairs": len(pairs), "examples": pairs[:5],
            "pre_merge_keys": sum(len(k) for k in a.family_member_keys.values()),
            "unobservable_keys": short, "representation": I.NEAR_DUP_REPRESENTATION,
            "explicit_merges": len(a.family_merges)}


def run_gates(a, rows=None, pool_values=None, records=None) -> dict:
    gates = [gate_spl3(a, rows), gate_spl5(), gate_spl6(a, rows, pool_values, records),
             gate_spl7(a, rows), gate_spl8(a), gate_spl9(a)]
    if rows is not None:
        gates.insert(1, gate_spl4(a, rows))
    return {g["invariant"]: g for g in gates}


# ───────────────────────────── CLI: fixture / determinism ─────────────────────────────
def cmd_fixture(args) -> int:
    guard_output(args.out)
    py = C.check_python()
    inp = fixture_inputs()
    a = build_from(inp)
    pre_render = pre_render_value_check(a, inp["pool_values"])          # StopBuild before anything renders
    gates = run_gates(a, pool_values=inp["pool_values"], records=inp["records"])
    code = C.code_fingerprint(os.path.join(HERE, f) for f in CODE_FILES)
    vd = inp["value_dedup"]
    extra = {"fixture": "SYNTHETIC identities only (invented strings); not a dataset",
             "pfid_rules_version": I.PFID_RULES_VERSION, "near_duplicate_representation": I.NEAR_DUP_REPRESENTATION,
             "value_deduplication": {"equivalence": vd["equivalence"], "groups": vd["groups"],
                                     "semantic_notes_applied": vd["semantic_notes_applied"],
                                     "excluded": vd["excluded"]},
             "pre_render_value_check": pre_render,
             "gates": gates, "code_sha256": code, "python_check": {k: py[k] for k in ("verified_minors", "verified")}}
    hashes = S.write_assignment(a, args.out, extra)
    if not args.quiet:
        print(json.dumps({"out": args.out, **hashes, "gates_ok": {k: g["ok"] for k, g in gates.items()}}, indent=2))
    return 0 if all(g["ok"] for g in gates.values()) else 2


def cmd_determinism(args) -> int:
    inp = fixture_inputs()
    raw = {"config": inp["config"], "decls": fixture_template_decls(), "records": inp["records"],
           "values": inp["values"]}
    res = {"SPL-1": spl1_order_independence(raw), "SPL-2": spl2_hashseed_independence()}
    os.makedirs(args.out, exist_ok=True)
    C.write_json(os.path.join(args.out, "determinism.json"), res)
    print(json.dumps({k: {"ok": v["ok"]} for k, v in res.items()}, indent=2))
    return 0 if all(v["ok"] for v in res.values()) else 2


# ───────────────────────────── CLI: census (real pools, counts only) ─────────────────────────────
BENIGN_POOLS = ("names_given", "names_family", "prose_en", "streets", "symbols")
# RATIFIED by D68 (DR-75, 2026-10-21) for these five examined pools ONLY; it assigns precedence to no
# further pool (passwords, urls_*, rel_paths, addr_data stay unratified, and a real build that configures
# them must get their precedence ruled too). Option B: names_family outranks names_given. The order only
# redistributes representatives (the A/B swap moves 782 between the two name pools); total unique coverage
# is invariant — 84,252 kept / 849 excluded either way — so it is not a security-performance claim.
# `symbols > names_given` (the D64 §3 analysis-backed candidate) is preserved. Ratifying this does not
# authorize a real split, a dataset freeze or training. Evidence:
# reports/v5/data-readiness/names_family-integration/README.md.
REAL_VALUE_PRECEDENCE = ["symbols", "streets", "names_family", "names_given", "prose_en"]
# Owner ruling, stage 3 round 3 (policy B): the round-2 hold is removed; NFC + casefold applies to every
# group. `wasps` (smallest value_entry_id) is kept; `WASPs` is excluded with this recorded difference.
REAL_VALUE_SEMANTIC_NOTES = {
    "i'm terrified of wasps.": "not synonyms: 'wasps' is the insect, 'WASPs' the acronym (White Anglo-Saxon "
                               "Protestants); excluded only by the NFC + casefold equivalence policy that keeps "
                               "equivalent values out of two splits"}
# I-7 (ratified): stage-2 `dedup_scope` vocabulary of the ML-trained categories (spec §2.3), recorded explicitly
REAL_CATEGORY_VOCABULARY = ["CRLF Injection", "Command Injection", "NoSQL Injection", "Open Redirect", "SQL Injection",
                            "Server Side Request Forgery", "Server Side Template Injection", "XPath Injection",
                            "XSS Injection", "path_file_access"]


def _hist(sizes, n_families):
    bins = (("2", 2, 2), ("3-5", 3, 5), ("6-10", 6, 10), ("11-50", 11, 50), ("51-100", 51, 100), (">100", 101, 10 ** 9))
    out = {"1": n_families - sum(sizes)}
    out.update({name: sum(1 for x in sizes if lo <= x <= hi) for name, lo, hi in bins})
    return out


def _internal_jaccard(keys):
    sh = {k: I.payload_shingles(k) for k in keys}
    ks = sorted(keys)
    pairs = [(ks[i], ks[j]) for i in range(len(ks)) for j in range(i + 1, len(ks))]
    if len(pairs) > 50000:
        rnd = random.Random("census-internal")
        pairs = [tuple(rnd.sample(ks, 2)) for _ in range(50000)]
    js = sorted(len(sh[a] & sh[b]) / len(sh[a] | sh[b]) for a, b in pairs if sh[a] | sh[b])
    if not js:
        return None, None
    return round(js[len(js) // 2], 3), round(sum(1 for j in js if j < 0.3) / len(js), 3)


def _projection(assign, report, fx) -> dict:
    """Per category: the step-2 outcome (hybrid I-8), the cuts of its own stratum, the foreign families
    counted, and the final SPL-8 flag from counts. Counts only."""
    ev = S.category_evaluability(fx, assign)
    out = {}
    for c, r in report.items():
        out[c] = {k: r[k] for k in ("n", "R", "outcome", "reserve_size", "INTERNAL_TEST", "VALIDATION", "TRAIN")}
        out[c].update(foreign_counted=r["foreign"]["in_splits"], final_flag=ev[c]["flag"],
                      families_counted=ev[c]["families_in_splits"], internal_test_counted=ev[c]["INTERNAL_TEST"])
    return out


def census(attack_pool: str, benign_dir: str, precedence=None, semantic_notes=None, vocabulary=None) -> dict:
    precedence = precedence or REAL_VALUE_PRECEDENCE
    vocabulary = vocabulary or REAL_CATEGORY_VOCABULARY
    semantic_notes = REAL_VALUE_SEMANTIC_NOTES if semantic_notes is None else semantic_notes
    C.assert_not_protected(attack_pool)
    C.assert_not_protected(benign_dir)
    all_records = C.read_jsonl(attack_pool)
    empty = [r for r in all_records if not I._family_key(r["payload_wire"])]
    records = [r for r in all_records if I._family_key(r["payload_wire"])]
    fams = I.build_families(records)
    cats = sorted({c for f in fams.values() for c in f.categories})
    res = {"schema": CENSUS_SCHEMA, "status": "DIAGNOSTIC — counts only; no split persisted; pool PENDING_ADJUDICATION",
           "inputs": {"attack_pool_sha256": C.sha256_file(attack_pool), "attack_records": len(all_records)},
           "pfid_rules_version": I.PFID_RULES_VERSION, "near_duplicate_representation": I.NEAR_DUP_REPRESENTATION,
           "records_with_empty_family_key": [{"record_id": r["record_id"], "category": r["dedup_scope"]} for r in empty]}
    excluded_path = os.path.join(os.path.dirname(attack_pool), "attack_excluded.jsonl")
    if os.path.exists(excluded_path):                 # stage-2 ledger: identity-related exclusions (counts only)
        ex = Counter(r["exclusion_reason"] for r in C.read_jsonl(excluded_path)
                     if r["exclusion_reason"].startswith(("identity_", "not_a_payload:")))
        res["inputs"]["attack_excluded_sha256"] = C.sha256_file(excluded_path)
        res["attack_identity_exclusions"] = dict(sorted(ex.items()))
    occ = Counter(c for f in fams.values() for c in f.categories)
    strat = Counter(f.stratum_category for f in fams.values())
    v1 = defaultdict(set)
    for r in records:
        v1[r["dedup_scope"]].add(I._family_key(r["payload_wire"], per_digit=True, redirect_forms=False))
    nfc_changed = sum(1 for r in records
                      if I._family_key(unicodedata.normalize("NFC", r["payload_wire"])) != I._family_key(r["payload_wire"]))
    res["families"] = {
        "records_whose_key_changes_if_nfc_applied_first": nfc_changed,      # I-19 stability check
        "total": len(fams), "multi_category": sum(1 for f in fams.values() if len(f.categories) > 1),
        "with_native_held_out_form": sum(1 for f in fams.values() if f.native_forms),
        "per_category": {c: {"records": sum(1 for r in records if r["dedup_scope"] == c), "families_occurring": occ[c],
                             "families_stratum": strat[c], "families_under_v1_rules": len(v1.get(c, ()))} for c in cats}}
    assign, report, fx = S.assign_families(fams.values(), policy=None, vocabulary=vocabulary)
    res["projection_before_merges"] = _projection(assign, report, fx)
    pairs = I.family_near_duplicate_pairs(fams)
    comps = I.propose_merges(pairs)
    sizes = sorted((len(c) for c in comps), reverse=True)
    own = {}
    for c in comps:
        for cat, n in Counter(fams[x].stratum_category for x in c).items():
            own[cat] = max(own.get(cat, 0), n)
    top = []
    for c in sorted(comps, key=lambda c: (-len(c), c[0]))[:10]:
        keys = [k for x in c for k in fams[x].merged_from]
        med, low = _internal_jaccard(keys)
        top.append({"size": len(c), "categories": dict(Counter(fams[x].stratum_category for x in c).most_common()),
                    "shortest_member": min(c, key=lambda k: (len(k), k))[:60],
                    "internal_median_jaccard": med, "internal_pairs_below_0_3": low})
    unobs = I.unobservable_keys(fams)
    res["near_duplicates"] = {
        "family_pairs_jaccard_ge_0_60": len(pairs), "union_find_components": len(comps),
        "families_in_components": sum(sizes), "units_after_merge_histogram": _hist(sizes, len(fams)),
        "top10_components": top,
        "largest_component_own_share": {c: f"{own.get(c, 0)}/{strat[c]}" for c in sorted(strat)},
        "cross_category_pairs": sum(1 for x, y in pairs if fams[x].stratum_category != fams[y].stratum_category),
        "unobservable_keys": [{"key": k, "stratum": fams[k].stratum_category if k in fams else None} for k in unobs]}
    merged = I.build_families(records, comps)
    massign, mreport, mfx = S.assign_families(merged.values(), policy=None, vocabulary=vocabulary)
    mfams = {p: I.Family(p, f.categories, f.native_forms, (), merged[p].merged_from) for p, f in mfx.items()}
    res["projection_if_all_proposed_merges"] = {
        "families": len(merged), "largest_merged_family_members": max(len(f.merged_from) for f in merged.values()),
        "cross_partition_near_duplicate_pairs": len(I.family_near_duplicate_pairs(mfams, massign)),
        "unobservable_keys": len(I.unobservable_keys(mfams)),
        "per_stratum_category": _projection(massign, mreport, mfx)}
    # value pools: equivalence groups, deduplication ledger, concept loss
    man_path = os.path.join(benign_dir, "manifest.json")
    res["inputs"]["benign_manifest_sha256"] = C.sha256_file(man_path) if os.path.exists(man_path) else None
    raw = {}
    for pool in BENIGN_POOLS:
        path = os.path.join(benign_dir, f"{pool}.jsonl")
        if os.path.exists(path):
            raw[pool] = C.read_jsonl(path)
    groups = defaultdict(list)
    for pool, rs in raw.items():
        for r in rs:
            groups[I.value_equivalence_key(r["value"])].append(pool)
    multi = [ps for ps in groups.values() if len(ps) > 1]
    dedup = I.dedup_value_pools(raw, precedence, semantic_notes)      # an unknown key raises, as in the builder
    vp = {}
    for pool in BENIGN_POOLS:
        if pool not in raw:
            vp[pool] = {"status": "BLOCKED (no pool file)"}
            continue
        before, after = raw[pool], dedup["kept"][pool]
        fb = Counter(f for r in before for f in r.get("flags", []))
        fa = Counter(f for r in after for f in r.get("flags", []))
        t, v, tr = S.cuts(len(after))
        vp[pool] = {"n_before": len(before), "n_after": len(after),
                    "excluded": sum(1 for e in dedup["excluded"] if e["pool_id"] == pool),
                    "flag_loss": {f: f"{fb[f] - fa[f]}/{fb[f]}" for f in sorted(fb) if fb[f] != fa[f]},
                    "projected_cuts_after": {S.INTERNAL_TEST: t, S.VALIDATION: v, S.TRAIN: tr},
                    "meets_minimum_20": min(t, v, tr) >= S.FROZEN["value_min_per_split"]}
    res["values"] = {
        "equivalence": I.VALUE_EQUIVALENCE, "precedence_PROPOSED": precedence,
        "semantic_notes": len(dedup["semantic_notes_applied"]),
        "excluded_by_reason": dict(sorted(Counter(e["exclusion_reason"] for e in dedup["excluded"]).items())),
        "policy_exclusions": [{"pool_id": e["pool_id"], "value_entry_id": e["value_entry_id"],
                               "representative_value_entry_id": e["representative"]["value_entry_id"],
                               "synonym": e["synonym"]} for e in dedup["excluded"] if "synonym" in e],
        "groups": len(multi), "groups_within_one_pool": dict(sorted(Counter(ps[0] for ps in multi if len(set(ps)) == 1).items())),
        "groups_across_pools": dict(sorted(Counter("+".join(sorted(set(ps))) for ps in multi if len(set(ps)) > 1).items())),
        "excluded_total": len(dedup["excluded"]), "per_pool": vp}
    return res


def census_summary(res: dict) -> str:
    fam, nd, pm, vals = res["families"], res["near_duplicates"], res["projection_if_all_proposed_merges"], res["values"]
    L = ["# V5 stage 3 — real-pool census (counts only, generated)", "",
         f"Status: {res['status']}.", "",
         f"- Attack pool sha256 `{res['inputs']['attack_pool_sha256']}`, {res['inputs']['attack_records']} records; "
         f"rules `{res['pfid_rules_version']}`; SPL-9 representation: {res['near_duplicate_representation']}.",
         f"- Records with an empty family key: {len(res['records_with_empty_family_key'])}. Stage-2 identity exclusions "
         f"(EXCLUDED, in the reconciliation ledger): {res.get('attack_identity_exclusions', 'n/a')}.",
         f"- Families: {fam['total']}; multi-category {fam['multi_category']}; with a native held-out form "
         f"{fam['with_native_held_out_form']}; records whose family key would change if NFC were applied first "
         f"(I-19): {fam['records_whose_key_changes_if_nfc_applied_first']}.", "",
         "| Category (stage-2 `dedup_scope`) | Records | Families (occurring) | Families (stratum) | Families under v1 rules |",
         "|---|---:|---:|---:|---:|"]
    for c, v in fam["per_category"].items():
        L.append(f"| {c} | {v['records']} | {v['families_occurring']} | {v['families_stratum']} | {v['families_under_v1_rules']} |")

    def proj(title, rows):
        out = ["", title, "", "| Stratum category | n | R | Outcome | Reserve | TEST | VAL | TRAIN | Foreign counted | Families / TEST counted | Final flag |",
               "|---|---:|---:|---|---:|---:|---:|---:|---:|---|---|"]
        for c, r in rows.items():
            out.append(f"| {c} | {r['n']} | {r['R']} | {r['outcome']} | {r['reserve_size']} | {r['INTERNAL_TEST']} | "
                       f"{r['VALIDATION']} | {r['TRAIN']} | {r['foreign_counted']} | {r['families_counted']} / "
                       f"{r['internal_test_counted']} | {r['final_flag']} |")
        return out
    L += proj("## Step-2 projection before any merge (counts; nothing persisted)", res["projection_before_merges"])
    L += ["", "## Near-duplicate families (SPL-9 representation, Jaccard ≥ 0.60, all families, no split)", "",
          f"- Family pairs: {nd['family_pairs_jaccard_ge_0_60']} ({nd['cross_category_pairs']} across stratum categories); "
          f"components: {nd['union_find_components']}, holding {nd['families_in_components']} families.",
          f"- Units after merging every component, by size: {nd['units_after_merge_histogram']}.",
          f"- Unobservable keys (shorter than 4 code points; SPL-9 cannot compare them, gate BLOCKED_UNOBSERVABLE while any "
          f"exists): {len(nd['unobservable_keys'])}"
          + (" — " + ", ".join(f"`{u['key']}` ({u['stratum']})" for u in nd["unobservable_keys"]) if nd["unobservable_keys"]
             else " (the stage-2 records that had one are EXCLUDED upstream, owner ruling round 3)") + ".", "",
          "| # | Size | Stratum categories | Shortest member | Internal median J | Internal pairs < 0.3 |", "|---:|---:|---|---|---:|---:|"]
    for i, c in enumerate(nd["top10_components"], 1):
        L.append(f"| {i} | {c['size']} | {c['categories']} | `{c['shortest_member']}` | {c['internal_median_jaccard']} | "
                 f"{c['internal_pairs_below_0_3']} |")
    L += ["", "Largest component, own stratum families / stratum families: "
          + ", ".join(f"{c} {v}" for c, v in nd["largest_component_own_share"].items()) + "."]
    L += proj(f"## Step-2 projection if every proposed component became an explicit merge ({pm['families']} families; "
              f"largest merged family = {pm['largest_merged_family_members']} pre-merge families; cross-partition "
              f"near-duplicate pairs {pm['cross_partition_near_duplicate_pairs']}; unobservable keys {pm['unobservable_keys']})",
              pm["per_stratum_category"])
    L += ["", f"## Value pools (equivalence `{vals['equivalence']}` on every group, no hold; precedence PROPOSED)", "",
          f"- Equivalence groups: {vals['groups']} (within one pool {vals['groups_within_one_pool']}; across pools "
          f"{vals['groups_across_pools']}); excluded: {vals['excluded_total']} {vals['excluded_by_reason']}.",
          f"- Groups with a recorded semantic difference (not synonyms; excluded by policy): {vals['semantic_notes']} — "
          + ", ".join(f"{e['pool_id']} `{e['value_entry_id'][:16]}` (kept `{e['representative_value_entry_id'][:16]}`)"
                      for e in vals["policy_exclusions"]) + ".",
          f"- Precedence (PROPOSED): {vals['precedence_PROPOSED']}.", "",
          "| Pool | Before | After | Excluded | Flag loss (lost/before) | TEST / VAL / TRAIN after | ≥ 20 each |",
          "|---|---:|---:|---:|---|---|---|"]
    for p, v in vals["per_pool"].items():
        if "n_before" not in v:
            L.append(f"| {p} | — | — | — | — | — | {v['status']} |")
            continue
        c = v["projected_cuts_after"]
        L.append(f"| {p} | {v['n_before']} | {v['n_after']} | {v['excluded']} | {v['flag_loss'] or '—'} | "
                 f"{c['INTERNAL_TEST']} / {c['VALIDATION']} / {c['TRAIN']} | {v['meets_minimum_20']} |")
    return "\n".join(L) + "\n"


def cmd_census(args) -> int:
    guard_output(args.out)
    if args.summary:
        guard_output(args.summary)
    py = C.check_python()
    res = census(args.attack_pool, args.benign_dir)
    res["python_check"] = {k: py[k] for k in ("verified_minors", "verified")}
    res["code_sha256"] = C.code_fingerprint(os.path.join(HERE, f) for f in CODE_FILES)
    digest = C.write_json(args.out, res)
    if args.summary:
        with open(args.summary, "w", encoding="utf-8") as fh:
            fh.write(census_summary(res))
    print(json.dumps({"out": args.out, "sha256": digest}, indent=2))
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    f = sub.add_parser("fixture")
    f.add_argument("--out", required=True)
    f.add_argument("--quiet", action="store_true")
    d = sub.add_parser("determinism")
    d.add_argument("--out", required=True)
    c = sub.add_parser("census")
    c.add_argument("--attack-pool", default=os.path.join(C.DEFAULT_OUT_DIR, "attack", "attack_pool.jsonl"))
    c.add_argument("--benign-dir", default=os.path.join(C.DEFAULT_OUT_DIR, "benign"))
    c.add_argument("--out", default=os.path.join(C.DEFAULT_OUT_DIR, "stage3", "census.json"))
    c.add_argument("--summary", default=None)
    args = ap.parse_args(argv)
    return {"fixture": cmd_fixture, "determinism": cmd_determinism, "census": cmd_census}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
