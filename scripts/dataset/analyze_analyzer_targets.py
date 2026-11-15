"""
firewall-IA — Analyzer target and dataset analysis (Hybrid Architecture Phase 2A, Issue #51).

Read-only analysis of `datasets/v4_clean/` that answers, with numbers, what the
Lightweight Request Analyzer could be trained to predict from `RequestFeatures` v2:

  schema       fields, label format, what the label text encodes
  distribution decisions and categories per split, absent and scarce categories
  labels       single- vs multi-label structure; multi-category payloads in the
               original sources (PayloadsAllTheThings directories, CSIC keyword rules)
  provenance   source and request shape inferred from the path (OFFLINE ONLY: used to
               measure construction shortcuts, never as an Analyzer input)
  features     RequestFeatures v2 typing; feature-space duplicates and label conflicts,
               per category; percent-encoding vs raw syntax per category
  shortcuts    single categorical feature / path -> label lookups (E0-style)
  split        cross-split overlap at the level the Analyzer sees (surface, canonical
               surface, feature vector)
  frozen design consequences of the approved Phase 2A design (D46-D51): target counts
               under the reason -> analyzer-category mapping, the grouped VALIDATION
               carve-out under two candidate group definitions, and the two INTERNAL
               TEST views. Nothing is written except this report.

It trains nothing, writes no dataset and never reads External Test v1. The V4 split
is used as frozen; its SHA-256 is verified against the manifest first.

RUN (repository root, ML environment; needs ~/PayloadsAllTheThings at the manifest's
commit for the source-collision section, which is skipped with a note otherwise):
    python3.12 scripts/dataset/analyze_analyzer_targets.py \
        --out reports/hybrid/phase2a-analyzer-design/analysis.json
"""

import argparse
import ast
import dataclasses
import hashlib
import inspect
import json
import os
import subprocess
import sys
from collections import Counter, defaultdict
from urllib.parse import unquote_plus

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO_ROOT, "data_plane"))
sys.path.insert(0, os.path.join(REPO_ROOT, "scripts", "dataset"))

import parse_dataset_v4 as gen  # noqa: E402  (read-only: constants and pure helpers)
import request_features as rf  # noqa: E402

DATA = os.path.join(REPO_ROOT, "datasets", "v4_clean")
MANIFEST = os.path.join(REPO_ROOT, "datasets", "manifest_v4_clean.json")
# E0 thresholds (check_dataset.py) for a deterministic reveal; D19 eval-support floor.
PURITY, COVERAGE, EVAL_SUPPORT_FLOOR = 0.99, 0.01, 30
CATEGORICAL = ("method", "content_type", "body_format")
# Runtime features with few distinct values in V4-clean that could stand in for the
# synthetic endpoint (path identity), which is construction metadata.
PATH_PROXIES = ("path_length", "path_depth")

# ── Frozen Phase 2A design (D47, D48, D49, D51) ──────────────────────────────
# V4 category (the reason's generator category) -> Analyzer category. Every other
# BLOCK category maps to the residual bucket "other_attack"; JWT is not a target.
ANALYZER_CATEGORY = {
    "SQL Injection": "sql_injection",
    "XSS Injection": "xss",
    "Directory Traversal": "path_file_access",
    "File Inclusion": "path_file_access",
    "Command Injection": "command_injection",
    "Server Side Template Injection": "ssti",
    "Open Redirect": "open_redirect",
    "Server Side Request Forgery": "ssrf",
}
UNSUPPORTED = {"JSON Web Token": "unsupported_jwt"}   # excluded from fitting (D48)
VALIDATION_SALT = "hybrid-analyzer-v1-validation"
VALIDATION_FRACTION = 0.20


def analyzer_target(category):
    """(target_attack, target_category, slice) of a V4 category under D47-D49."""
    if category == "BENIGN":
        return 0, None, None
    if category in UNSUPPORTED:
        return 1, None, UNSUPPORTED[category]
    return 1, ANALYZER_CATEGORY.get(category, "other_attack"), None


def in_validation(group_key):
    """Deterministic group -> VALIDATION assignment: a SHA-256 bucket over a fixed
    salt, the same mechanism as D16; independent of order and PYTHONHASHSEED."""
    h = hashlib.sha256(f"{VALIDATION_SALT}\x00{group_key}".encode()).digest()
    return int.from_bytes(h[:8], "big") % 10_000 < int(VALIDATION_FRACTION * 10_000)


# ── loading ─────────────────────────────────────────────────────────────────
def load(manifest):
    rows = []
    for split in ("train", "eval"):
        path = os.path.join(DATA, f"{split}.jsonl")
        raw = open(path, "rb").read()
        digest = hashlib.sha256(raw).hexdigest()
        if digest != manifest["artifact_sha256"][split]:
            raise SystemExit(f"FATAL: {path} SHA-256 {digest} != manifest")
        for line in raw.decode("utf-8").splitlines():
            r = json.loads(line)
            r["split"] = split
            rows.append(r)
    return rows


def parse_text(text):
    """method, path, query, content type, body of a D1 text (same layout rules
    as request_features)."""
    head, _, body = text.partition("\n\n")
    request_line, *headers = head.split("\n")
    method, _, rest = request_line.partition(" ")
    target = rest.rpartition(" ")[0] if " " in rest else rest
    path, _, query = target.partition("?")
    ctype = ""
    for h in headers:
        name, _, value = h.partition(":")
        if name.strip().lower() == "content-type":
            ctype = value.split(";", 1)[0].strip().lower()
            break
    return method, path, query, ctype, body


# ── label structure in the original sources ─────────────────────────────────
def patt_collisions():
    """Canonical payload keys that occur under more than one category in the
    sources, before the generator keeps only the first one seen."""
    head = subprocess.run(["git", "-C", gen.PAYLOADS_REPO, "rev-parse", "HEAD"],
                          capture_output=True, text=True).stdout.strip()
    expected = json.load(open(MANIFEST))["payloadsallthethings_commit"]
    if head != expected:
        return {"skipped": f"{gen.PAYLOADS_REPO} at {head or 'missing'}, manifest {expected}"}
    stats = {"reject_reasons": Counter(), "candidates_per_category": Counter()}
    cats = defaultdict(set)
    for rec in gen.extract_sources(stats) + gen.build_hardcoded_sources():
        key = rec["payload"] if rec.get("structural") else gen.canonical_key(rec["payload"])
        cats[key].add(rec["category"])
    multi = {k: v for k, v in cats.items() if len(v) > 1}
    pairs = Counter(tuple(sorted(v)) for v in multi.values())
    first_wins = Counter(sorted(v)[0] for v in multi.values())
    return {"payloadsallthethings_commit": head,
            "unique_canonical_payloads": len(cats),
            "payloads_in_more_than_one_category": len(multi),
            "share": len(multi) / len(cats),
            "category_sets": {" + ".join(k): n for k, n in pairs.most_common()},
            "label_kept_by_generator (first in sorted order)": dict(first_wins.most_common())}


def csic_rule_families():
    """(reason, keywords) of each rule in parse_dataset_v4.csic_category, read
    from its source so this analysis cannot drift from the generator."""
    tree = ast.parse(inspect.getsource(gen.csic_category))
    rules = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.If) and isinstance(node.test, ast.Call)
                and getattr(node.test.func, "id", "") == "has"
                and isinstance(node.body[0], ast.Return)):
            rules.append((node.body[0].value.value, ast.literal_eval(node.test.args[0])))
    return rules


def csic_multi_match(csic_block_rows, rules):
    """How many CSIC-derived BLOCK rows match more than one keyword family.
    The generator keeps the first match only."""
    n_match = Counter()
    combos = Counter()
    first_agrees = 0
    for r in csic_block_rows:
        m, p, q, _, body = r["_parsed"]
        probe = f"{m} {p}?{q}\n{body}"
        s, dec = probe.lower(), unquote_plus(probe).lower()
        hits = [reason for reason, kws in rules if any(k in s or k in dec for k in kws)]
        n_match[len(hits)] += 1
        if len(hits) > 1:
            combos[" + ".join(h.split(" payload")[0].split(" attack")[0] for h in hits)] += 1
        first_agrees += bool(hits) and hits[0] == r["reason"]
    return {"rows": len(csic_block_rows),
            "rule_families_matched": {str(k): v for k, v in sorted(n_match.items())},
            "first_match_equals_label": first_agrees,
            "multi_family_combinations": dict(combos.most_common(12))}


# ── shortcuts ───────────────────────────────────────────────────────────────
def lookup(train, evals, key, target):
    """E0-style single-variable lookup: majority target per value, fit on train,
    scored on eval; plus values that reveal one target almost deterministically."""
    if not train or not evals:
        return None
    by = defaultdict(Counter)
    for r in train:
        by[key(r)][target(r)] += 1
    majority = Counter(target(r) for r in train).most_common(1)[0][0]
    table = {v: c.most_common(1)[0][0] for v, c in by.items()}
    acc = sum(table.get(key(r), majority) == target(r) for r in evals) / len(evals)
    base = sum(majority == target(r) for r in evals) / len(evals)
    reveals = []
    for v, c in by.items():
        n = sum(c.values())
        t, k = c.most_common(1)[0]
        if n >= COVERAGE * len(train) and k / n >= PURITY:
            reveals.append({"value": v, "target": t, "train_rows": n, "purity": round(k / n, 4)})
    return {"eval_accuracy": round(acc, 4), "majority_baseline": round(base, 4),
            "distinct_values": len(by), "deterministic_reveals": reveals}


# ── main ────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", help="write the JSON result here (refuses to overwrite)")
    args = ap.parse_args()
    if args.out and os.path.exists(args.out):
        raise SystemExit(f"FATAL: {args.out} exists; analyses are never overwritten")

    manifest = json.load(open(MANIFEST))
    rows = load(manifest)
    reason_to_cat = {r: c for c, (r, _) in {**gen.CATEGORY_SHAPES, **gen.HARDCODED_SHAPES}.items()}
    shape_paths = defaultdict(set)
    for name, shape in gen.SHAPES.items():
        for p in shape["paths"]:
            shape_paths[p].add(name)

    out = {"inputs": {"dataset": "datasets/v4_clean", "sha256_verified": True,
                      "manifest_generator_commit": manifest["generator_git_commit"],
                      "external_test_v1": "not read"}}

    # schema and label format
    keys = Counter(tuple(sorted(k for k in r if k != "split")) for r in rows)
    instructions = Counter(r["instruction"] for r in rows)
    malformed = 0
    for r in rows:
        decision, sep, reason = r["output"].partition(" | ")
        if not sep or decision not in ("ALLOW", "BLOCK") or "|" in reason:
            malformed += 1
        r["decision"], r["reason"] = decision, reason
        r["category"] = "BENIGN" if decision == "ALLOW" else reason_to_cat.get(reason, "UNMAPPED:" + reason)
        r["_parsed"] = parse_text(r["input"])
        path = r["_parsed"][1]
        r["source"] = ("shape" if path in shape_paths and path != "/" else
                       "ambiguous('/')" if path == "/" else "csic")
        r["shapes"] = "|".join(sorted(shape_paths.get(path, {"<csic>"})))
    label_strings = {r["reason"] for r in rows} | {"ALLOW |", "BLOCK |"}
    out["schema"] = {
        "fields": {"+".join(k): n for k, n in keys.items()},
        "distinct_instructions": len(instructions),
        "outputs_not_matching 'ALLOW|BLOCK | <reason>'": malformed,
        "distinct_outputs": len({r["output"] for r in rows}),
        "allow_reasons": sorted({r["reason"] for r in rows if r["decision"] == "ALLOW"}),
        "fields_absent": "no category, source, group id or provenance field; the category "
                         "exists only as the reason text inside `output`",
        "inputs_containing_a_label_or_reason_string": sum(
            any(x in r["input"] for x in label_strings) for r in rows),
    }

    # distribution
    split_n = Counter(r["split"] for r in rows)
    dec = Counter((r["split"], r["decision"]) for r in rows)
    cat = Counter((r["split"], r["category"]) for r in rows)
    cats = sorted({r["category"] for r in rows}, key=lambda c: -(cat[("train", c)] + cat[("eval", c)]))
    logical = manifest["logical_groups_per_category"]
    out["distribution"] = {
        "total": len(rows), "train": split_n["train"], "eval": split_n["eval"],
        "decisions": {f"{s}:{d}": n for (s, d), n in sorted(dec.items())},
        "categories": [{
            "category": c,
            "reason": next(r["output"] for r in rows if r["category"] == c),
            "train": cat[("train", c)], "eval": cat[("eval", c)],
            "pct_of_all_rows": round(100 * (cat[("train", c)] + cat[("eval", c)]) / len(rows), 3),
            "pct_of_block_rows": None if c == "BENIGN" else round(
                100 * (cat[("train", c)] + cat[("eval", c)]) / (dec[("train", "BLOCK")] + dec[("eval", "BLOCK")]), 3),
            "logical_groups_patt_hardcoded (manifest; CSIC groups not counted)": logical.get(c),
            "absent_from": [s for s in ("train", "eval") if cat[(s, c)] == 0],
            "eval_support_below_30": c != "BENIGN" and cat[("eval", c)] < EVAL_SUPPORT_FLOOR,
            "insufficient_data (manifest, <100 logical groups)": c in manifest["insufficient_data_categories"],
        } for c in cats],
    }

    # provenance inferred from the path (offline only)
    block = [r for r in rows if r["decision"] == "BLOCK"]
    out["provenance_offline"] = {
        "source_by_category": {c: dict(Counter(r["source"] for r in rows if r["category"] == c)) for c in cats},
        "csic_block_rows_inferred": sum(r["source"] == "csic" for r in block),
        "csic_block_rows_manifest_reports": 3906,
        "shape_by_category": {c: dict(Counter(r["shapes"] for r in rows if r["category"] == c).most_common(6))
                              for c in cats},
    }

    # label structure in the sources
    rules = csic_rule_families()
    out["label_sources"] = {
        "patt_cross_category_payloads": patt_collisions(),
        "csic_rule_families": [{"reason": r, "keywords": len(k)} for r, k in rules],
        "csic_multi_match": csic_multi_match([r for r in block if r["source"] == "csic"], rules),
    }

    # features
    fields = [f for f in dataclasses.fields(rf.RequestFeatures) if f.name != "schema_version"]
    type_name = {f.name: getattr(f.type, "__name__", f.type) for f in fields}
    out["feature_typing"] = {k: [n for n, t in type_name.items() if t == t_]
                             for k, t_ in (("numeric_int", "int"), ("numeric_float", "float"),
                                           ("boolean", "bool"), ("categorical", "str"))}
    for r in rows:
        f = rf.extract_features(r["input"])
        r["_f"] = f
        r["_vec"] = tuple(getattr(f, x.name) for x in fields)
        m, p, q, ct, body = r["_parsed"]
        r["_surface"] = f"{m} {p}?{q}\n{ct}\n{body}"
    out["feature_values"] = {c: dict(Counter(getattr(r["_f"], c) for r in rows).most_common(12))
                             for c in CATEGORICAL}

    by_vec = defaultdict(list)
    for r in rows:
        by_vec[r["_vec"]].append(r)
    conflict_rows = Counter()
    conflict_with_allow = Counter()
    for group in by_vec.values():
        outs = {r["category"] for r in group}
        if len(outs) > 1:
            for r in group:
                conflict_rows[r["category"]] += 1
                if r["category"] != "BENIGN" and "BENIGN" in outs:
                    conflict_with_allow[r["category"]] += 1
    tot = Counter(r["category"] for r in rows)
    out["feature_space"] = {
        "distinct_vectors": len(by_vec),
        "rows_sharing_a_vector_with_another_label": sum(conflict_rows.values()),
        "per_category": {c: {"rows": tot[c],
                             "in_label_conflict": conflict_rows[c],
                             "same_vector_as_a_BENIGN_row": conflict_with_allow[c],
                             "pct_same_vector_as_benign": round(100 * conflict_with_allow[c] / tot[c], 2)}
                         for c in cats},
    }
    # Observability from RequestFeatures: share of a category's rows whose coarse
    # feature profile (everything except lengths, ratios and entropy, which vary with
    # random benign values) also occurs among BENIGN rows of the same request shape.
    # High = the features describe these attacks like benign traffic of that shape.
    coarse = [f.name for f in fields if type_name[f.name] in ("int", "bool", "str")
              and not f.name.endswith(("_length",))]
    benign_profiles = defaultdict(set)
    for r in rows:
        if r["category"] == "BENIGN":
            benign_profiles[r["shapes"]].add(tuple(getattr(r["_f"], x) for x in coarse))
    out["observability_vs_benign_same_shape"] = {
        "coarse_profile_fields": coarse,
        "per_category_pct_rows_with_a_benign_profile": {
            c: round(100 * sum(tuple(getattr(r["_f"], x) for x in coarse) in benign_profiles[r["shapes"]]
                               for r in rs) / len(rs), 1)
            for c in cats if c != "BENIGN" for rs in [[r for r in rows if r["category"] == c]]}}
    syntax = ("single_quote_count", "double_quote_count", "parenthesis_count", "semicolon_count",
              "backslash_count", "angle_bracket_count", "pipe_count", "brace_count")
    out["encoding_by_category"] = {
        c: {"pct_percent_encoded": round(100 * sum(r["_f"].has_percent_encoding for r in rs) / len(rs), 1),
            "pct_any_raw_syntax_char": round(100 * sum(any(getattr(r["_f"], s) for s in syntax) for r in rs) / len(rs), 1)}
        for c in cats for rs in [[r for r in rows if r["category"] == c]]}

    # shortcuts
    train = [r for r in rows if r["split"] == "train"]
    evals = [r for r in rows if r["split"] == "eval"]
    btrain = [r for r in train if r["decision"] == "BLOCK"]
    beval = [r for r in evals if r["decision"] == "BLOCK"]
    tasks = {"decision": (train, evals, lambda r: r["decision"]),
             "category_20way": (train, evals, lambda r: r["category"]),
             "category_given_BLOCK": (btrain, beval, lambda r: r["category"])}
    out["single_variable_lookup"] = {
        name: {**{feat: lookup(tr, ev, (lambda r, feat=feat: getattr(r["_f"], feat)), tgt)
                  for feat in CATEGORICAL + PATH_PROXIES},
               "path (OFFLINE, not a feature)": lookup(tr, ev, lambda r: r["_parsed"][1], tgt),
               "source (OFFLINE, not a feature)": lookup(tr, ev, lambda r: r["source"], tgt)}
        for name, (tr, ev, tgt) in tasks.items()}

    # split overlap at Analyzer level
    def cross(keyf):
        tr = defaultdict(set)
        for r in train:
            tr[keyf(r)].add(r["category"])
        hit = [r for r in evals if keyf(r) in tr]
        same = sum(r["category"] in tr[keyf(r)] for r in hit)
        return {"eval_rows_with_key_in_train": len(hit), "of_which_same_category": same,
                "by_category_and_source": dict(Counter(f"{r['category']} / {r['source']}"
                                                       for r in hit).most_common())}

    canon = {id(r): gen.canonical_key(r["_surface"]) for r in rows}
    groups_train = Counter(canon[id(r)] for r in train)
    out["split"] = {
        "mechanism": "D16: group id from the canonical payload (attacks), shape|path|param|value "
                     "(synthetic benign) or a digit-collapsed request key (CSIC), hashed into "
                     "train/eval before rendering; generator asserts no group in both splits; "
                     "group ids are not written to the JSONL",
        "exact_input": cross(lambda r: r["input"]),
        "surface (method+path+query+content_type+body; envelope removed)": cross(lambda r: r["_surface"]),
        "canonical_surface (generator canonical_key over the surface)": cross(lambda r: canon[id(r)]),
        "feature_vector": cross(lambda r: r["_vec"]),
        "train_canonical_surface_groups": len(groups_train),
        "train_rows_in_groups_of_2_or_more": sum(n for n in groups_train.values() if n > 1),
    }

    # consequences of the frozen design (D46-D51)
    for r in rows:
        r["t_attack"], r["t_category"], r["t_slice"] = analyzer_target(r["category"])
    out["frozen_design"] = {
        "category_mapping": [{"v4_category": c, "v4_reason": next(r["reason"] for r in rows if r["category"] == c),
                              "analyzer": ("not a target (ALLOW)" if c == "BENIGN" else
                                           UNSUPPORTED.get(c) or ANALYZER_CATEGORY.get(c, "other_attack")),
                              "train": cat[("train", c)], "eval": cat[("eval", c)]} for c in cats],
        "target_counts": {s: dict(Counter(r["t_category"] or r["t_slice"] or "BENIGN"
                                          for r in rows if r["split"] == s)) for s in ("train", "eval")},
        "validation": {"salt": VALIDATION_SALT, "fraction": VALIDATION_FRACTION,
                       "bucket": "sha256(salt + NUL + group_key)[:8] as big-endian int % 10000 < 2000"},
        "group_definitions": {},
    }

    # Group candidates. "canonical_request": the generator's canonical_key over the
    # header-free surface. "canonical_request_or_vector": rows linked by either the same
    # canonical request OR the same feature vector (connected components), so no feature
    # vector can sit on both sides of the TRAIN / VALIDATION boundary.
    parent = {}

    def find(x):
        while parent.setdefault(x, x) != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    for r in train:
        a, b = find(("c", canon[id(r)])), find(("v", r["_vec"]))
        if a != b:
            parent[max(a, b, key=repr)] = min(a, b, key=repr)
    members = defaultdict(list)
    for r in train:
        members[find(("c", canon[id(r)]))].append(r)
    component = {id(r): min(canon[id(m)] for m in ms) for ms in members.values() for r in ms}
    group_keys = {"canonical_request": lambda r: canon[id(r)],
                  "canonical_request_or_vector": lambda r: component[id(r)]}

    eligible_eval = [r for r in evals if r["t_slice"] is None]
    # Strict reference set: every V4-train row the Analyzer may use (TRAIN and
    # VALIDATION; VALIDATION informs model selection and calibration). Independent of
    # the VALIDATION carve-out.
    used = [r for r in train if r["t_slice"] is None]
    used_vec, used_canon = {r["_vec"] for r in used}, {canon[id(r)] for r in used}
    strict = [r for r in eligible_eval if r["_vec"] not in used_vec]
    out["frozen_design"]["internal_test_strict (reference: TRAIN + VALIDATION)"] = {
        "internal_test_full_rows": len(eligible_eval),
        "flag_feature_vector_in_train_or_validation": len(eligible_eval) - len(strict),
        "flag_canonical_request_in_train_or_validation": sum(canon[id(r)] in used_canon
                                                             for r in eligible_eval),
        "internal_test_feature_disjoint_rows": len(strict),
        "decisions": {"full": dict(Counter(r["decision"] for r in eligible_eval)),
                      "feature_disjoint": dict(Counter(r["decision"] for r in strict))},
        "targets": {"full": dict(Counter(r["t_category"] or "BENIGN" for r in eligible_eval)),
                    "feature_disjoint": dict(Counter(r["t_category"] or "BENIGN" for r in strict))},
    }
    largest = Counter(canon[id(r)] for r in train).most_common(1)[0]
    out["frozen_design"]["largest_canonical_request_group"] = {
        "rows": largest[1], "categories": dict(Counter(r["category"] for r in train
                                                       if canon[id(r)] == largest[0])),
        "sources": dict(Counter(r["source"] for r in train if canon[id(r)] == largest[0]))}
    for name, gkey in group_keys.items():
        sizes = Counter(gkey(r) for r in train)
        val = [r for r in train if in_validation(gkey(r))]
        trn = [r for r in train if not in_validation(gkey(r))]
        fit = [r for r in trn if r["t_slice"] is None]          # effective TRAIN (JWT out)
        fit_vec = {r["_vec"] for r in fit}
        fit_canon = {canon[id(r)] for r in fit}
        val_vec = {r["_vec"] for r in val if r["t_slice"] is None}
        disjoint = [r for r in eligible_eval if r["_vec"] not in fit_vec]
        out["frozen_design"]["group_definitions"][name] = {
            "groups": len(sizes), "largest_group_rows": max(sizes.values()),
            "rows_in_groups_of_10_or_more": sum(n for n in sizes.values() if n >= 10),
            "train_rows": len(trn), "validation_rows": len(val),
            "validation_share": round(len(val) / len(train), 4),
            "decisions": {"train": dict(Counter(r["decision"] for r in trn)),
                          "validation": dict(Counter(r["decision"] for r in val))},
            "targets": {"train": dict(Counter(r["t_category"] or r["t_slice"] or "BENIGN" for r in trn)),
                        "validation": dict(Counter(r["t_category"] or r["t_slice"] or "BENIGN" for r in val))},
            # Support of the rows that are actually fitted / used for selection (JWT out),
            # against the D19 support floor of 30 rows.
            "fitted_support": {
                role: {"decisions": dict(Counter(r["decision"] for r in rs if r["t_slice"] is None)),
                       "categories": {c: sum(r["t_category"] == c for r in rs)
                                      for c in dict.fromkeys(ANALYZER_CATEGORY.values())
                                      | {"other_attack": None}},
                       "below_floor_30": sorted(
                           [c for c in dict.fromkeys(ANALYZER_CATEGORY.values()) | {"other_attack": None}
                            if sum(r["t_category"] == c for r in rs) < EVAL_SUPPORT_FLOOR]
                           + [d for d in ("ALLOW", "BLOCK")
                              if sum(r["decision"] == d and r["t_slice"] is None for r in rs)
                              < EVAL_SUPPORT_FLOOR])}
                for role, rs in (("train", trn), ("validation", val))},
            "validation_rows_whose_vector_is_in_effective_train": sum(
                r["_vec"] in fit_vec for r in val if r["t_slice"] is None),
            "validation_rows_whose_canonical_request_is_in_effective_train": sum(
                canon[id(r)] in fit_canon for r in val),
            "internal_test": {
                "unsupported_jwt_slice_rows": sum(r["t_slice"] == "unsupported_jwt" for r in evals),
                "internal_test_full_rows": len(eligible_eval),
                "flag_feature_vector_in_effective_train": len(eligible_eval) - len(disjoint),
                "flag_canonical_request_in_effective_train": sum(canon[id(r)] in fit_canon
                                                                 for r in eligible_eval),
                "internal_test_feature_disjoint_rows": len(disjoint),
                "vector_only_in_validation (counted as disjoint)": sum(
                    r["_vec"] in val_vec and r["_vec"] not in fit_vec for r in eligible_eval),
                "decisions": {"full": dict(Counter(r["decision"] for r in eligible_eval)),
                              "feature_disjoint": dict(Counter(r["decision"] for r in disjoint))},
                "targets": {"full": dict(Counter(r["t_category"] or "BENIGN" for r in eligible_eval)),
                            "feature_disjoint": dict(Counter(r["t_category"] or "BENIGN" for r in disjoint))},
            },
        }

    text = json.dumps(out, indent=2, ensure_ascii=False, default=str) + "\n"
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "x", encoding="utf-8") as f:
            f.write(text)
    print(text, end="")


if __name__ == "__main__":
    main()
