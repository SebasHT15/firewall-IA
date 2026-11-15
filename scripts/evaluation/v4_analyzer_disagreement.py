"""
firewall-IA — V4 ↔ Analyzer disagreement diagnostics on DEVELOPMENT data (issue #57).

Protocol, fixed before scoring: reports/hybrid/v4-analyzer-disagreement-v1/PROTOCOL.md

DIAGNOSTIC, not an evaluation. Per unique development text it crosses: known label × V4
decision (recorded, or from the one manual-suite re-run) × frozen Analyzer `attack` ×
auxiliary category (context, never a decision, D46). It trains, calibrates and thresholds
nothing; the bands are fixed descriptive bins (0.5 is only the D55 reporting convention).

Sources (PROTOCOL §2):
  S1  reports/diagnostics/real-http-fp-v1/ — benign, recorded V4 decisions; the EVALSWAP
      family (texts from V4-clean eval = Analyzer INTERNAL TEST) is NOT scored (D54).
  S2  the legacy 135-case manual suite in scripts/evaluation/test_model.py, with per-case V4
      decisions from scripts/evaluation/v4_manual_suite_decisions.py.

External Test v1 is refused by construction: every file this module opens goes through
`dev_path()`, which rejects datasets/external_v1/, reports/external/, docker/.lab-logs/ and
the Analyzer's External v1 report folder.

Research environment (.venv-analyzer), from the repository root:

    .venv-analyzer/bin/python scripts/evaluation/v4_analyzer_disagreement.py run
"""

import argparse
import hashlib
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO_ROOT, "scripts", "evaluation"))

import numpy as np  # noqa: E402

import analyzer_external_v1 as ev  # noqa: E402  (frozen helpers only: load_model, relations)
import v4_manual_suite_decisions as manual  # noqa: E402  (suite extraction; no torch import)

ha, rf = ev.ha, ev.rf

REPORT_DIR = os.path.join(REPO_ROOT, "reports", "hybrid", "v4-analyzer-disagreement-v1")
S1_DIR = os.path.join(REPO_ROOT, "reports", "diagnostics", "real-http-fp-v1")
S1_CASES = os.path.join(S1_DIR, "cases.jsonl")
S1_RESULTS = os.path.join(S1_DIR, "results.jsonl")
S2_DECISIONS = os.path.join(REPORT_DIR, "raw", "v4_manual_suite_decisions.jsonl")
V4_TRAIN = os.path.join(REPO_ROOT, "datasets", "v4_clean", "train.jsonl")
V4_EVAL = os.path.join(REPO_ROOT, "datasets", "v4_clean", "eval.jsonl")

ANCHORS = {
    "s1_cases": "b60bafba44c3d22c123897662546133fd0329b7a9a53f26abdde86f38f122690",
    "s1_results": "03e1c78a500041b89690311a33cac7ea2749cec8a7aae6c15017f7ec0b9d64ac",
    "v4_train": "4459f6861629279395acc57f99173d82bbda4dc8205a5f3bd08750dd528d262b",
    "v4_eval": "61f15591203609b4c583773184cd25edd6d1adc5f86959e009cfd47f6d370859",
    "suite": manual.SUITE_SHA256,
}

FORBIDDEN = tuple(os.path.realpath(os.path.join(REPO_ROOT, p)) for p in (
    "datasets/external_v1", "reports/external", "docker/.lab-logs",
    "reports/hybrid/analyzer-external-v1-run-001"))


class ForbiddenSource(Exception):
    """Raised before opening anything that belongs to External Test v1."""


def dev_path(path):
    real = os.path.realpath(path)
    for f in FORBIDDEN:
        if real == f or real.startswith(f + os.sep):
            raise ForbiddenSource("External Test v1 data is not development data (D40 / D45 / D53)")
    return path


def read_jsonl(path):
    with open(dev_path(path), encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def sha_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha_file(path):
    return ev.sha256_file(dev_path(path))


# ── fixed descriptive bands (PROTOCOL §5; not a policy, not tuned) ──────────
BANDS = ((0.0, 0.1, "[0,0.1)"), (0.1, 0.5, "[0.1,0.5)"), (0.5, 0.9, "[0.5,0.9)"), (0.9, 1.0, "[0.9,1]"))
BAND_LABELS = tuple(b[2] for b in BANDS)
EXTREME_LOW, EXTREME_HIGH = 0.01, 0.99


def band(p):
    if not 0.0 <= p <= 1.0:
        raise ValueError("probability outside [0, 1]")
    for lo, hi, label in BANDS:
        if lo <= p < hi:
            return label
    return BANDS[-1][2]          # p == 1.0


def extreme(p):
    return "low" if p < EXTREME_LOW else ("high" if p >= EXTREME_HIGH else None)


# ── signal location (PROTOCOL §5) ───────────────────────────────────────────
HEADER_ONLY_CATEGORIES = {"JWT Attacks", "CSRF"}
HEADER_DEPENDENT_CATEGORIES = {"HTTP Request Smuggling"}
S1_HEADER_FAMILIES = {"HOST", "PORT", "HDR", "UA", "UAxPC"}


def signal_location(category):
    if category in HEADER_ONLY_CATEGORIES:
        return "header-only"
    if category in HEADER_DEPENDENT_CATEGORIES:
        return "header-dependent"
    return "surface"


def extra_headers(text):
    """Header names other than Host and Content-Type (lowercase, sorted): content the
    Analyzer never reads (D44). Used to tag benign and attack texts alike."""
    head = text.partition("\n\n")[0].split("\n")[1:]
    names = {h.partition(":")[0].strip().lower() for h in head if ":" in h}
    return sorted(names - {"host", "content-type"})


# D47 mapping of the suite categories (PROTOCOL §5)
SUITE_TO_D47 = {
    "SQL Injection": "sql_injection", "XSS Injection": "xss", "Command Injection": "command_injection",
    "Path Traversal": "path_file_access", "File Inclusion": "path_file_access", "SSTI": "ssti",
    "Open Redirect": "open_redirect", "SSRF": "ssrf",
    "LDAP Injection": "other_attack", "XXE Injection": "other_attack", "GraphQL Injection": "other_attack",
    "NoSQL Injection": "other_attack", "Insecure Deserialization": "other_attack",
    "HTTP Request Smuggling": "other_attack", "CRLF Injection": "other_attack",
    "HTTP Parameter Pollution": "other_attack", "XPath Injection": "other_attack",
    "CSRF": "other_attack", "JWT Attacks": None,
}
ADVERSARIAL_PREFIX = (("SQL", "sql_injection"), ("XSS", "xss"), ("Path traversal", "path_file_access"),
                      ("Command injection", "command_injection"), ("SSTI", "ssti"))


def d47_category(category, description, expected):
    if expected != "BLOCK":
        return None
    if category == "Adversarial":
        for prefix, cat in ADVERSARIAL_PREFIX:
            if description.startswith(prefix):
                return cat
        return None
    return SUITE_TO_D47[category]


# ── sources ─────────────────────────────────────────────────────────────────
def load_s1(cases_path=None, results_path=None):
    """Unique benign texts of real-http-fp-v1 with their recorded V4 decision. Texts that occur
    in the EVALSWAP family (from V4-clean eval rows) are excluded, not scored (D54)."""
    cases = read_jsonl(cases_path or S1_CASES)
    results = read_jsonl(results_path or S1_RESULTS)
    problems = []
    texts = {}
    for c in cases:
        if sha_text(c["text"]) != c["text_sha256"]:
            problems.append("a case text does not match its text_sha256")
        if c["expected_label"] != "ALLOW":
            problems.append("a case is not labelled ALLOW")
        u = texts.setdefault(c["text_sha256"], {"text": c["text"], "case_ids": [], "families": set(),
                                                "from_v4_eval": False})
        u["case_ids"].append(c["case_id"])
        u["families"].add(c["family"])
        if c["family"] == "EVALSWAP" or str(c.get("source", "")).startswith("datasets/v4_clean"):
            u["from_v4_eval"] = True
    reps = defaultdict(dict)
    for r in results:
        if r.get("phase") == "direct":
            reps[r["text_sha256"]][r["rep"]] = (r["decision"], r["reason"], r["status"])
    units, excluded, inconsistent = [], 0, 0
    for sha, u in sorted(texts.items()):
        if u["from_v4_eval"]:
            excluded += 1
            continue
        got = reps.get(sha, {})
        if 1 not in got:
            problems.append("a unique text has no recorded direct decision")
            continue
        consistent = len(set(got.values())) == 1
        inconsistent += not consistent
        d, reason, status = got[1]
        units.append({"source": "S1", "unit_id": "S1:" + sha[:12], "text_sha256": sha, "text": u["text"],
                      "label": "ALLOW", "category": None, "description": None,
                      "families": sorted(u["families"]), "case_ids": sorted(u["case_ids"]),
                      "v4_decision": d if status == "ok" else "INVALID", "v4_reason": reason,
                      "v4_status": status, "v4_reps_consistent": consistent,
                      "signal_location": None})
    pairs = []
    by_id = {c["case_id"]: c for c in cases}
    for c in cases:
        ref = by_id.get(c["pair_with"]) if c.get("pair_with") else None
        if ref is None or c["family"] == "EVALSWAP":
            continue
        pairs.append({"family": c["family"], "variable": c["variable"], "value": c["value"],
                      "a": ref["text_sha256"], "b": c["text_sha256"],
                      "location": "header" if c["family"] in S1_HEADER_FAMILIES else "surface"})
    return units, pairs, {"cases": len(cases), "unique_texts": len(texts),
                          "excluded_from_v4_eval (D54)": excluded, "scored_unique_texts": len(units),
                          "v4_rep_inconsistent": inconsistent, "problems": problems}


def load_s2(decisions_path=None, suite_path=None):
    cases, digest = manual.manual_suite(suite_path or manual.TEST_MODEL)
    problems = [] if digest == ANCHORS["suite"] else ["manual suite differs from the protocol"]
    decisions = read_jsonl(decisions_path or S2_DECISIONS)
    if len(decisions) != len(cases):
        problems.append("V4 decision count differs from the suite")
    units = []
    for i, (text, expected, category, desc) in enumerate(cases):
        d = decisions[i] if i < len(decisions) else None
        if d is None or d["index"] != i or d["text_sha256"] != sha_text(text) or d["expected"] != expected:
            problems.append("V4 decision record does not match its suite case")
            continue
        sha = sha_text(text)
        units.append({"source": "S2", "unit_id": f"S2:{i:03d}", "text_sha256": sha, "text": text,
                      "label": expected, "category": category, "description": desc,
                      "families": None, "case_ids": [f"manual-{i:03d}"],
                      "v4_decision": d["decision"] if d["status"] == "ok" else "INVALID",
                      "v4_reason": d["reason"], "v4_status": d["status"], "v4_reps_consistent": None,
                      "signal_location": signal_location(category) if expected == "BLOCK" else None,
                      "headers_beyond_host_content_type": extra_headers(text),
                      "d47_expected": d47_category(category, desc, expected)})
    if len({u["text_sha256"] for u in units}) != len(units):
        problems.append("duplicate texts in the manual suite")
    return units, {"cases": len(cases), "suite_sha256": digest, "problems": problems}


# ── relations to the Analyzer's data roles (membership only) ────────────────
MEMBERSHIP_FIELDS = ("role", "slice", "meta_feature_vector_sha256", "meta_canonical_request_sha256")


def load_membership(path=None, manifest_path=None):
    """hybrid_analyzer_v2, verified, reduced to the fields membership needs (PROTOCOL §4: a "look"
    at INTERNAL TEST = Analyzer output joined with its labels or row identities, so labels,
    targets, V4 metadata and row ids of INTERNAL TEST rows are never kept). TRAIN / VALIDATION
    rows keep their row_id for the canonical-relation self-check."""
    path = dev_path(path or ev.DATASET_V2)
    manifest_path = dev_path(manifest_path or ev.DATASET_V2_MANIFEST)
    with open(manifest_path, encoding="utf-8") as f:
        expected = json.load(f)["artifact"]["sha256"]
    if ev.sha256_file(path) != expected:
        raise ValueError("hybrid_analyzer_v2 SHA-256 differs from its manifest")
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            keep = {k: r[k] for k in MEMBERSHIP_FIELDS}
            if r["role"] in ("train", "validation"):
                keep["row_id"] = r["row_id"]
            rows.append(keep)
    return rows


def role_sets(dataset_rows):
    sets = {k: {"vec": set(), "canon": set()} for k in ("train_validation", "train_validation_jwt",
                                                       "internal_test")}
    for r in dataset_rows:
        if r["role"] in ("train", "validation"):
            key = "train_validation" if r["slice"] is None else "train_validation_jwt"
        else:
            key = "internal_test"
        sets[key]["vec"].add(r["meta_feature_vector_sha256"])
        sets[key]["canon"].add(r["meta_canonical_request_sha256"])
    return sets


def canonical_relation_check(dataset_rows, v4_train_rows):
    """The D51 canonical request recomputed from V4-clean train text must equal the hash stored
    in hybrid_analyzer_v2 for the same row (row_id = SHA-256 of the text)."""
    stored = {r["row_id"]: r["meta_canonical_request_sha256"] for r in dataset_rows
              if r["role"] in ("train", "validation")}
    ok = checked = 0
    for r in v4_train_rows:
        rid = sha_text(r["input"])
        if rid in stored:
            checked += 1
            ok += sha_text(ev.canonical_request(r["input"])) == stored[rid]
    return checked, ok


def attach_analyzer(units, analyzer, sets, v4_train_texts, v4_eval_texts):
    feats = [rf.extract_features(u["text"]) for u in units]
    p = np.asarray(analyzer.attack_proba(feats), dtype=float) if units else np.zeros(0)
    pc = np.asarray(analyzer.category_proba(feats), dtype=float) if units else np.zeros((0, 8))
    cats = list(ha.CATEGORIES)
    for u, f, pa, row in zip(units, feats, p, pc):
        vec, canon = ev.vector_hash(f), sha_text(ev.canonical_request(u["text"]))
        top = int(row.argmax())
        u.update({
            "attack": float(pa), "band": band(float(pa)), "extreme": extreme(float(pa)),
            "category_top1": cats[top], "category_top1_p": float(row[top]),
            "category_probs": {c: round(float(row[i]), 6) for i, c in enumerate(cats)},
            "feature_vector_sha256": vec, "canonical_request_sha256": canon,
            "content_type": f.content_type, "method": f.method,
            "seen_train_validation": vec in sets["train_validation"]["vec"]
            or canon in sets["train_validation"]["canon"],
            "seen_train_validation_jwt": vec in sets["train_validation_jwt"]["vec"]
            or canon in sets["train_validation_jwt"]["canon"],
            "in_internal_test_relation": vec in sets["internal_test"]["vec"]
            or canon in sets["internal_test"]["canon"],
            "exact_text_in_v4_train": u["text_sha256"] in v4_train_texts,
            "exact_text_in_v4_eval": u["text_sha256"] in v4_eval_texts,
        })
    return units


# ── aggregation (pure; synthetic-testable) ──────────────────────────────────
def crosstab(units, keys=("label", "v4_decision", "band")):
    c = Counter(tuple(u[k] for k in keys) for u in units)
    return [{**dict(zip(keys, k)), "n": n} for k, n in sorted(c.items(), key=lambda kv: tuple(map(str, kv[0])))]


def at_reporting_threshold(units):
    """label × V4 × (attack ≥ 0.5): the D55 reporting convention, not an operating point."""
    c = Counter((u["label"], u["v4_decision"], "attack>=0.5" if u["attack"] >= 0.5 else "attack<0.5")
                for u in units)
    return {" | ".join(k): n for k, n in sorted(c.items())}


def summary_stats(values):
    v = np.asarray(values, dtype=float)
    if not len(v):
        return {"n": 0}
    return {"n": int(len(v)), "min": round(float(v.min()), 4), "median": round(float(np.median(v)), 4),
            "max": round(float(v.max()), 4)}


def vectors_with_both_v4_decisions(units):
    by = defaultdict(set)
    for u in units:
        by[u["feature_vector_sha256"]].add(u["v4_decision"])
    mixed = {v for v, d in by.items() if len(d) > 1}
    return {"distinct_vectors": len(by), "vectors_with_both_v4_decisions": len(mixed),
            "texts_in_those_vectors": sum(1 for u in units if u["feature_vector_sha256"] in mixed)}


def vector_level(units):
    """PROTOCOL §5 (audit B2): the Analyzer sees one feature vector, so its results are counted
    per distinct vector first. Per vector: texts, label mix, V4 decision mix, attack, band."""
    by = defaultdict(list)
    for u in units:
        by[u["feature_vector_sha256"]].append(u)
    vectors = []
    for v, us in by.items():
        labels = sorted({u["label"] for u in us})
        v4 = Counter(u["v4_decision"] for u in us)
        vectors.append({"vector": v[:12], "texts": len(us), "labels": "/".join(labels),
                        "v4_block": v4.get("BLOCK", 0), "v4_allow": v4.get("ALLOW", 0),
                        "v4_invalid": v4.get("INVALID", 0),
                        "v4_mix": "/".join(sorted(v4)), "attack": round(us[0]["attack"], 6),
                        "band": us[0]["band"]})
    vectors.sort(key=lambda r: (-r["texts"], r["vector"]))
    cross = Counter((r["labels"], r["v4_mix"], r["band"]) for r in vectors)
    return {"distinct_vectors": len(vectors),
            "cross_label_mix_v4_mix_band (vectors)": [
                {"labels": k[0], "v4": k[1], "band": k[2], "vectors": n}
                for k, n in sorted(cross.items())],
            "vectors": vectors if len(vectors) <= 40 else None}


def pair_analysis(pairs, units_by_sha):
    out = Counter()
    for p in pairs:
        a, b = units_by_sha.get(p["a"]), units_by_sha.get(p["b"])
        if a is None or b is None:
            continue
        v4_flip = a["v4_decision"] != b["v4_decision"]
        changed = abs(a["attack"] - b["attack"]) > 1e-12
        out[(p["family"], p["location"], "V4 flips" if v4_flip else "V4 same",
             "Analyzer changes" if changed else "Analyzer identical")] += 1
    return [{"family": k[0], "varied": k[1], "v4": k[2], "analyzer": k[3], "pairs": n}
            for k, n in sorted(out.items())]


def per_group(units, key):
    groups = defaultdict(list)
    for u in units:
        for g in (u[key] if isinstance(u[key], list) else [u[key]]):
            groups[g].append(u)
    out = {}
    for g, us in sorted(groups.items(), key=lambda kv: str(kv[0])):
        blocked = [u for u in us if u["v4_decision"] == "BLOCK"]
        out[str(g)] = {"texts": len(us), "v4_block": len(blocked),
                       "analyzer_bands": dict(Counter(u["band"] for u in us)),
                       "attack_when_v4_block": summary_stats([u["attack"] for u in blocked]),
                       "attack_when_v4_allow": summary_stats([u["attack"] for u in us
                                                              if u["v4_decision"] != "BLOCK"])}
    return out


def category_usefulness(units):
    mapped = [u for u in units if u["label"] == "BLOCK" and u.get("d47_expected")]
    agree = sum(1 for u in mapped if u["category_top1"] == u["d47_expected"])
    per = defaultdict(lambda: Counter())
    for u in mapped:
        per[u["d47_expected"]][u["category_top1"]] += 1
    return {"block_cases_with_d47_mapping": len(mapped), "top1_agrees": agree,
            "by_expected": {k: dict(v) for k, v in sorted(per.items())},
            "unmapped_block_cases (JWT, adversarial without mapping)":
                sum(1 for u in units if u["label"] == "BLOCK" and not u.get("d47_expected"))}


def extremes(units):
    c = Counter((u["label"], u["v4_decision"], u["extreme"]) for u in units if u["extreme"])
    return {" | ".join(k): n for k, n in sorted(c.items())}


def analyse(s1, pairs, s2):
    all_units = s1 + s2
    by_sha = {u["text_sha256"]: u for u in s1}
    s2_unseen = [u for u in s2 if not u["seen_train_validation"]]
    return {
        "S1_real_http_fp_v1": {
            "vector_level (primary unit for Analyzer-side results)": vector_level(s1),
            "cross_label_v4_band (texts, secondary)": crosstab(s1),
            "at_reporting_threshold_0_5 (D55, not an operating point)": at_reporting_threshold(s1),
            "per_family": per_group(s1, "families"),
            "pairs": pair_analysis(pairs, by_sha),
            "feature_vectors": vectors_with_both_v4_decisions(s1),
            "v4_block_texts_analyzer_category_vs_v4_reason": dict(Counter(
                f"{u['v4_reason']} -> {u['category_top1']}" for u in s1 if u["v4_decision"] == "BLOCK")),
            "overlap": overlap(s1),
        },
        "S2_manual_suite": {
            "vector_level (primary unit for Analyzer-side results)": vector_level(s2),
            "cross_label_v4_band (texts, secondary)": crosstab(s2),
            "allow_texts_with_headers_beyond_host_content_type": sum(
                1 for u in s2 if u["label"] == "ALLOW" and u["headers_beyond_host_content_type"]),
            "cross_label_v4_band_unseen_only": crosstab(s2_unseen),
            "at_reporting_threshold_0_5 (D55, not an operating point)": at_reporting_threshold(s2),
            "at_reporting_threshold_0_5_unseen_only": at_reporting_threshold(s2_unseen),
            "per_category": per_group(s2, "category"),
            "block_by_signal_location": {loc: {"texts": len(us), "v4_block": sum(u["v4_decision"] == "BLOCK" for u in us),
                                               "analyzer_bands": dict(Counter(u["band"] for u in us)),
                                               "attack": summary_stats([u["attack"] for u in us])}
                                         for loc, us in group_by(s2, "signal_location").items() if loc},
            "category_head": category_usefulness(s2),
            "feature_vectors": vectors_with_both_v4_decisions(s2),
            "vectors_shared_by_allow_and_block": shared_label_vectors(s2),
            "overlap": overlap(s2),
        },
        "extremes (attack < 0.01 or >= 0.99)": extremes(all_units),
    }


def group_by(units, key):
    g = defaultdict(list)
    for u in units:
        g[u[key]].append(u)
    return dict(g)


def shared_label_vectors(units):
    by = defaultdict(set)
    for u in units:
        by[u["feature_vector_sha256"]].add(u["label"])
    return sum(1 for s in by.values() if len(s) > 1)


def overlap(units):
    keys = ("seen_train_validation", "seen_train_validation_jwt", "in_internal_test_relation",
            "exact_text_in_v4_train", "exact_text_in_v4_eval")
    return {k: {"allow": sum(1 for u in units if u[k] and u["label"] == "ALLOW"),
                "block": sum(1 for u in units if u[k] and u["label"] == "BLOCK")} for k in keys}


# ── run ─────────────────────────────────────────────────────────────────────
def write_exclusive(path, text):
    with open(dev_path(path), "x", encoding="utf-8") as f:
        f.write(text)


def cmd_run(args):
    out_dir = args.out_dir
    for name in ("records.jsonl", "results.json"):
        if os.path.exists(os.path.join(out_dir, name)):
            raise SystemExit(f"REFUSING to overwrite {name}")
    checks = {"s1_cases": sha_file(S1_CASES) == ANCHORS["s1_cases"],
              "s1_results": sha_file(S1_RESULTS) == ANCHORS["s1_results"],
              "v4_train": sha_file(V4_TRAIN) == ANCHORS["v4_train"],
              "v4_eval": sha_file(V4_EVAL) == ANCHORS["v4_eval"]}
    model_path = os.path.join(REPO_ROOT, ev.ANCHORS["model_path"])
    model_before = sha_file(model_path)
    analyzer = ev.load_model(dev_path(model_path), ev.ANCHORS["model_sha256"])
    s1, pairs, s1_meta = load_s1()
    s2, s2_meta = load_s2()
    dataset = load_membership()
    sets = role_sets(dataset)
    v4_train = read_jsonl(V4_TRAIN)
    v4_eval_texts = {sha_text(r["input"]) for r in read_jsonl(V4_EVAL)}
    checked, ok = canonical_relation_check(dataset, v4_train)
    v4_train_texts = {sha_text(r["input"]) for r in v4_train}
    del dataset, v4_train
    attach_analyzer(s1, analyzer, sets, v4_train_texts, v4_eval_texts)
    attach_analyzer(s2, analyzer, sets, v4_train_texts, v4_eval_texts)
    problems = s1_meta["problems"] + s2_meta["problems"] + [k for k, v in checks.items() if not v]
    if ok != checked or checked == 0:
        problems.append("canonical relation does not reproduce the v2 build")
    result = {
        "run": "v4-analyzer-disagreement-v1", "type": "DIAGNOSTIC on development data (issue #57)",
        "created_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "git_head": ev._git("rev-parse", "HEAD").stdout.strip(),
        "analyzer_version": analyzer.version, "model_sha256": model_before,
        "model_unchanged_after": sha_file(model_path) == model_before == ev.ANCHORS["model_sha256"],
        "input_checks": checks, "canonical_relation_check": {"rows_checked": checked, "rows_equal": ok},
        "s1_meta": s1_meta, "s2_meta": {k: v for k, v in s2_meta.items()},
        "bands (descriptive, fixed in PROTOCOL §5)": list(BAND_LABELS),
        "evaluator_sha256": sha_file(os.path.abspath(__file__)),
        "protocol_sha256": sha_file(os.path.join(REPORT_DIR, "PROTOCOL.md")),
        "problems": problems,
        **analyse(s1, pairs, s2),
    }
    records = "".join(json.dumps({k: v for k, v in u.items()}, ensure_ascii=False) + "\n" for u in s1 + s2)
    write_exclusive(os.path.join(out_dir, "records.jsonl"), records)
    write_exclusive(os.path.join(out_dir, "results.json"),
                    json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    print(f"S1 scored {len(s1)} unique texts (excluded {s1_meta['excluded_from_v4_eval (D54)']}); "
          f"S2 scored {len(s2)}; problems: {problems or 'none'}")
    return 0 if not problems else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.strip().split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--out-dir", default=REPORT_DIR)
    args = ap.parse_args(argv)
    return {"run": cmd_run}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
