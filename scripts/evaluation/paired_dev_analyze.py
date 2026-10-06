"""
firewall-IA — offline analysis of the paired development diagnostic (issue #59).

DIAGNOSTIC on DEVELOPMENT data. Joins, per scored case: the oracle label, V4's gateway
decision + reason (from paired_dev_capture.py), and the frozen Analyzer's `attack` probability
and auxiliary category (context only, D46). It trains / calibrates / thresholds nothing; the
bands are fixed descriptive bins and 0.5 is only the D55 reporting convention. Every count is a
diagnostic count on an author-chosen composition, never an FPR / FNR / recall / prevalence / rate
(D42, methodology section 7).

Read-only. The frozen Analyzer artifact hash is checked before and after. External Test v1 is
refused by construction (reuses the v4_analyzer_disagreement dev_path guard). INTERNAL TEST is
touched by MEMBERSHIP METADATA ONLY (D54, no third look).

    .venv-analyzer/bin/python scripts/evaluation/paired_dev_analyze.py run \
        --cases reports/hybrid/v4-analyzer-paired-dev-v1/cases.jsonl \
        --raw   reports/hybrid/v4-analyzer-paired-dev-v1/raw/records_raw.jsonl \
        --out-dir reports/hybrid/v4-analyzer-paired-dev-v1
"""

import argparse
import json
import os
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO_ROOT, "scripts", "evaluation"))

import numpy as np  # noqa: E402

import v4_analyzer_disagreement as da  # noqa: E402  (pure helpers + guards, reused)

ev = da.ev
ha, rf = da.ha, da.rf

REPORT_DIR = os.path.join(REPO_ROOT, "reports", "hybrid", "v4-analyzer-paired-dev-v1")
CONCLUSION_FAMILIES = ("sql_injection", "xss", "command_injection", "path_file_access", "ssrf")
MIN_GROUPS = 30  # D18


def read_jsonl(path):
    with open(da.dev_path(path), encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


# ── join cases with the capture raw records and attach the Analyzer ──────────
def build_units(cases, raw):
    raw_by_id = {r["case_id"]: r for r in raw}
    units, problems, excluded = [], [], 0
    for c in cases:
        r = raw_by_id.get(c["case_id"])
        if r is None:
            problems.append(f"no capture record for {c['case_id']}")
            continue
        # the text actually scored = what the gateway rendered (captured) when fidelity held
        scored_text = c["request_text"] if r.get("capture_ok") else None
        if scored_text is None:
            excluded += 1  # fidelity failed; not scored (handled transparently, not silently)
            units.append({**_base(c, r), "scored": False, "exclude_reason": "capture_not_faithful"})
            continue
        if r.get("v4_decision") is None:
            excluded += 1
            units.append({**_base(c, r), "scored": False, "exclude_reason": "v4_classify_error"})
            continue
        units.append({**_base(c, r), "scored": True, "text": scored_text,
                      "text_sha256": c["request_sha256"]})
    return units, problems, excluded


def _base(c, r):
    return {"case_id": c["case_id"], "group_id": c["group_id"], "pair_id": c["pair_id"],
            "role": c["role"], "label": c["label"], "family": c["family"],
            "technique": c["technique"], "endpoint": c["endpoint"], "placement": c["placement"],
            "host": c["host"], "signal_location": c["signal_location"],
            "d47_category": c["d47_category"], "conclusion_family": c["conclusion_family"],
            "payload_canonical": c.get("payload_canonical"),
            "sink_type": c.get("sink_type"),
            "independent_attack_unit": c.get("independent_attack_unit", False),
            "placement_variant": c.get("placement_variant", False),
            "v4_decision": r.get("v4_decision"), "v4_reason": r.get("v4_reason"),
            "v4_status": r.get("v4_status"), "gateway_enforced": r.get("gateway_enforced"),
            "gateway_consistent": r.get("gateway_consistent"), "capture_ok": r.get("capture_ok")}


# V4 decision helpers — INVALID and classify/gateway errors are NEVER a false negative (owner
# pre-scoring finding). A false negative is only a genuine ALLOW decision on an attack.
def is_block(u):
    return u.get("v4_decision") == "BLOCK"


def is_allow(u):
    return u.get("v4_decision") == "ALLOW"


def is_invalid(u):
    return u.get("v4_decision") == "INVALID"


def hash_problems(before, after, expected):
    """Both before and after are checked EXPLICITLY against expected (owner finding: a chained
    `before != after != expected` does not reject every mismatch). Returns a list of problems."""
    out = []
    if before != expected:
        out.append("analyzer artifact hash != expected BEFORE inference")
    if after != expected:
        out.append("analyzer artifact hash != expected AFTER inference")
    if before != after:
        out.append("analyzer artifact hash changed during the run")
    return out


def attach_analyzer(units, analyzer, sets, v4_train_texts, v4_eval_texts):
    scored = [u for u in units if u.get("scored")]
    feats = [rf.extract_features(u["text"]) for u in scored]
    p = np.asarray(analyzer.attack_proba(feats), dtype=float) if scored else np.zeros(0)
    pc = np.asarray(analyzer.category_proba(feats), dtype=float) if scored else np.zeros((0, 8))
    cats = list(ha.CATEGORIES)
    for u, f, pa, row in zip(scored, feats, p, pc):
        vec = ev.vector_hash(f)
        canon = da.sha_text(ev.canonical_request(u["text"]))
        top = int(row.argmax())
        u.update({
            "attack": float(pa), "band": da.band(float(pa)), "extreme": da.extreme(float(pa)),
            "category_top1": cats[top], "category_top1_p": float(row[top]),
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


# ── aggregation (pure; synthetic-testable) ───────────────────────────────────
def scored(units):
    return [u for u in units if u.get("scored")]


def summary_stats(values):
    v = np.asarray(values, dtype=float)
    if not len(v):
        return {"n": 0}
    return {"n": int(len(v)), "min": round(float(v.min()), 4),
            "median": round(float(np.median(v)), 4), "max": round(float(v.max()), 4)}


def label_v4_band(units):
    return da.crosstab(scored(units), keys=("label", "v4_decision", "band"))


def family_tables(units):
    out = {}
    for fam, us in _group_by(scored(units), "family").items():
        attacks = [u for u in us if u["role"] == "attack"]
        groups = {u["group_id"] for u in us}
        techniques = {u["technique"] for u in us}
        blocked = [u for u in us if u["v4_decision"] == "BLOCK"]
        out[fam] = {
            "cases": len(us), "logical_groups": len(groups), "distinct_techniques": len(techniques),
            "role": us[0]["role"], "v4_block": len(blocked),
            "v4_allow": sum(1 for u in us if u["v4_decision"] == "ALLOW"),
            "v4_invalid": sum(1 for u in us if u["v4_decision"] == "INVALID"),
            "analyzer_bands": dict(Counter(u["band"] for u in us)),
            "attack_prob_all": summary_stats([u["attack"] for u in us]),
            "attack_prob_when_v4_block": summary_stats([u["attack"] for u in blocked]),
        }
    return out


def _family_block(us, label):
    """Descriptive block for a set of independent attack cases; V4 ALLOW is reported as
    'v4_allow' (a delivered attack V4 did not block), INVALID separately, never pooled."""
    return {
        label: len(us),
        "distinct_independent_payloads": len({u["payload_canonical"] for u in us}),
        "v4_block": sum(1 for u in us if is_block(u)),
        "v4_allow (delivered attack, not blocked)": sum(1 for u in us if is_allow(u)),
        "v4_invalid (NOT a false negative)": sum(1 for u in us if is_invalid(u)),
        "attack_prob": summary_stats([u["attack"] for u in us]),
        "v4_block_with_analyzer_below_0_1": sum(1 for u in us if is_block(u) and u["attack"] < 0.1),
        "v4_block_with_analyzer_below_0_5": sum(1 for u in us if is_block(u) and u["attack"] < 0.5),
        "v4_allow_with_analyzer_at_or_above_0_5": sum(1 for u in us if is_allow(u) and u["attack"] >= 0.5),
    }


def conclusion_family_view(units):
    """Category-level descriptive view over INDEPENDENT attack payloads only (placement variants
    excluded), reported only where a family has >= 30 distinct canonical payloads (D18). Each
    family is SPLIT by sink_type (natural_sink vs generic_carrier), because a V4 ALLOW on a token
    delivered into a free-text carrier is not an operational detection failure (audit NB-1)."""
    out = {}
    for fam in CONCLUSION_FAMILIES:
        us = [u for u in scored(units) if u["family"] == fam and u["independent_attack_unit"]]
        payloads = {u["payload_canonical"] for u in us}
        status = ("OK" if len(payloads) >= MIN_GROUPS
                  else "INSUFFICIENT INDEPENDENT SUPPORT (<30 distinct payloads)")
        natural = [u for u in us if u["sink_type"] == "natural_sink"]
        generic = [u for u in us if u["sink_type"] == "generic_carrier"]
        out[fam] = {
            "support_status": status, "distinct_independent_payloads": len(payloads),
            "independent_attack_cases": len(us),
            "natural_sink_note": ("field-role is a plausible injection point for this family; "
                                  "a V4 ALLOW here is the closest to a detection concern"),
            "all_independent": _family_block(us, "cases"),
            "natural_sink_only": _family_block(natural, "cases"),
            "generic_carrier_only (delivery/classification context, NOT detection)":
                _family_block(generic, "cases"),
        }
    return out


def pair_separation(units):
    """For each attack/benign pair on the same endpoint/placement: does V4 separate them (one
    BLOCK, one ALLOW)? does the Analyzer separate them (attack prob higher on the attack)?"""
    by_pair = defaultdict(dict)
    for u in scored(units):
        if u["family"] in ("benign_probe",):
            continue
        by_pair[u["pair_id"]][u["role"]] = u
    complete = v4_sep = an_sep_strict = both = neither = 0
    an_gap = []
    for pid, d in by_pair.items():
        if set(d) != {"attack", "benign"}:
            continue
        complete += 1
        a, b = d["attack"], d["benign"]
        v4s = (a["v4_decision"] == "BLOCK") and (b["v4_decision"] == "ALLOW")
        ans = a["attack"] > b["attack"]
        an_gap.append(a["attack"] - b["attack"])
        v4_sep += v4s
        an_sep_strict += ans
        both += v4s and ans
        neither += (not v4s) and (not ans)
    return {"complete_pairs": complete, "v4_separates (attack BLOCK & benign ALLOW)": v4_sep,
            "analyzer_attack_prob_higher_on_attack": an_sep_strict,
            "both_separate": both, "neither_separates": neither,
            "analyzer_prob_gap_attack_minus_benign": summary_stats(an_gap)}


def v4_false_positives(units):
    """Q1: benign cases V4 BLOCKs, split by Analyzer band."""
    fp = [u for u in scored(units) if u["label"] == "ALLOW" and u["v4_decision"] == "BLOCK"]
    return {"n_benign_v4_block": len(fp),
            "analyzer_below_0_1": sum(1 for u in fp if u["attack"] < 0.1),
            "analyzer_0_1_to_0_5": sum(1 for u in fp if 0.1 <= u["attack"] < 0.5),
            "analyzer_at_or_above_0_5": sum(1 for u in fp if u["attack"] >= 0.5),
            "by_band": dict(Counter(u["band"] for u in fp)),
            "by_placement": dict(Counter(u["placement"] for u in fp)),
            "v4_reasons": dict(Counter(f"{u['v4_reason']}" for u in fp))}


def attacks_v4_blocks_low_analyzer(units):
    """Q3a: attacks V4 correctly BLOCKs that the Analyzer scores low (surface vs header).
    Counted over INDEPENDENT attack payloads; distinct-payload counts reported."""
    tp = [u for u in scored(units) if u["label"] == "BLOCK" and is_block(u)
          and u["independent_attack_unit"]]
    low = [u for u in tp if u["attack"] < 0.1]
    low_surface = [u for u in low if u["signal_location"] == "surface"]
    return {"n_independent_attacks_v4_block": len(tp),
            "analyzer_below_0_1": len(low),
            "analyzer_below_0_1_surface": len(low_surface),
            "analyzer_below_0_1_surface_distinct_payloads":
                len({u["payload_canonical"] for u in low_surface}),
            "analyzer_below_0_1_surface_by_family": dict(Counter(u["family"] for u in low_surface)),
            "analyzer_below_0_5": sum(1 for u in tp if u["attack"] < 0.5)}


def attacks_v4_misses_high_analyzer(units):
    """Q3b: attacks V4 did NOT block. A genuine ALLOW is split by sink_type; INVALID outputs are
    a separate bucket and are NEVER a false negative. 'Detection concern' language is reserved
    for natural_sink ALLOWs; generic_carrier ALLOWs are reported as delivery context (NB-1)."""
    atk = [u for u in scored(units) if u["label"] == "BLOCK" and u["independent_attack_unit"]]
    allow = [u for u in atk if is_allow(u)]
    invalid = [u for u in atk if is_invalid(u)]
    allow_nat = [u for u in allow if u["sink_type"] == "natural_sink"]
    allow_gen = [u for u in allow if u["sink_type"] == "generic_carrier"]
    return {"n_independent_attacks": len(atk),
            "v4_allow_total (delivered attacks not blocked)": len(allow),
            "v4_allow_natural_sink (closest to a detection concern)": len(allow_nat),
            "v4_allow_generic_carrier (delivery/classification context, not detection)": len(allow_gen),
            "v4_invalid_outputs (NOT false negatives)": len(invalid),
            "allow_natural_sink_analyzer_at_or_above_0_5": sum(1 for u in allow_nat if u["attack"] >= 0.5),
            "allow_total_analyzer_at_or_above_0_5": sum(1 for u in allow if u["attack"] >= 0.5),
            "allow_total_analyzer_at_or_above_0_9": sum(1 for u in allow if u["attack"] >= 0.9),
            "allow_by_family": dict(Counter(u["family"] for u in allow)),
            "allow_natural_sink_by_family": dict(Counter(u["family"] for u in allow_nat)),
            "invalid_by_family": dict(Counter(u["family"] for u in invalid))}


def benign_high_probes(units):
    """Benign standalone probes the Analyzer scores high (structures flagged in #57)."""
    probes = [u for u in scored(units) if u["family"] == "benign_probe"]
    return {"n_probes": len(probes),
            "analyzer_at_or_above_0_5": sum(1 for u in probes if u["attack"] >= 0.5),
            "by_band": dict(Counter(u["band"] for u in probes)),
            "v4_block": sum(1 for u in probes if u["v4_decision"] == "BLOCK")}


def signal_location_table(units):
    out = {}
    for loc, us in _group_by(scored(units), "signal_location").items():
        atk = [u for u in us if u["role"] == "attack"]
        out[loc] = {"cases": len(us), "attack_cases": len(atk),
                    "attack_v4_block": sum(1 for u in atk if u["v4_decision"] == "BLOCK"),
                    "attack_analyzer_below_0_1": sum(1 for u in atk if u["attack"] < 0.1),
                    "attack_analyzer": summary_stats([u["attack"] for u in atk])}
    return out


def category_head(units):
    """D46 auxiliary category top-1 agreement on attacks with a D47 mapping (context only)."""
    mapped = [u for u in scored(units) if u["role"] == "attack" and u.get("d47_category")]
    agree = sum(1 for u in mapped if u["category_top1"] == u["d47_category"])
    per = defaultdict(lambda: Counter())
    for u in mapped:
        per[u["d47_category"]][u["category_top1"]] += 1
    return {"attack_cases_with_mapping": len(mapped), "top1_agrees": agree,
            "by_expected": {k: dict(v) for k, v in sorted(per.items())}}


def overlap(units):
    us = scored(units)
    keys = ("seen_train_validation", "seen_train_validation_jwt", "in_internal_test_relation",
            "exact_text_in_v4_train", "exact_text_in_v4_eval")
    return {k: {"allow": sum(1 for u in us if u.get(k) and u["label"] == "ALLOW"),
                "block": sum(1 for u in us if u.get(k) and u["label"] == "BLOCK")} for k in keys}


def _group_by(units, key):
    g = defaultdict(list)
    for u in units:
        g[u[key]].append(u)
    return dict(g)


def honest_units(units):
    us = scored(units)
    atk = [u for u in us if u["role"] == "attack"]
    indep = [u for u in atk if u["independent_attack_unit"]]
    pvar = [u for u in atk if u["placement_variant"]]
    twins = [u for u in us if u["family"] == "benign_twin"]
    probes = [u for u in us if u["family"] == "benign_probe"]

    def uv(xs):
        return len({u["feature_vector_sha256"] for u in xs})

    return {
        "note": "independent unit = distinct canonical attack payload (one placement each); "
                "placement variants and reused benign texts are NEVER independent observations",
        "scored_records": len(us),
        "unique_feature_vectors_scored": uv(us),
        "attack_records": len(atk),
        "independent_attack_records (per-family distinct canonical payload)": len(indep),
        "distinct_family_canonical_pairs (the independence unit)":
            len({(u["family"], u["payload_canonical"]) for u in indep}),
        "distinct_canonical_payload_strings": len({u["payload_canonical"] for u in indep}),
        "cross_family_shared_canonical_strings":
            sum(1 for s in {u["payload_canonical"] for u in indep}
                if len({u["family"] for u in indep if u["payload_canonical"] == s}) > 1),
        "placement_sensitivity_variant_records (DEPENDENT)": len(pvar),
        "conclusion_family_sink_coverage (independent attacks)": {
            fam: {"natural_sink": sum(1 for u in indep if u["family"] == fam
                                      and u["sink_type"] == "natural_sink"),
                  "generic_carrier": sum(1 for u in indep if u["family"] == fam
                                         and u["sink_type"] == "generic_carrier")}
            for fam in CONCLUSION_FAMILIES},
        "benign_twin_records": len(twins),
        "benign_twin_unique_vectors": uv(twins),
        "benign_probe_records": len(probes),
        "v4_invalid_outputs_total": sum(1 for u in us if is_invalid(u)),
    }


def gateway_consistency(units):
    us = scored(units)
    agree = sum(1 for u in us if u.get("gateway_consistent") is True)
    disagree = sum(1 for u in us if u.get("gateway_consistent") is False)
    none = sum(1 for u in us if u.get("gateway_consistent") is None)
    return {"scored": len(us), "enforcement_agrees_with_classify": agree,
            "disagree": disagree, "not_comparable": none,
            "note": "pass-2 data-plane enforcement (403/503/forward) vs pass-3 /classify decision "
                    "on the same text; agreement is the empirical bridge between the two paths"}


CAPTURE_CLAIM = (
    "What pass 1 establishes: the D1 text the SAME production render_request() produces from the "
    "wire bytes (the capture proxy imports data_plane.render_request; object identity is asserted "
    "by tests/test_external_capture). It is NOT a byte-capture of the live data-plane -> "
    "control-plane channel. The data plane is shown to behave consistently with this text by "
    "pass 2 (enforcement) vs pass 3 (/classify) agreement, reported in gateway_consistency. "
    "The text scored by both models is this captured text (identical to the designed text when "
    "capture_ok).")


def analyse(units):
    return {
        "honest_units": honest_units(units),
        "capture_fidelity_claim": CAPTURE_CLAIM,
        "gateway_consistency": gateway_consistency(units),
        "counts": {"total_cases": len(units), "scored": len(scored(units)),
                   "excluded": sum(1 for u in units if not u.get("scored")),
                   "exclude_reasons": dict(Counter(u.get("exclude_reason") for u in units
                                                   if not u.get("scored")))},
        "label_x_v4_x_band (texts; descriptive bins, 0.5 is D55 reporting-only)": label_v4_band(units),
        "at_reporting_threshold_0_5 (D55, not an operating point)": da.at_reporting_threshold(scored(units)),
        "vector_level (primary Analyzer unit; one row per distinct feature vector)":
            da.vector_level(scored(units)),
        "per_family": family_tables(units),
        "conclusion_families (category-level; only where >=30 groups, D18)": conclusion_family_view(units),
        "paired_separation": pair_separation(units),
        "q1_v4_false_positives": v4_false_positives(units),
        "q3a_attacks_v4_blocks_low_analyzer": attacks_v4_blocks_low_analyzer(units),
        "q3b_attacks_v4_misses_high_analyzer": attacks_v4_misses_high_analyzer(units),
        "q_benign_high_probes": benign_high_probes(units),
        "signal_location": signal_location_table(units),
        "category_head (context only, D46)": category_head(units),
        "extremes (attack < 0.01 or >= 0.99)": da.extremes(scored(units)),
        "data_role_overlap (membership only)": overlap(units),
        "external_v1_overlap": "UNKNOWN — never opened (D53); this set is development data and "
                               "is not an independent test of the Hybrid system",
    }


def cmd_run(args):
    out_dir = args.out_dir
    for name in ("records.jsonl", "results.json"):
        if os.path.exists(os.path.join(out_dir, name)):
            raise SystemExit(f"REFUSING to overwrite {name}")
    cases = read_jsonl(args.cases)
    raw = read_jsonl(args.raw)
    model_path = os.path.join(REPO_ROOT, ev.ANCHORS["model_path"])
    model_before = ev.sha256_file(model_path)
    analyzer = ev.load_model(da.dev_path(model_path), ev.ANCHORS["model_sha256"])
    dataset = da.load_membership()
    sets = da.role_sets(dataset)
    v4_train = read_jsonl(da.V4_TRAIN)
    v4_eval_texts = {da.sha_text(r["input"]) for r in read_jsonl(da.V4_EVAL)}
    checked, ok = da.canonical_relation_check(dataset, v4_train)
    v4_train_texts = {da.sha_text(r["input"]) for r in v4_train}
    del dataset, v4_train
    units, problems, excluded = build_units(cases, raw)
    attach_analyzer(units, analyzer, sets, v4_train_texts, v4_eval_texts)
    model_after = ev.sha256_file(model_path)
    if ok != checked or checked == 0:
        problems.append("canonical relation does not reproduce the v2 build")
    expected = ev.ANCHORS["model_sha256"]
    problems += hash_problems(model_before, model_after, expected)
    capture_meta_path = os.path.join(out_dir, "raw", "capture_run_meta.json")
    capture_meta = json.load(open(capture_meta_path)) if os.path.exists(capture_meta_path) else None
    result = {
        "run": "v4-analyzer-paired-dev-v1",
        "type": "DIAGNOSTIC on DEVELOPMENT data (issue #59); not an evaluation or external test",
        "created_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "git_head": ev._git("rev-parse", "HEAD").stdout.strip(),
        "analyzer_version": analyzer.version, "model_sha256_before": model_before,
        "model_sha256_after": model_after, "model_sha256_expected": expected,
        "model_unchanged_and_matches_expected":
            (model_before == expected) and (model_after == expected),
        "v4_adapter_sha256_expected": "7bf168758a428fa7775dff0328de3d07d3063ddf99b961dc8b8406a0dce93de1",
        "canonical_relation_check": {"rows_checked": checked, "rows_equal": ok},
        "bands (descriptive, fixed)": list(da.BAND_LABELS),
        "evaluator_sha256": ev.sha256_file(os.path.abspath(__file__)),
        "generator_sha256": ev.sha256_file(os.path.join(REPO_ROOT, "scripts", "evaluation",
                                                        "paired_dev_set.py")),
        "capture_sha256": ev.sha256_file(os.path.join(REPO_ROOT, "scripts", "evaluation",
                                                      "paired_dev_capture.py")),
        "cases_sha256": ev.sha256_file(args.cases),
        "protocol_sha256": ev.sha256_file(os.path.join(out_dir, "PROTOCOL.md"))
        if os.path.exists(os.path.join(out_dir, "PROTOCOL.md")) else None,
        "capture_meta": capture_meta,
        "problems": problems,
        **analyse(units),
    }
    records = "".join(json.dumps(u, ensure_ascii=False) + "\n" for u in units)
    with open(os.path.join(out_dir, "records.jsonl"), "x", encoding="utf-8") as f:
        f.write(records)
    with open(os.path.join(out_dir, "results.json"), "x", encoding="utf-8") as f:
        f.write(json.dumps(result, indent=2, ensure_ascii=False) + "\n")
    print(f"scored {len(scored(units))}/{len(units)} cases (excluded {excluded}); "
          f"problems: {problems or 'none'}")
    return 0 if not problems else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.strip().split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--cases", default=os.path.join(REPORT_DIR, "cases.jsonl"))
    r.add_argument("--raw", default=os.path.join(REPORT_DIR, "raw", "records_raw.jsonl"))
    r.add_argument("--out-dir", default=REPORT_DIR)
    args = ap.parse_args(argv)
    return {"run": cmd_run}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
