"""
firewall-IA — V4 minimal-pair probe v2 (`v5-minimal-pairs-v2`): scoring and analysis.

DEVELOPMENT DIAGNOSTIC. Inference only on the frozen V4 (unchanged `inference_core`, greedy
decoding): nothing is trained, tuned or thresholded on the model. The cases come from
`minimal_pair_probe_v2_cases.py` and are anchored by `SHA256SUMS` before scoring. The analysis
reuses the v1 statistics (exact McNemar, Holm, Clopper-Pearson, pre-registered effect classes);
v2 has one CONTENT Holm family and one content instability control (`CONTROL-COV2`), and groups
each comparison by the per-case `stratum`.

  run      (ML environment) Verifies every pre-registered hash, then:
           phase 1 — determinism: the repeat subset is scored REPEAT_RUNS times; any divergence in
                     the raw output stops the run before phase 2;
           phase 2 — every unique text once, in a seeded shuffled order.
           Writes raw/records.jsonl and raw/run_meta.json; refuses to overwrite.
  analyze  (standard library) Offline and deterministic: per comparison, paired 2x2 counts, flip
           rates, exact McNemar (two-sided), Holm, Clopper-Pearson intervals, per-stratum counts and
           the pre-registered effect class. Writes results.json and results_table.md.

    python3 scripts/evaluation/minimal_pair_probe_v2_cases.py --out-dir reports/v5/minimal-pair-probe-v2
    python3.12 scripts/evaluation/run_v4_minimal_pair_probe_v2.py run --dir reports/v5/minimal-pair-probe-v2
    python3 scripts/evaluation/run_v4_minimal_pair_probe_v2.py analyze --dir reports/v5/minimal-pair-probe-v2
"""

import argparse
import hashlib
import json
import math
import os
import platform
import random
import re
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ADAPTER_SHA256 = "7bf168758a428fa7775dff0328de3d07d3063ddf99b961dc8b8406a0dce93de1"
INFERENCE_CORE_SHA256 = "325e3149ef014e2422f1a1a41337b1a8f8d41b5ccba8016b547f9573d7f0f954"
ANALYSIS_VERSION = "v5-minimal-pairs-v2/analysis-2"
ORDER_SEED = "v5-minimal-pairs-v2|order"

ANCHORED = {
    "PROTOCOL.md": "{dir}/PROTOCOL.md",
    "manifest.json": "{dir}/manifest.json",
    "cases.jsonl": "{dir}/cases.jsonl",
    "minimal_pair_probe_v2_cases.py": "scripts/evaluation/minimal_pair_probe_v2_cases.py",
    "run_v4_minimal_pair_probe_v2.py": "scripts/evaluation/run_v4_minimal_pair_probe_v2.py",
}

# ── Pre-registered analysis constants (PROTOCOL.md §5) ──────────────────────────────────────
ALPHA = 0.05
STRONG_DOMINANT_RATE = 0.20
STRONG_CONSISTENCY = 0.80
MODERATE_DOMINANT_RATE = 0.10
MODERATE_MIN_DOMINANT = 6
MODERATE_CONSISTENCY = 0.80
TESTABLE_FRACTION = 2 / 3        # a direction is testable only if that side's reference >= 2n/3
STRATUM_EFFECT_MIN = 6          # per-stratum (n≈15): A->B >= 6 to call an effect
STRATUM_NULL_MAX = 2           # per-stratum: A->B <= 2 (with reference-ALLOW >= 10) to call a testable null
STRATUM_NULL_REF_ALLOW_MIN = 10
INVALID_FLAG_FRACTION = 0.05
INSTABILITY_MATERIAL_LOWER = 0.05
CONTENT_CONTROL = "CONTROL-COV2:val_a->val_b"
HOLM_FAMILIES = ("CONTENT",)


def matched_control(comp):
    """Every v2 non-control comparison (all CONTENT) is compared with the content control."""
    return CONTENT_CONTROL


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_jsonl(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def verify_anchor(probe_dir):
    sums = {}
    with open(os.path.join(probe_dir, "SHA256SUMS"), encoding="utf-8") as f:
        for line in f:
            if line.strip():
                digest, name = line.split(maxsplit=1)
                sums[name.strip()] = digest
    rel_dir = os.path.relpath(probe_dir, REPO_ROOT)
    out = {}
    for name, tmpl in ANCHORED.items():
        actual = sha256_file(os.path.join(REPO_ROOT, tmpl.format(dir=rel_dir)))
        if sums.get(name) != actual:
            raise SystemExit(f"ANCHOR MISMATCH: {name} is {actual}, SHA256SUMS says {sums.get(name)}")
        out[name] = actual
    with open(os.path.join(probe_dir, "manifest.json"), encoding="utf-8") as f:
        manifest = json.load(f)
    if manifest["cases_sha256"] != out["cases.jsonl"]:
        raise SystemExit("cases.jsonl does not match the manifest")
    return out, manifest


# ── run ─────────────────────────────────────────────────────────────────────────────────────
def cmd_run(args):
    probe_dir = os.path.abspath(args.dir)
    anchors, manifest = verify_anchor(probe_dir)
    raw_dir = os.path.join(probe_dir, "raw")
    rec_path, meta_path = os.path.join(raw_dir, "records.jsonl"), os.path.join(raw_dir, "run_meta.json")
    for p in (rec_path, meta_path):
        if os.path.exists(p):
            raise SystemExit(f"REFUSING to overwrite {p} (scoring runs once)")
    cases = load_jsonl(os.path.join(probe_dir, "cases.jsonl"))
    text_of = {c["text_sha256"]: c["text"] for c in cases}
    repeat = manifest["repeat_control"]["text_sha256"]
    runs = manifest["repeat_control"]["runs"]

    ic_path = os.path.join(REPO_ROOT, "control_plane", "inference_core.py")
    if sha256_file(ic_path) != INFERENCE_CORE_SHA256:
        raise SystemExit("inference_core.py differs from the pre-registered hash (325e3149…)")
    sys.path.insert(0, os.path.join(REPO_ROOT, "control_plane"))
    import inference_core as ic  # noqa: E402  (ML environment only)
    adapter_file = os.path.join(ic.DEFAULT_ADAPTER_DIR, "adapter_model.safetensors")
    if sha256_file(adapter_file) != ADAPTER_SHA256:
        raise SystemExit("V4 adapter differs from model-output-v4-clean (7bf16875…)")
    started = datetime.now(timezone.utc).isoformat(timespec="seconds")
    tok, mdl = ic.load_model(ic.DEFAULT_ADAPTER_DIR)
    device = ic.resolve_device()

    os.makedirs(raw_dir, exist_ok=True)
    divergent = []
    n_done = 0
    with open(rec_path, "x", encoding="utf-8") as f:
        def score(sha, phase, rep, order):
            nonlocal n_done
            raw, m = ic.classify_timed(tok, mdl, text_of[sha], device)
            decision, reason, status = ic.parse_prediction(raw)
            rec = {"text_sha256": sha, "phase": phase, "rep": rep, "order": order, "raw": raw,
                   "decision": decision, "reason": reason, "status": status,
                   "prompt_tokens": m["prompt_tokens"], "generated_tokens": m["generated_tokens"],
                   "generate_ms_observation_only": round(m["generate_ms"], 3)}
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            n_done += 1
            if n_done % 100 == 0:
                print(f"{n_done} classifications", flush=True)
            return rec

        first = {}
        for rep in range(runs):
            for k, sha in enumerate(repeat):
                rec = score(sha, "determinism", rep, k)
                if rep == 0:
                    first[sha] = rec["raw"]
                elif rec["raw"] != first[sha]:
                    divergent.append({"text_sha256": sha, "rep": rep})
        f.flush()
        if divergent:
            print(f"DETERMINISM FAILURE on {len(divergent)} repeats — phase 2 not run", flush=True)
        else:
            order = sorted(text_of)
            random.Random(ORDER_SEED).shuffle(order)
            for k, sha in enumerate(order):
                rec = score(sha, "main", 0, k)
                if sha in first and rec["raw"] != first[sha]:
                    divergent.append({"text_sha256": sha, "rep": "main"})

    adapter_after = sha256_file(adapter_file)
    import torch
    import transformers
    import peft
    meta = {"started_utc": started,
            "finished_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "anchors_verified": anchors, "adapter_model_sha256_before": ADAPTER_SHA256,
            "adapter_model_sha256_after": adapter_after,
            "adapter_unchanged": adapter_after == ADAPTER_SHA256,
            "inference_core_sha256": sha256_file(os.path.join(REPO_ROOT, "control_plane", "inference_core.py")),
            "git_head": subprocess.run(["git", "-C", REPO_ROOT, "rev-parse", "HEAD"],
                                       capture_output=True, text=True).stdout.strip(),
            "environment": {"python": platform.python_version(), "torch": torch.__version__,
                            "transformers": transformers.__version__, "peft": peft.__version__,
                            "device": str(device),
                            "gpu": torch.cuda.get_device_name(0) if torch.cuda.is_available() else None},
            "decoding": "greedy (inference_core.classify_timed = classify_raw path, unchanged)",
            "n_classifications": n_done, "n_unique_texts": len(text_of),
            "repeat_texts": len(repeat), "repeat_runs": runs,
            "determinism_divergences": divergent, "main_phase_run": not any(
                d["rep"] != "main" for d in divergent)}
    with open(meta_path, "x", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(json.dumps({"n_classifications": n_done, "divergences": len(divergent)}))
    return 0 if not divergent and meta["adapter_unchanged"] else 1


# ── statistics (standard library) ────────────────────────────────────────────────────────────
def binom_cdf(k, n, p=0.5):
    if k < 0:
        return 0.0
    return min(1.0, sum(math.comb(n, i) * p ** i * (1 - p) ** (n - i) for i in range(0, min(k, n) + 1)))


def mcnemar_exact(b, c):
    n = b + c
    if n == 0:
        return 1.0
    return min(1.0, 2 * binom_cdf(min(b, c), n))


def holm(pvalues, alpha=ALPHA):
    m = len(pvalues)
    order = sorted(range(m), key=lambda i: pvalues[i])
    adj = [0.0] * m
    running = 0.0
    for rank, i in enumerate(order):
        running = max(running, min(1.0, (m - rank) * pvalues[i]))
        adj[i] = running
    return adj, [a < alpha for a in adj]


def clopper_pearson(k, n, conf=0.95):
    if n == 0:
        return (0.0, 1.0)
    a = (1 - conf) / 2
    lower = 0.0 if k == 0 else _cp_lower(k, n, a)
    upper = 1.0 if k == n else _cp_upper(k, n, a)
    return (lower, upper)


def _cp_upper(k, n, a):
    lo, hi = k / n, 1.0
    for _ in range(200):
        mid = (lo + hi) / 2
        if binom_cdf(k, n, mid) > a:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2


def _cp_lower(k, n, a):
    lo, hi = 0.0, k / n
    for _ in range(200):
        mid = (lo + hi) / 2
        if 1 - binom_cdf(k - 1, n, mid) < a:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2


# ── classification (pre-registered, PROTOCOL.md §5) ────────────────────────────────────────
def classify_effect(row, control=None):
    """Direction-aware, control-relative class (PROTOCOL.md §5). A->B is the hypothesised
    direction; a B->A (reverse) result is labelled and does not support the FP hypotheses.
    A 0-discordant result is only 'NO OBSERVED EFFECT' when A->B was *testable* (enough
    reference-ALLOW bases); otherwise it is 'NO OBSERVED (UNTESTABLE)' and cannot falsify."""
    ab, ba, n = row["A_to_B"], row["B_to_A"], row["n_valid_pairs"]
    disc = ab + ba
    if n == 0:
        return "INSUFFICIENT DATA"
    if disc == 0:
        return "NO OBSERVED EFFECT" if row.get("testable_A_to_B") else "NO OBSERVED (UNTESTABLE)"
    dominant = max(ab, ba)
    direction = "A→B" if ab >= ba else "B→A"
    consistency = dominant / disc
    beats_control = control is None or (row["flip_rate"] > control["flip_rate_ci95"][1])
    raw_sig = row.get("mcnemar_exact_p_two_sided", 1.0) < ALPHA
    if (dominant / n >= STRONG_DOMINANT_RATE and consistency >= STRONG_CONSISTENCY
            and row["holm_reject"] and beats_control):
        return f"STRONG EFFECT ({direction})"
    if (dominant / n >= MODERATE_DOMINANT_RATE and dominant >= MODERATE_MIN_DOMINANT
            and consistency >= MODERATE_CONSISTENCY and beats_control and raw_sig):
        return f"MODERATE EFFECT ({direction})"
    return "WEAK/INCONCLUSIVE"


def paired_table(pairs):
    t = Counter()
    invalid = 0
    for r, l in pairs:
        if r is None or l is None:
            invalid += 1
            continue
        t[(r, l)] += 1
    aa, ab = t[("ALLOW", "ALLOW")], t[("ALLOW", "BLOCK")]
    ba, bb = t[("BLOCK", "ALLOW")], t[("BLOCK", "BLOCK")]
    n = aa + ab + ba + bb
    disc = ab + ba
    row = {"n_bases": len(pairs), "n_invalid_pairs": invalid, "n_valid_pairs": n,
           "ALLOW_to_ALLOW": aa, "A_to_B": ab, "B_to_A": ba, "BLOCK_to_BLOCK": bb,
           "flip_rate": disc / n if n else None,
           "flip_rate_ci95": list(clopper_pearson(disc, n)) if n else None,
           "net_direction": (ab - ba) / n if n else None,
           "baseline_allow_rate": (aa + ab) / n if n else None,
           "paired_allow_rate": (aa + ba) / n if n else None,
           "conditional_A_to_B": ab / (aa + ab) if aa + ab else None,
           "conditional_A_to_B_ci95": list(clopper_pearson(ab, aa + ab)) if aa + ab else None,
           "conditional_B_to_A": ba / (ba + bb) if ba + bb else None,
           "conditional_B_to_A_ci95": list(clopper_pearson(ba, ba + bb)) if ba + bb else None,
           "direction_consistency": max(ab, ba) / disc if disc else None,
           "mcnemar_exact_p_two_sided": mcnemar_exact(ab, ba)}
    ref_allow, ref_block = aa + ab, ba + bb
    thr = math.ceil(TESTABLE_FRACTION * n) if n else 0
    row["reference_allow"], row["reference_block"] = ref_allow, ref_block
    row["testable_A_to_B"] = n > 0 and ref_allow >= thr
    row["testable_B_to_A"] = n > 0 and ref_block >= thr
    flags = []
    if n and not row["testable_A_to_B"]:
        flags.append(f"UNTESTABLE_A_TO_B (reference-ALLOW {ref_allow} < {thr} = ceil(2n/3))")
    if n and invalid / len(pairs) > INVALID_FLAG_FRACTION:
        flags.append(f"HIGH_INVALID ({invalid}/{len(pairs)} pairs dropped)")
    row["flags"] = flags
    return row


def stratum_verdict(row, c_hi):
    """Per-stratum (n≈15) pre-registered verdict (PROTOCOL.md §7): 'effect(dir)',
    'no effect (testable)', or 'indeterminate'. Used for the B/C heterogeneity rule."""
    ab, ba, n = row["A_to_B"], row["B_to_A"], row["n_valid_pairs"]
    if n == 0:
        return "indeterminate"
    if ab >= STRATUM_EFFECT_MIN and row["direction_consistency"] and row["direction_consistency"] >= 0.80 \
            and row["flip_rate"] > c_hi and ab >= ba:
        return "effect (A→B)"
    if ab <= STRATUM_NULL_MAX and row["reference_allow"] >= STRATUM_NULL_REF_ALLOW_MIN:
        return "no effect (testable)"
    return "indeterminate"


PCT_RE = re.compile(r"%[0-9A-Fa-f]{2}")


def _span(xs):
    return {"min": min(xs), "max": max(xs), "mean": round(sum(xs) / len(xs), 2)} if xs else None


def analyze(cases, manifest, records):
    main = {r["text_sha256"]: r for r in records if r["phase"] == "main"}
    det = defaultdict(list)
    for r in records:
        if r["phase"] == "determinism":
            det[r["text_sha256"]].append(r)
    divergent_raw = divergent_decision = divergent_reason = 0
    for sha, rs in det.items():
        allr = rs + ([main[sha]] if sha in main else [])
        divergent_raw += len({x["raw"] for x in allr}) > 1
        divergent_decision += len({(x["status"], x["decision"]) for x in allr}) > 1
        divergent_reason += len({x["reason"] for x in allr}) > 1
    deterministic = divergent_raw == 0 and len(det) == len(manifest["repeat_control"]["text_sha256"])

    by_key = {(c["factor"], c["base"], c["level"]): c for c in cases}

    def dec(c):
        r = main.get(c["text_sha256"])
        if r is None or r["status"] != "ok":
            return None
        return r["decision"]

    rows = []
    for comp in manifest["comparisons"]:
        fid, ref, lv = comp["factor"], comp["reference"], comp["level"]
        pairs, strata, reason_changes, flip_reasons = [], defaultdict(list), 0, Counter()
        d_len, d_pct, d_tok = [], [], []
        for i in range(comp["n_bases"]):
            cr, cl = by_key[(fid, i, ref)], by_key[(fid, i, lv)]
            d = (dec(cr), dec(cl))
            pairs.append(d)
            strata[cr.get("stratum", "all")].append(d)
            rr, rl = main.get(cr["text_sha256"]), main.get(cl["text_sha256"])
            d_len.append(len(cl["text"]) - len(cr["text"]))
            d_pct.append(len(PCT_RE.findall(cl["text"])) - len(PCT_RE.findall(cr["text"])))
            if rr and rl and "prompt_tokens" in rr and "prompt_tokens" in rl:
                d_tok.append(rl["prompt_tokens"] - rr["prompt_tokens"])
            if d[0] is not None and d[0] == d[1] and rr["reason"] != rl["reason"]:
                reason_changes += 1
            if d[0] is not None and d[1] is not None and d[0] != d[1]:
                flip_reasons[(rl if d[1] == "BLOCK" else rr)["reason"]] += 1
        row = {**comp, **paired_table(pairs),
               "same_decision_reason_changed": reason_changes,
               "block_reasons_in_flips": dict(flip_reasons.most_common()),
               "matched_control": matched_control(comp) if comp["block"] != "CONTROL" else None,
               "side_effects_level_minus_reference": {
                   "chars": _span(d_len), "percent_triplets": _span(d_pct), "prompt_tokens": _span(d_tok)},
               "strata": {s: paired_table(p) for s, p in sorted(strata.items())}}
        rows.append(row)

    for fam in HOLM_FAMILIES:
        members = [r for r in rows if r["block"] == fam]
        adj, rej = holm([r["mcnemar_exact_p_two_sided"] for r in members])
        for r, a, j in zip(members, adj, rej):
            r["holm_family"], r["holm_family_size"] = fam, len(members)
            r["holm_adjusted_p"], r["holm_reject"] = a, j
    for r in rows:
        if r["block"] == "CONTROL":
            r["holm_family"], r["holm_family_size"], r["holm_adjusted_p"] = None, None, None
            r["holm_reject"] = r["mcnemar_exact_p_two_sided"] < ALPHA
    by_id = {r["comparison_id"]: r for r in rows}
    for r in rows:
        if not deterministic:
            r["effect_class"] = "WITHHELD (determinism failure)"
        else:
            r["effect_class"] = classify_effect(
                r, None if r["block"] == "CONTROL" else by_id[matched_control(r)])
    cov = by_id[CONTENT_CONTROL]
    c_hi = cov["flip_rate_ci95"][1] if cov["flip_rate_ci95"] else 1.0
    instability = {"control": CONTENT_CONTROL, "flip_rate": cov["flip_rate"],
                   "flip_rate_ci95": cov["flip_rate_ci95"], "C_hi": c_hi,
                   "per_stratum_flip_rate": {s: st["flip_rate"] for s, st in cov["strata"].items()},
                   "material": bool(cov["flip_rate_ci95"] and cov["flip_rate_ci95"][0] >= INSTABILITY_MATERIAL_LOWER),
                   "rule": f"material iff CP lower bound >= {INSTABILITY_MATERIAL_LOWER}; "
                           f"C_hi = CONTROL-COV2 flip-rate CP95 upper bound used as the effect bar"}
    # Per-stratum verdicts and the B/C heterogeneity flag (PROTOCOL.md §7).
    for r in rows:
        if r["block"] == "CONTROL":
            r["stratum_verdicts"], r["heterogeneous"] = {}, None
            continue
        if not deterministic:
            r["stratum_verdicts"], r["heterogeneous"] = {}, None
            continue
        sv = {s: stratum_verdict(st, c_hi) for s, st in r["strata"].items()}
        r["stratum_verdicts"] = sv
        vals = set(sv.values())
        r["heterogeneous"] = ("effect (A→B)" in vals and "no effect (testable)" in vals)
    host_ref = defaultdict(Counter)
    for comp in manifest["comparisons"]:
        for i in range(comp["n_bases"]):
            c = by_key[(comp["factor"], i, comp["reference"])]
            host = next((l[6:] for l in c["text"].split("\n") if l.startswith("Host: ")), "?")
            host_ref[host][dec(c) or "INVALID"] += 1

    status_counts = Counter(r["status"] for r in main.values())
    decision_counts = Counter(r["decision"] for r in main.values() if r["status"] == "ok")
    reasons = Counter(r["reason"] for r in main.values() if r["status"] == "ok" and r["decision"] == "BLOCK")
    return {
        "analysis_version": ANALYSIS_VERSION, "data_role": manifest["data_role"],
        "pre_registered": {"alpha": ALPHA, "test": "exact McNemar, two-sided",
                           "multiplicity": "Holm within the CONTENT family; control outside (raw p)",
                           "strong": {"dominant_rate": STRONG_DOMINANT_RATE, "consistency": STRONG_CONSISTENCY,
                                      "holm_reject": True,
                                      "flip_rate_above": "CONTROL-COV2 Clopper-Pearson 95% upper bound"},
                           "moderate": {"dominant_rate": MODERATE_DOMINANT_RATE,
                                        "min_dominant": MODERATE_MIN_DOMINANT,
                                        "consistency": MODERATE_CONSISTENCY, "raw_mcnemar_p_below": ALPHA,
                                        "flip_rate_above": "CONTROL-COV2 Clopper-Pearson 95% upper bound"},
                           "matched_control": CONTENT_CONTROL,
                           "direction": "A->B hypothesised; B->A labelled as reverse and non-supporting",
                           "no_observed_effect": "0 discordant pairs AND A->B testable (reference-ALLOW >= ceil(2n/3)); "
                                                 "otherwise NO OBSERVED (UNTESTABLE), which cannot falsify",
                           "testable_fraction": TESTABLE_FRACTION,
                           "stratum_rule": {"effect": f"A->B >= {STRATUM_EFFECT_MIN}/15, consistency >= 0.80, "
                                            "flip_rate > C_hi", "no_effect_testable":
                                            f"A->B <= {STRATUM_NULL_MAX} and reference-ALLOW >= {STRATUM_NULL_REF_ALLOW_MIN}",
                                            "heterogeneous": "at least one 'effect' stratum and one 'no effect (testable)' stratum"}},
        "instability": instability,
        "reference_decisions_by_host": {h: dict(c) for h, c in sorted(host_ref.items())},
        "determinism": {"repeat_texts": len(det), "divergent_raw": divergent_raw,
                        "divergent_decision": divergent_decision, "divergent_reason": divergent_reason,
                        "deterministic": deterministic},
        "global": {"n_unique_texts_scored": len(main), "status": dict(status_counts),
                   "decisions": dict(decision_counts),
                   "distinct_block_reasons": len(reasons),
                   "block_reasons": dict(reasons.most_common())},
        "comparisons": rows,
    }


def fmt(x, nd=2):
    return "—" if x is None else f"{x:.{nd}f}"


def table_md(res):
    lines = ["| Comparison | Block | N | A→A | A→B | B→A | B→B | flip rate [95% CI] | cond. A→B | "
             "base ALLOW | McNemar p | Holm p | Class | Flags |",
             "|---|---|---:|---:|---:|---:|---:|---|---:|---:|---:|---:|---|---|"]
    for r in res["comparisons"]:
        ci = r["flip_rate_ci95"]
        lines.append(
            f"| `{r['comparison_id']}` | {r['block']} | {r['n_valid_pairs']} | {r['ALLOW_to_ALLOW']} | "
            f"{r['A_to_B']} | {r['B_to_A']} | {r['BLOCK_to_BLOCK']} | {fmt(r['flip_rate'])} "
            f"[{fmt(ci[0]) if ci else '—'}, {fmt(ci[1]) if ci else '—'}] | {fmt(r['conditional_A_to_B'])} | "
            f"{fmt(r['baseline_allow_rate'])} | {fmt(r['mcnemar_exact_p_two_sided'], 4)} | "
            f"{fmt(r['holm_adjusted_p'], 4)} | {r['effect_class']} | "
            f"{'; '.join(f.split(' ')[0] for f in r['flags'])} |")
    return "\n".join(lines) + "\n"


def cmd_analyze(args):
    probe_dir = os.path.abspath(args.dir)
    anchors, manifest = verify_anchor(probe_dir)
    cases = load_jsonl(os.path.join(probe_dir, "cases.jsonl"))
    records = load_jsonl(os.path.join(probe_dir, "raw", "records.jsonl"))
    res = analyze(cases, manifest, records)
    res["anchors_verified"] = anchors
    res["records_sha256"] = sha256_file(os.path.join(probe_dir, "raw", "records.jsonl"))
    with open(os.path.join(probe_dir, "results.json"), "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2, ensure_ascii=False)
        f.write("\n")
    with open(os.path.join(probe_dir, "results_table.md"), "w", encoding="utf-8") as f:
        f.write(table_md(res))
    print(table_md(res))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.strip().split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("run", "analyze"):
        p = sub.add_parser(name)
        p.add_argument("--dir", required=True)
    args = ap.parse_args(argv)
    return cmd_run(args) if args.cmd == "run" else cmd_analyze(args)


if __name__ == "__main__":
    sys.exit(main())
