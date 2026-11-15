"""
firewall-IA — V4 minimal-pair probe (`v5-minimal-pairs-v1`): scoring and analysis.

DEVELOPMENT DIAGNOSTIC. Inference only on the frozen V4 (unchanged `inference_core`,
greedy decoding): nothing is trained, tuned or thresholded on the model. The cases come
from `minimal_pair_probe_cases.py` and are anchored by `SHA256SUMS` before scoring.

Two subcommands:

  run      (ML environment) Verifies every pre-registered hash, then:
           phase 1 — CONTROL-REP: the repeat subset is scored REPEAT_RUNS times; any
                     divergence in the raw output stops the run before phase 2;
           phase 2 — every unique text once, in a seeded shuffled order.
           Writes raw/records.jsonl and raw/run_meta.json; refuses to overwrite.
  analyze  (standard library) Offline and deterministic: per comparison, paired 2x2 counts,
           flip rates, exact McNemar (two-sided), Holm, Clopper-Pearson intervals and the
           pre-registered effect class. Writes results.json and results_table.md.

    python3 scripts/evaluation/minimal_pair_probe_cases.py --out-dir reports/v5/minimal-pair-probe-v1
    python3.12 scripts/evaluation/run_v4_minimal_pair_probe.py run --dir reports/v5/minimal-pair-probe-v1
    python3 scripts/evaluation/run_v4_minimal_pair_probe.py analyze --dir reports/v5/minimal-pair-probe-v1
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
ANALYSIS_VERSION = "v5-minimal-pairs-v1/analysis-2"
ORDER_SEED = "v5-minimal-pairs-v1|order"

# Files anchored in SHA256SUMS before any scoring (paths relative to the repo root).
ANCHORED = {
    "PROTOCOL.md": "{dir}/PROTOCOL.md",
    "manifest.json": "{dir}/manifest.json",
    "cases.jsonl": "{dir}/cases.jsonl",
    "minimal_pair_probe_cases.py": "scripts/evaluation/minimal_pair_probe_cases.py",
    "run_v4_minimal_pair_probe.py": "scripts/evaluation/run_v4_minimal_pair_probe.py",
}

# ── Pre-registered analysis constants (PROTOCOL.md §7) ─────────────────────────────────────
ALPHA = 0.05
STRONG_DOMINANT_RATE = 0.20     # dominant-direction flips / valid pairs
STRONG_CONSISTENCY = 0.80       # dominant / discordant
MODERATE_DOMINANT_RATE = 0.10
MODERATE_MIN_DOMINANT = 6
MODERATE_CONSISTENCY = 0.80
LOW_SENSITIVITY_MIN = 20        # fewer reference-ALLOW (or -BLOCK) bases => that direction is weakly testable
INSTABILITY_MATERIAL_LOWER = 0.05   # CONTROL-COV flip-rate CP lower bound at or above => instability material
CONTENT_CONTROL = "CONTROL-COV:user_a->user_b"
ENVELOPE_CONTROL = "CONTROL-ENV:absent->present"
HOLM_FAMILIES = ("ENVELOPE", "CONTENT")     # controls are outside every family (raw p only)


def matched_control(comp):
    """ENVELOPE comparisons and F-CTB (a header change) are compared with the envelope
    control; every other CONTENT comparison with the content control."""
    if comp["block"] == "ENVELOPE" or comp["factor"] == "F-CTB":
        return ENVELOPE_CONTROL
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
    """Every anchored file must match SHA256SUMS exactly; returns the verified digests."""
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


# ── run ────────────────────────────────────────────────────────────────────────────────────
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
            # classify_timed is the generation path classify_raw delegates to (unchanged);
            # it also returns the prompt/generated token counts.
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

        # Phase 1 — determinism control.
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
            # Phase 2 — main scoring, every unique text once, seeded order.
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


# ── statistics (standard library) ──────────────────────────────────────────────────────────
def binom_cdf(k, n, p=0.5):
    if k < 0:
        return 0.0
    return min(1.0, sum(math.comb(n, i) * p ** i * (1 - p) ** (n - i) for i in range(0, min(k, n) + 1)))


def mcnemar_exact(b, c):
    """Two-sided exact McNemar: binomial test of b vs c discordant pairs at p = 0.5."""
    n = b + c
    if n == 0:
        return 1.0
    return min(1.0, 2 * binom_cdf(min(b, c), n))


def holm(pvalues, alpha=ALPHA):
    """Holm step-down. Returns (adjusted p-values, reject flags), in input order."""
    m = len(pvalues)
    order = sorted(range(m), key=lambda i: pvalues[i])
    adj = [0.0] * m
    running = 0.0
    for rank, i in enumerate(order):
        running = max(running, min(1.0, (m - rank) * pvalues[i]))
        adj[i] = running
    return adj, [a < alpha for a in adj]


def clopper_pearson(k, n, conf=0.95):
    """Exact two-sided interval for a binomial proportion, by bisection on the CDF."""
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


# ── classification (pre-registered, PROTOCOL.md §7) ────────────────────────────────────────
def classify_effect(row, control=None):
    """STRONG / MODERATE / WEAK-INCONCLUSIVE / NO OBSERVED EFFECT for one comparison.

    `control` is the matched control row (None when classifying a control itself: the
    instability condition is then not applied and `holm_reject` is the raw-p test)."""
    ab, ba, n = row["A_to_B"], row["B_to_A"], row["n_valid_pairs"]
    disc = ab + ba
    if n == 0:
        return "INSUFFICIENT DATA"
    if disc == 0:
        return "NO OBSERVED EFFECT"
    dominant = max(ab, ba)
    consistency = dominant / disc
    beats_control = control is None or row["flip_rate"] > control["flip_rate_ci95"][1]
    if (dominant / n >= STRONG_DOMINANT_RATE and consistency >= STRONG_CONSISTENCY
            and row["holm_reject"] and beats_control):
        return "STRONG EFFECT"
    if (dominant / n >= MODERATE_DOMINANT_RATE and dominant >= MODERATE_MIN_DOMINANT
            and consistency >= MODERATE_CONSISTENCY and beats_control):
        return "MODERATE EFFECT"
    return "WEAK/INCONCLUSIVE"


def paired_table(pairs):
    """pairs: list of (ref_decision, level_decision) with None for invalid outputs."""
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
    flags = []
    if aa + ab < LOW_SENSITIVITY_MIN:
        flags.append("LOW_SENSITIVITY_A_TO_B (few reference-ALLOW bases)")
    if ba + bb < LOW_SENSITIVITY_MIN:
        flags.append("LOW_SENSITIVITY_B_TO_A (few reference-BLOCK bases)")
    row["flags"] = flags
    return row


def analyze(cases, manifest, records):
    """Pure function: (cases, manifest, records) -> results dict."""
    main = {}
    for r in records:
        if r["phase"] == "main":
            main[r["text_sha256"]] = r
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
            method = cr["text"].split(" ", 1)[0]
            stratum = ("GET" if method == "GET" else "body")
            if fid == "F-CL":
                stratum = ["form1", "form2", "json1", "json3"][i % 4]
            strata[stratum].append(d)
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
               "strata": {s: {k: v for k, v in paired_table(p).items()
                              if k in ("n_valid_pairs", "A_to_B", "B_to_A", "ALLOW_to_ALLOW",
                                       "BLOCK_to_BLOCK")} for s, p in sorted(strata.items())}}
        rows.append(row)

    for fam in HOLM_FAMILIES:
        members = [r for r in rows if r["block"] == fam]
        adj, rej = holm([r["mcnemar_exact_p_two_sided"] for r in members])
        for r, a, j in zip(members, adj, rej):
            r["holm_family"], r["holm_family_size"] = fam, len(members)
            r["holm_adjusted_p"], r["holm_reject"] = a, j
    for r in rows:
        if r["block"] == "CONTROL":       # outside every family: raw p only
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
    instability = {"control": CONTENT_CONTROL, "flip_rate": cov["flip_rate"],
                   "flip_rate_ci95": cov["flip_rate_ci95"],
                   "material": bool(cov["flip_rate_ci95"] and cov["flip_rate_ci95"][0] >= INSTABILITY_MATERIAL_LOWER),
                   "rule": f"material iff CP lower bound >= {INSTABILITY_MATERIAL_LOWER}"}
    # Reference-ALLOW counts by Host value, over every reference text (descriptive, review IMPORTANT).
    host_ref = defaultdict(Counter)
    for comp in manifest["comparisons"]:
        for i in range(comp["n_bases"]):
            c = by_key[(comp["factor"], i, comp["reference"])]
            host = next(l[6:] for l in c["text"].split("\n") if l.startswith("Host: "))
            host_ref[host][dec(c) or "INVALID"] += 1

    status_counts = Counter(r["status"] for r in main.values())
    decision_counts = Counter(r["decision"] for r in main.values() if r["status"] == "ok")
    reasons = Counter(r["reason"] for r in main.values() if r["status"] == "ok" and r["decision"] == "BLOCK")
    return {
        "analysis_version": ANALYSIS_VERSION, "data_role": manifest["data_role"],
        "pre_registered": {"alpha": ALPHA, "test": "exact McNemar, two-sided",
                           "multiplicity": "Holm within the ENVELOPE family and within the CONTENT family; "
                                           "controls outside (raw p)",
                           "strong": {"dominant_rate": STRONG_DOMINANT_RATE, "consistency": STRONG_CONSISTENCY,
                                      "holm_reject": True,
                                      "flip_rate_above": "matched control's Clopper-Pearson 95% upper bound"},
                           "moderate": {"dominant_rate": MODERATE_DOMINANT_RATE,
                                        "min_dominant": MODERATE_MIN_DOMINANT,
                                        "consistency": MODERATE_CONSISTENCY,
                                        "flip_rate_above": "matched control's Clopper-Pearson 95% upper bound"},
                           "matched_controls": {"ENVELOPE and F-CTB": ENVELOPE_CONTROL, "CONTENT": CONTENT_CONTROL},
                           "hypothesis_support": "STRONG comparisons only",
                           "no_observed_effect": "0 discordant pairs",
                           "low_sensitivity_min": LOW_SENSITIVITY_MIN},
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


PCT_RE = re.compile(r"%[0-9A-Fa-f]{2}")


def _span(xs):
    return {"min": min(xs), "max": max(xs), "mean": round(sum(xs) / len(xs), 2)} if xs else None


def fmt(x, nd=2):
    return "—" if x is None else f"{x:.{nd}f}"


def table_md(res):
    lines = ["| Comparison | Block | N | A→A | A→B | B→A | B→B | flip rate [95% CI] | base ALLOW | "
             "McNemar p | Holm p | Class | Flags |",
             "|---|---|---:|---:|---:|---:|---:|---|---:|---:|---:|---|---|"]
    for r in res["comparisons"]:
        ci = r["flip_rate_ci95"]
        lines.append(
            f"| `{r['comparison_id']}` | {r['block']} | {r['n_valid_pairs']} | {r['ALLOW_to_ALLOW']} | "
            f"{r['A_to_B']} | {r['B_to_A']} | {r['BLOCK_to_BLOCK']} | {fmt(r['flip_rate'])} "
            f"[{fmt(ci[0]) if ci else '—'}, {fmt(ci[1]) if ci else '—'}] | {fmt(r['baseline_allow_rate'])} | "
            f"{fmt(r['mcnemar_exact_p_two_sided'], 4)} | {fmt(r['holm_adjusted_p'], 4)} | {r['effect_class']} | "
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
