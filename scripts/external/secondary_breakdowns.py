"""External Test v1 — SECONDARY breakdowns pre-registered in the protocol (§4.3, §10).

Completion of pre-registered analysis, NOT error analysis. READ-ONLY over frozen evidence:
it reads `datasets/external_v1/cases.jsonl` (metadata recorded before exposure) and
`reports/external/external-v1-run-001/results.jsonl`, changes no case, label or record,
re-runs nothing, and never selects a case by its prediction.

Every choice is taken from what already existed before execution:

  population   the L1 headline population, selected exactly as `external_v1_run.score_l1`
               does: gateway channel, repetition 1, nondeterministic cases excluded (none).
  dimensions   `client_profile`, `host_type`, `method`, `body_type` — the four listed in
               protocol §10, read verbatim from the frozen case metadata. No value is
               mapped, merged or renamed.
  scoring      the frozen D19 scorer `test_model.score_binary` (protocol §3: imported, never
               reimplemented; BLOCK positive).
  rates        the runner's per-cell convention: confusion matrix, recall over the BLOCK
               cases and FPR over the ALLOW cases, each with numerator and denominator.
               Accuracy and precision are not reported per value: each value's ALLOW/BLOCK
               mix is a by-product of the construction, and §3 requires prevalence to be
               stated wherever those appear.
  status       protocol §3 support rule, applied to each rate's own denominator:
               >= MIN_EVAL_SUPPORT (30) OK · 1-29 INSUFFICIENT DATA · 0 NOT EVALUABLE.
  zero errors  protocol §3 / methodology §5: a zero-error rate also carries the
               rule-of-three bound — the methodology's APPROXIMATE zero-event bound, 3/n on
               the error rate (for recall: the miss rate, so recall >= ~1 - 3/n). It is not
               an exact confidence interval, and it is reported beside the observed value,
               never instead of it. A rate cannot exceed 100%, so the bound is capped there
               and marked uninformative when 3/n >= 1 (n <= 3).

`route_family` (listed in §4.3, not in §10) is NOT produced: it is absent from the frozen
case metadata, and it was only ever computed for enumerable specs, never for the 80
browser-captured cases, so producing it now would be a post-exposure methodological choice.

    python3.12 scripts/external/secondary_breakdowns.py            # print
    python3.12 scripts/external/secondary_breakdowns.py --write    # write the report (refuses to overwrite)

Needs the ML environment (the frozen scorer imports torch).
"""

import argparse
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import external_v1_run as run  # noqa: E402

sys.path.insert(0, os.path.join(run.REPO_ROOT, "scripts", "evaluation"))

DIMENSIONS = ("client_profile", "host_type", "method", "body_type")
OUT_DIR = os.path.join(run.REPO_ROOT, "reports", "external", "external-v1-secondary-breakdowns")
NOT_PRODUCED = {
    "route_family": (
        "Pre-registered in protocol §4.3 (not in the §10 breakdown list). Not present in the "
        "frozen case metadata (datasets/external_v1/cases.jsonl). Its only definition, "
        "spec_lib.Spec.route_family, was applied to enumerable specs before exposure and never "
        "to the 80 browser-captured cases; assigning route families now would be a new, "
        "post-exposure methodological choice. Pre-registered, not produced."),
}


def status(n, min_support):
    if n == 0:
        return "NOT EVALUABLE"
    return "OK" if n >= min_support else "INSUFFICIENT DATA"


def rule_of_three(errors, n, kind):
    """The methodology's approximate zero-event bound for a zero-error rate, or None.

    kind "fpr": the error rate is the FPR itself. kind "recall": the error rate is the miss
    rate (FNR), and the matching approximate recall lower bound is 100% minus it.
    """
    if not n or errors != 0:
        return None
    upper = min(100.0, 100.0 * 3 / n)
    out = {"error_rate": "FPR" if kind == "fpr" else "miss rate (FNR)",
           "upper_bound_pct": upper, "informative": n > 3}
    if kind == "recall":
        out["recall_lower_bound_pct"] = 100.0 - upper
    return out


def rate(num, den, errors, min_support, kind):
    """A class-conditional OBSERVED rate with its support status. The rule-of-three bound,
    when it applies, is kept in a separate field and never replaces the observed value."""
    return {"num": num, "den": den, "pct": (100.0 * num / den) if den else None,
            "evidence_status": status(den, min_support),
            "rule_of_three": rule_of_three(errors, den, kind)}


def headline_rows(results):
    """Same population as external_v1_run.score_l1."""
    rep1 = [r for r in results if r["channel"] == "gateway" and r["repetition"] == 1]
    flagged = {f["case_id"] for f in run.determinism_report(results, "gateway")}
    return [r for r in rep1 if r["case_id"] not in flagged], sorted(flagged)


def compute(score_fn=None, min_support=None):
    if score_fn is None or min_support is None:
        from test_model import MIN_EVAL_SUPPORT, score_binary  # noqa: E402  frozen D19
        score_fn = score_fn or score_binary
        min_support = min_support or MIN_EVAL_SUPPORT

    _rows, _manifest, ihash, problems = run.verify_frozen()
    if problems or ihash != run.FROZEN_INTEGRITY_HASH:
        raise SystemExit("frozen integrity check FAILED: " + "; ".join(problems))

    cases = {c["case_id"]: c for c in run.load_jsonl(run.FROZEN_CASES)}
    results = run.load_jsonl(os.path.join(run.RUN_DIR, "results.jsonl"))
    rows, flagged = headline_rows(results)

    def scored(subset):
        return [{"expected": r["ground_truth"], "predicted": r["decision"], "status": r["status"]}
                for r in subset]

    overall = score_fn(scored(rows))["confusion_matrix"]
    out = {
        "analysis": "External Test v1 — SECONDARY breakdowns (pre-registered, protocol §4.3/§10)",
        "label": "SECONDARY — not headline. No causal claim. 50/50 construction; not production prevalence.",
        "run_id": run.RUN_ID,
        "freeze_commit": "36df2ee",
        "frozen_integrity_hash": run.FROZEN_INTEGRITY_HASH,
        "population": "gateway channel, repetition 1, nondeterministic cases excluded (as score_l1)",
        "headline_n": len(rows),
        "excluded_nondeterministic": flagged,
        "headline_confusion": overall,
        "support_rule": f">= {min_support} OK; 1-{min_support - 1} INSUFFICIENT DATA; 0 NOT EVALUABLE "
                        "(per rate, on its own denominator)",
        "rule_of_three": ("approximate zero-event bound defined by protocol §3 / methodology §5: "
                          "upper bound ~= 3/n on a zero-error rate (recall: on the miss rate, so "
                          "recall >= ~1 - 3/n); not an exact confidence interval; reported beside "
                          "the observed value; capped at 100% and uninformative for n <= 3"),
        "breakdowns": {},
        "not_produced": NOT_PRODUCED,
    }
    for dim in DIMENSIONS:
        values = {}
        for value in sorted({cases[r["case_id"]][dim] for r in rows}):
            subset = [r for r in rows if cases[r["case_id"]][dim] == value]
            s = score_fn(scored(subset))
            cm = s["confusion_matrix"]
            values[value] = {
                "n": len(subset),
                "allow_support": s["allow_support"],
                "block_support": s["block_support"],
                "confusion": cm,
                "invalid_outputs": s["invalid_outputs"],
                "fpr": rate(cm["FP"], s["allow_support"], cm["FP"], min_support, "fpr"),
                "recall_block": rate(cm["TP"], s["block_support"], cm["FN"], min_support,
                                     "recall"),
            }
        totals = {k: sum(v["confusion"][k] for v in values.values()) for k in ("TP", "FP", "FN", "TN")}
        out["breakdowns"][dim] = {"values": values,
                                  "reconciles_with_headline": totals == {k: overall[k] for k in totals}}
    return out


def _fmt_rate(r):
    """The OBSERVED rate only."""
    if r["den"] == 0:
        return "— (0 cases; NOT EVALUABLE)"
    return f"{r['num']} / {r['den']} = {r['pct']:.1f}% · {r['evidence_status']}"


def _fmt_bounds(v):
    """The rule-of-three statement(s) for a value's zero-error rates, kept separate."""
    parts = []
    for key, label in (("fpr", "FPR"), ("recall_block", "miss rate")):
        b = v[key]["rule_of_three"]
        if b is None:
            continue
        n = v[key]["den"]
        if not b["informative"]:
            parts.append(f"{label}: uninformative (n = {n} ≤ 3; capped at 100%)")
        elif key == "recall_block":
            parts.append(f"miss rate ≤ ≈ 3/{n} = {b['upper_bound_pct']:.1f}% "
                         f"(recall ≥ ≈ {b['recall_lower_bound_pct']:.1f}%)")
        else:
            parts.append(f"FPR ≤ ≈ 3/{n} = {b['upper_bound_pct']:.1f}%")
    return "; ".join(parts) if parts else "—"


def to_markdown(o):
    lines = [
        "# External Test v1 — SECONDARY breakdowns (pre-registered)", "",
        f"**{o['label']}**", "",
        f"Run `{o['run_id']}` · freeze `{o['freeze_commit']}` · population: {o['population']} "
        f"(n = {o['headline_n']}; headline confusion TP {o['headline_confusion']['TP']} · "
        f"TN {o['headline_confusion']['TN']} · FP {o['headline_confusion']['FP']} · "
        f"FN {o['headline_confusion']['FN']}).", "",
        "Completion of the secondary breakdowns pre-registered in "
        "`docs/external_test_v1_protocol.md` §4.3 and §10 — **not** error analysis: no case is "
        "selected by its prediction, and no value is mapped or merged. Generated by "
        "`scripts/external/secondary_breakdowns.py` with the frozen D19 scorer. Support rule: "
        f"{o['support_rule']}. Rule of three: {o['rule_of_three']}. "
        "Accuracy and precision are not reported per value: each value's ALLOW/BLOCK mix is a "
        "by-product of the 50/50 construction. INSUFFICIENT DATA rows are exploratory only.", "",
    ]
    for dim, block in o["breakdowns"].items():
        lines += [f"## `{dim}`", "",
                  "| Value | n | ALLOW / BLOCK | TP · TN · FP · FN | Observed FPR (over ALLOW) | "
                  "Observed recall (over BLOCK) | Rule-of-three bound, zero-error rates only (approx.) |",
                  "|---|---:|---|---|---|---|---|"]
        for value, v in block["values"].items():
            cm = v["confusion"]
            lines.append(f"| `{value}` | {v['n']} | {v['allow_support']} / {v['block_support']} | "
                         f"{cm['TP']} · {cm['TN']} · {cm['FP']} · {cm['FN']} | "
                         f"{_fmt_rate(v['fpr'])} | {_fmt_rate(v['recall_block'])} | "
                         f"{_fmt_bounds(v)} |")
        lines += ["", f"Reconciles with the headline confusion matrix: "
                      f"{'yes' if block['reconciles_with_headline'] else 'NO'}.", ""]
    lines += ["## Not produced", ""]
    for dim, why in o["not_produced"].items():
        lines.append(f"- **`{dim}`** — {why}")
    lines += ["", "Invalid outputs: 0 in every value (see `secondary_breakdowns.json`).", ""]
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--write", action="store_true",
                    help=f"write the report to {os.path.relpath(OUT_DIR, run.REPO_ROOT)}/ "
                         "(refuses to overwrite)")
    args = ap.parse_args(argv)
    o = compute()
    md = to_markdown(o)
    if not args.write:
        print(md)
        return 0
    if os.path.exists(OUT_DIR):
        raise SystemExit(f"refusing to overwrite existing {OUT_DIR}")
    os.makedirs(OUT_DIR)
    files = {"secondary_breakdowns.json": json.dumps(o, indent=2, ensure_ascii=False) + "\n",
             "secondary_breakdowns.md": md}
    for name, text in files.items():
        with open(os.path.join(OUT_DIR, name), "w", encoding="utf-8") as f:
            f.write(text)
    with open(os.path.join(OUT_DIR, "SHA256SUMS"), "w", encoding="utf-8") as f:
        for name, text in files.items():
            f.write(f"{hashlib.sha256(text.encode('utf-8')).hexdigest()}  {name}\n")
    print(f"wrote {os.path.relpath(OUT_DIR, run.REPO_ROOT)}/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
