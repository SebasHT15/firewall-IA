"""
firewall-IA — benchmark comparison (Issue #9).

Compares two benchmark summaries and states, per statistic, how much a
candidate moved relative to a reference:

    percentage reduction  =  100 * (baseline - candidate) / baseline
    speedup factor        =  baseline / candidate

These are DIFFERENT quantities and are never conflated: a 50% reduction is a
2.0x speedup, a 75% reduction is 4.0x. The reduction is reported for every
comparable statistic separately — there is no single blended "improvement".

WHAT THIS TOOL REFUSES TO DO
    It does not call two numbers comparable because both are milliseconds.
    Before any figure is presented, the two reports are checked on timing scope,
    dataset hash, request count and selection, protocol version, batch size and
    concurrency. A mismatch on any of those is BLOCKING: the comparison is
    printed but stamped NOT COMPARABLE, and the process exits non-zero.

    Differences in hardware, driver, library versions, model identity or
    quantization are WARNINGS: the numbers can be compared, but the cause of a
    change cannot be attributed to software alone. When hardware changed, the
    report says plainly that the base version must be re-run on that hardware
    before any claim of a software improvement. When hardware AND software both
    changed, the result is reported as a JOINT effect with no causal split.

    A speed improvement is never presented on its own: quality metrics are
    compared in the same pass and any degradation is raised next to the speedup.

USAGE
    python3.12 scripts/benchmarks/benchmark_compare.py --baseline baseline-local-v1 \\
                                    --candidate <experiment-id-or-path>
    python3.12 scripts/benchmarks/benchmark_compare.py --baseline baseline-local-v1 \\
                                    --candidate <id> --previous <id>
    python3.12 scripts/benchmarks/benchmark_compare.py --legacy-baseline reports/v4_clean_eval.json \\
                                    --candidate baseline-local-v1
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

# This file lives in scripts/benchmarks/, two levels below the repository root.
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BENCH_ROOT = os.path.join(REPO_ROOT, "reports", "benchmarks")

# Fallback only. A summary carries its own `metric_directions`, which wins.
from benchmark_inference import (  # noqa: E402
    HISTORICAL_TIMING_SCOPE,
    METRIC_DIRECTIONS,
)

# Identity fields that must match before any number is comparable.
BLOCKING_FIELDS = (
    "timing_scope_id", "measurement_unit", "dataset_sha256",
    "n_requests_per_run", "selection_policy", "request_order", "reduced_set",
    "batch_size", "concurrency",
)

# Fields that permit comparison but change what a difference can be attributed to.
WARNING_FIELDS = (
    "gpu_name", "gpu_vram_mib", "nvidia_driver_version", "torch_cuda_runtime",
    "torch_version", "transformers_version", "peft_version", "bitsandbytes_version",
    "python_version", "os", "kernel", "cpu", "device",
    "model_base_repo", "model_base_revision", "adapter_sha256", "quantization",
    "runs", "seed",
)

INFO_FIELDS = ("git_commit", "working_tree_clean", "working_tree_diff_sha256",
               "protocol_version", "dataset_path")

# A change in any of these means the machine changed, not the software.
HARDWARE_FIELDS = ("gpu_name", "gpu_vram_mib", "cpu", "device")
# A change in any of these means the software stack changed.
SOFTWARE_FIELDS = ("torch_version", "transformers_version", "peft_version",
                   "bitsandbytes_version", "python_version", "torch_cuda_runtime",
                   "nvidia_driver_version", "git_commit", "adapter_sha256",
                   "quantization", "model_base_revision")


# ── Formulas ───────────────────────────────────────────────────────────────
def pct_reduction(baseline, candidate):
    """100 * (baseline - candidate) / baseline.

    Positive = the candidate's value is lower than the baseline's. Whether
    "lower" means better depends on the metric, which is why the caller passes
    `lower_is_better` to `compare_metric` rather than this function guessing.

    Never returns a number it cannot justify:
      * either side missing        -> status says which, value None
      * baseline zero              -> undefined, value None (no division)
      * baseline negative          -> undefined, value None (the sign of the
                                      ratio would invert its meaning)
    A negative result is a real answer — the candidate got worse — and is
    returned as such, never clamped to zero or hidden.
    """
    if baseline is None and candidate is None:
        return {"value": None, "status": "both_missing",
                "note": "neither report contains this metric"}
    if baseline is None:
        return {"value": None, "status": "baseline_missing",
                "note": "no reference value to reduce from"}
    if candidate is None:
        return {"value": None, "status": "candidate_missing",
                "note": "candidate did not report this metric"}
    b, c = float(baseline), float(candidate)
    if b == 0:
        return {"value": None, "status": "baseline_zero",
                "note": ("percentage reduction is undefined against a zero "
                         "reference; compare the absolute difference instead"),
                "absolute_difference": c - b}
    if b < 0:
        return {"value": None, "status": "baseline_not_positive",
                "note": "percentage reduction is undefined for a negative reference",
                "absolute_difference": c - b}
    return {"value": 100.0 * (b - c) / b, "status": "ok"}


def speedup(baseline, candidate):
    """baseline / candidate — a FACTOR, not a percentage.

    Distinct from `pct_reduction`: 50% reduction is 2.0x, 90% is 10.0x. A
    factor below 1.0 means the candidate is slower.
    """
    if baseline is None or candidate is None:
        return {"value": None, "status": "missing",
                "note": "speedup needs both values"}
    b, c = float(baseline), float(candidate)
    if c == 0:
        return {"value": None, "status": "candidate_zero",
                "note": "division by zero; an instantaneous candidate is not a factor"}
    if c < 0 or b < 0:
        return {"value": None, "status": "not_positive",
                "note": "speedup is undefined for negative values"}
    return {"value": b / c, "status": "ok"}


def compare_metric(name, baseline, candidate, direction):
    """One statistic, compared. Reduction, speedup, delta and a verdict."""
    lower_better = (direction or {}).get("lower_is_better")
    red = pct_reduction(baseline, candidate)
    out = {
        "metric": name,
        "unit": (direction or {}).get("unit"),
        "family": (direction or {}).get("family"),
        "lower_is_better": lower_better,
        "baseline": baseline,
        "candidate": candidate,
        "percent_reduction": red,
        "absolute_delta": (None if baseline is None or candidate is None
                           else float(candidate) - float(baseline)),
    }
    # A speedup factor only means something for a duration.
    if (direction or {}).get("family") in ("latency", "cold_start"):
        out["speedup_factor"] = speedup(baseline, candidate)

    if red["status"] != "ok":
        out["verdict"] = "not_available"
        return out
    r = red["value"]
    if abs(r) < 1e-9:
        out["verdict"] = "unchanged"
    elif lower_better is None:
        out["verdict"] = "changed"          # no direction defined; do not judge
    elif (r > 0) == bool(lower_better):
        out["verdict"] = "improved"
    else:
        out["verdict"] = "regressed"
    return out


# ── Report loading ─────────────────────────────────────────────────────────
def resolve(ref):
    """Accept an experiment id or a path to a summary.json."""
    if os.path.isfile(ref):
        return ref
    cand = os.path.join(BENCH_ROOT, ref, "summary.json")
    if os.path.isfile(cand):
        return cand
    raise SystemExit(f"FATAL: no benchmark summary for {ref!r} "
                     f"(looked at {ref} and {cand})")


def load_report(ref):
    """Load a benchmark summary, native or legacy.

    A legacy `test_model.py --mode dataset` result (`reports/v4_clean_eval.json`)
    is accepted and converted, but it is NOT dressed up as a native report: its
    timing scope is recorded as the unsynchronized historical one, and the
    populations it never separated are left missing rather than invented. The
    compatibility check then blocks it against a native report, which is the
    correct answer — those numbers are an antecedent, not a comparand.
    """
    path = resolve(ref)
    with open(path) as f:
        doc = json.load(f)

    if doc.get("summary_schema", "").startswith("firewall-IA/benchmark-summary"):
        doc["_source_path"] = path
        return doc

    if "run_metadata" in doc and "latency" in doc:
        return _from_legacy_eval(doc, path)

    raise SystemExit(f"FATAL: {path} is not a benchmark summary or a legacy "
                     f"evaluation result.")


def _from_legacy_eval(doc, path):
    meta, lat, binary = doc["run_metadata"], doc["latency"], doc.get("binary", {})
    return {
        "summary_schema": "firewall-IA/benchmark-summary/1",
        "experiment_id": f"legacy:{os.path.basename(path)}",
        "created_utc": meta.get("date_utc"),
        "_source_path": path,
        "_legacy": True,
        "_legacy_note": (
            "Converted from a test_model.py evaluation result. It was produced "
            "under a different protocol: a single run, no separation of model "
            "load / first inference / warm-up from steady state, and an "
            "UNSYNCHRONIZED generate() timer. It is a historical antecedent, "
            "not a benchmark under this protocol."),
        "identity": {
            "experiment_id": f"legacy:{os.path.basename(path)}",
            "protocol_version": None,
            "timing_scope_id": HISTORICAL_TIMING_SCOPE,
            "measurement_unit": "milliseconds",
            "dataset_sha256": meta.get("dataset_sha256"),
            "dataset_path": meta.get("dataset"),
            "n_requests_per_run": lat.get("count"),
            "reduced_set": None,
            "selection_policy": None,
            "request_order": None,
            "seed": None,
            "runs": 1,
            "batch_size": None,
            "concurrency": None,
            "git_commit": meta.get("git_commit"),
        },
        "metrics": {
            "steady_generate_mean_ms": lat.get("mean_ms"),
            "steady_generate_p50_ms": lat.get("p50_ms"),
            "steady_generate_p95_ms": lat.get("p95_ms"),
            "steady_generate_p99_ms": lat.get("p99_ms"),
            "steady_generate_min_ms": lat.get("min_ms"),
            "steady_generate_max_ms": lat.get("max_ms"),
            "steady_generate_stdev_ms": lat.get("stdev_ms"),
            "quality_attack_detection_rate": binary.get("attack_detection_rate"),
            "quality_false_positive_rate": binary.get("false_positive_rate"),
            "quality_false_negative_rate": binary.get("false_negative_rate"),
            "quality_invalid_output_rate": binary.get("invalid_output_rate"),
            "quality_accuracy": binary.get("accuracy"),
        },
        "metric_directions": METRIC_DIRECTIONS,
    }


# ── Compatibility ──────────────────────────────────────────────────────────
def check_compatibility(base_id, cand_id):
    """Every dimension on which two experiments differ, with a severity.

    Missing on one side is itself a finding: an unknown timing scope is not the
    same as a matching one.
    """
    findings = []

    def add(field, severity):
        b, c = base_id.get(field, "<absent>"), cand_id.get(field, "<absent>")
        if b == c:
            return
        findings.append({
            "field": field, "severity": severity,
            "baseline": b, "candidate": c,
            "unknown_on_one_side": (b in (None, "<absent>")) != (c in (None, "<absent>")),
        })

    for f in BLOCKING_FIELDS:
        add(f, "BLOCKING")
    for f in WARNING_FIELDS:
        add(f, "WARNING")
    for f in INFO_FIELDS:
        add(f, "INFO")

    changed = {f["field"] for f in findings}
    hardware_changed = sorted(changed & set(HARDWARE_FIELDS))
    software_changed = sorted(changed & set(SOFTWARE_FIELDS))
    blocking = [f for f in findings if f["severity"] == "BLOCKING"]

    notes = []
    if hardware_changed:
        notes.append(
            "HARDWARE CHANGED (" + ", ".join(hardware_changed) + "). A latency "
            "difference measured across different hardware is not evidence of a "
            "software improvement. To isolate the software effect, re-run the "
            "BASE version of the software on this hardware and compare against "
            "that, not against the original baseline.")
    if hardware_changed and software_changed:
        notes.append(
            "HARDWARE AND SOFTWARE BOTH CHANGED (" + ", ".join(software_changed) +
            "). Any difference is a JOINT effect of the two. It must be reported "
            "as such; it cannot be attributed to either one alone.")
    elif software_changed:
        notes.append(
            "Software changed (" + ", ".join(software_changed) + "). Hardware is "
            "unchanged, so a difference is attributable to the software stack as "
            "a whole — not to any single change within it unless they were "
            "varied one at a time.")
    if not findings:
        notes.append("No recorded difference between the two experiments' "
                     "identity fields.")

    return {
        "comparable": not blocking,
        "blocking_count": len(blocking),
        "findings": findings,
        "hardware_changed": hardware_changed,
        "software_changed": software_changed,
        "attribution_notes": notes,
        "policy": ("Shared units are not evidence of comparability. Timing scope, "
                   "dataset, request selection, protocol, batch size and "
                   "concurrency must match before a figure is presented."),
    }


# ── Comparison ─────────────────────────────────────────────────────────────
def compare(baseline, candidate, role="baseline"):
    """Compare two loaded reports across every metric either one reports."""
    b_id = baseline.get("identity", {})
    c_id = candidate.get("identity", {})
    directions = {**METRIC_DIRECTIONS,
                  **(baseline.get("metric_directions") or {}),
                  **(candidate.get("metric_directions") or {})}

    b_m, c_m = baseline.get("metrics", {}), candidate.get("metrics", {})
    names = sorted(set(b_m) | set(c_m), key=lambda n: (
        (directions.get(n) or {}).get("family", "zz"), n))

    metrics = [compare_metric(n, b_m.get(n), c_m.get(n), directions.get(n))
               for n in names]
    compat = check_compatibility(b_id, c_id)

    quality_regressions = [m for m in metrics
                           if m["family"] == "quality" and m["verdict"] == "regressed"]
    latency_improvements = [m for m in metrics
                            if m["family"] == "latency" and m["verdict"] == "improved"]

    warnings = []
    if latency_improvements and quality_regressions:
        warnings.append(
            "SPEED IMPROVED BUT QUALITY DEGRADED on " +
            ", ".join(m["metric"] for m in quality_regressions) +
            ". A latency reduction bought with worse detection is a trade, not a "
            "win, and must not be reported as a speed result alone.")
    if baseline.get("_legacy") or candidate.get("_legacy"):
        warnings.append(
            "One side is a legacy evaluation result, not a benchmark run under "
            "this protocol. See `_legacy_note` in the loaded report.")

    return {
        "comparison_schema": "firewall-IA/benchmark-comparison/1",
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "role": role,
        "formulas": {
            "percent_reduction": "100 * (baseline - candidate) / baseline",
            "speedup_factor": "baseline / candidate",
            "relationship": ("distinct quantities: 50% reduction = 2.0x speedup; "
                             "a negative reduction is a regression, reported as such"),
        },
        "baseline": {
            "experiment_id": baseline.get("experiment_id"),
            "created_utc": baseline.get("created_utc"),
            "source": baseline.get("_source_path"),
            "identity": b_id,
        },
        "candidate": {
            "experiment_id": candidate.get("experiment_id"),
            "created_utc": candidate.get("created_utc"),
            "source": candidate.get("_source_path"),
            "identity": c_id,
        },
        "compatibility": compat,
        "comparable": compat["comparable"],
        "metrics": metrics,
        "warnings": warnings,
        "primary": next((m for m in metrics if m["metric"] == "steady_generate_p95_ms"),
                        None),
    }


# ── Rendering ──────────────────────────────────────────────────────────────
def _fmt(v, nd=2):
    if v is None:
        return "n/a"
    if isinstance(v, float):
        return f"{v:.{nd}f}"
    return str(v)


def render_text(cmp_doc):
    L = ["=" * 78,
         f"BENCHMARK COMPARISON — candidate vs {cmp_doc['role']}",
         "=" * 78,
         f"  {cmp_doc['role']:<10} {cmp_doc['baseline']['experiment_id']}"
         f"   ({cmp_doc['baseline']['created_utc']})",
         f"  candidate  {cmp_doc['candidate']['experiment_id']}"
         f"   ({cmp_doc['candidate']['created_utc']})",
         ""]

    if not cmp_doc["comparable"]:
        L += ["*** NOT COMPARABLE — "
              f"{cmp_doc['compatibility']['blocking_count']} blocking difference(s). "
              "The figures below are printed for diagnosis only and must not be "
              "reported as an improvement. ***", ""]

    L.append(f"{'metric':<34}{'baseline':>14}{'candidate':>14}"
             f"{'reduction':>20}{'verdict':>15}")
    L.append("-" * 97)
    family = None
    for m in cmp_doc["metrics"]:
        if m["family"] != family:
            family = m["family"]
            L.append(f"[{family}]")
        red = m["percent_reduction"]
        rs = (f"{red['value']:+.4f}%" if red["status"] == "ok" else red["status"])
        nd = 6 if m["unit"] == "ratio" else 3   # rates need more digits than ms
        L.append(f"  {m['metric']:<32}{_fmt(m['baseline'], nd):>14}"
                 f"{_fmt(m['candidate'], nd):>14}{rs:>20}{m['verdict']:>15}")
        sp = m.get("speedup_factor")
        if sp and sp["status"] == "ok":
            L.append(f"  {'':<32}{'':>14}{'':>14}"
                     f"{sp['value']:>19.4f}x{'speedup':>14}")

    L += ["", "COMPATIBILITY"]
    if not cmp_doc["compatibility"]["findings"]:
        L.append("  no differences on any checked identity field")
    for f in cmp_doc["compatibility"]["findings"]:
        L.append(f"  [{f['severity']:<8}] {f['field']}")
        L.append(f"             baseline : {f['baseline']}")
        L.append(f"             candidate: {f['candidate']}")
    for n in cmp_doc["compatibility"]["attribution_notes"]:
        L += ["", "  " + _wrap(n, 74, "  ")]
    for w in cmp_doc["warnings"]:
        L += ["", "  !! " + _wrap(w, 72, "     ")]
    L.append("=" * 78)
    return "\n".join(L)


def _wrap(text, width, indent):
    words, lines, cur = text.split(), [], ""
    for w in words:
        if len(cur) + len(w) + 1 > width:
            lines.append(cur)
            cur = w
        else:
            cur = f"{cur} {w}".strip()
    lines.append(cur)
    return ("\n" + indent).join(lines)


def render_markdown(cmp_doc):
    c = cmp_doc
    L = [f"# Benchmark comparison — candidate vs {c['role']}", "",
         f"- **{c['role']}**: `{c['baseline']['experiment_id']}` "
         f"({c['baseline']['created_utc']})",
         f"- **candidate**: `{c['candidate']['experiment_id']}` "
         f"({c['candidate']['created_utc']})",
         f"- **comparable**: {'yes' if c['comparable'] else '**NO**'}", ""]
    if not c["comparable"]:
        L += ["> **NOT COMPARABLE.** "
              f"{c['compatibility']['blocking_count']} blocking difference(s) in "
              "timing scope, dataset, selection or protocol. The table below is "
              "diagnostic only.", ""]
    L += ["`reduction = 100 x (baseline - candidate) / baseline` · "
          "`speedup = baseline / candidate`", "",
          "| metric | unit | baseline | candidate | reduction | speedup | verdict |",
          "|---|---|---:|---:|---:|---:|---|"]
    for m in c["metrics"]:
        red = m["percent_reduction"]
        rs = f"{red['value']:+.4f}%" if red["status"] == "ok" else f"_{red['status']}_"
        sp = m.get("speedup_factor")
        ss = f"{sp['value']:.4f}x" if sp and sp["status"] == "ok" else "—"
        nd = 6 if m["unit"] == "ratio" else 3
        L.append(f"| `{m['metric']}` | {m['unit'] or ''} | {_fmt(m['baseline'], nd)} "
                 f"| {_fmt(m['candidate'], nd)} | {rs} | {ss} | {m['verdict']} |")
    L += ["", "## Compatibility", ""]
    if c["compatibility"]["findings"]:
        L += ["| severity | field | baseline | candidate |", "|---|---|---|---|"]
        for f in c["compatibility"]["findings"]:
            L.append(f"| {f['severity']} | `{f['field']}` | `{f['baseline']}` "
                     f"| `{f['candidate']}` |")
    else:
        L.append("No difference on any checked identity field.")
    L.append("")
    for n in c["compatibility"]["attribution_notes"]:
        L += [f"> {n}", ""]
    for w in c["warnings"]:
        L += [f"> **{w}**", ""]
    return "\n".join(L)


# ── CLI ────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(
        description="Compare firewall-IA inference benchmark reports (Issue #9)")
    ap.add_argument("--baseline", help="reference experiment id or summary.json path")
    ap.add_argument("--legacy-baseline",
                    help="a test_model.py evaluation result to use as the reference "
                         "(will be flagged as a historical antecedent)")
    ap.add_argument("--candidate", required=True,
                    help="candidate experiment id or summary.json path")
    ap.add_argument("--previous",
                    help="the candidate's immediately preceding experiment — "
                         "compared in the same report, so a candidate can be read "
                         "against both the original baseline and its own last version")
    ap.add_argument("--json", help="write the machine-readable comparison here")
    ap.add_argument("--markdown", help="write a Markdown comparison here")
    ap.add_argument("--allow-incompatible", action="store_true",
                    help="exit 0 even when blocking differences were found "
                         "(the report still says NOT COMPARABLE)")
    args = ap.parse_args()

    if not args.baseline and not args.legacy_baseline:
        raise SystemExit("FATAL: pass --baseline or --legacy-baseline")

    candidate = load_report(args.candidate)
    baseline = load_report(args.baseline or args.legacy_baseline)

    comparisons = [compare(baseline, candidate, role="baseline")]
    if args.previous:
        comparisons.append(compare(load_report(args.previous), candidate,
                                   role="previous version"))

    for c in comparisons:
        print(render_text(c))
        print()

    doc = {"comparison_set_schema": "firewall-IA/benchmark-comparison-set/1",
           "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           "comparisons": comparisons}
    if args.json:
        os.makedirs(os.path.dirname(os.path.abspath(args.json)), exist_ok=True)
        with open(args.json, "w") as f:
            json.dump(doc, f, indent=2)
        print(f"machine-readable comparison -> {args.json}")
    if args.markdown:
        os.makedirs(os.path.dirname(os.path.abspath(args.markdown)), exist_ok=True)
        with open(args.markdown, "w") as f:
            f.write("\n\n---\n\n".join(render_markdown(c) for c in comparisons) + "\n")
        print(f"markdown comparison -> {args.markdown}")

    if any(not c["comparable"] for c in comparisons) and not args.allow_incompatible:
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
