"""External Test v1 — descriptive latency OBSERVATIONS from existing Phase F evidence.

READ-ONLY. Reads the committed records of `external-v1-run-001`, writes nothing, contacts
nothing, and never re-runs a case. Statistics use `benchmark_inference.summarize()`, so the
percentile definition is the one `baseline-local-v1` uses (nearest-rank, no interpolation).

WHAT EACH FIELD MEASURES — they are different quantities and are never pooled:

  gateway `model_latency_ms`  the data plane's wall-clock time around its POST /classify call
                              (`data_plane.py`: perf_counter before and after
                              ask_classifier), logged as integer ms and parsed from
                              raw/data-plane-phase-f.log by the runner. It includes the HTTP
                              call to the control plane and the whole server-side handling.
                              Despite the field name it is NOT model-side time.
  direct  `model_latency_ms`  the control plane's own `generate()`-only time, returned in the
                              /classify response (`inference_core.classify_raw`).
  direct  `wall_ms`           the runner's client-side wall time for its POST /classify.

None of them is end-to-end gateway latency (client -> proxy -> destination -> client), and
none is a benchmark: sequential single-client replay, no warm-up separation, no thermal
control. The formal end-to-end benchmark is Issue #18 (pending). The direct channel covers a
predeclared 100-case subset, so direct and gateway figures describe different populations.

    python3.12 scripts/external/summarize_latency_observations.py [--json]
"""

import argparse
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(ROOT, "scripts", "benchmarks"))
from benchmark_inference import summarize  # noqa: E402

RUN_DIR = os.path.join(ROOT, "reports", "external", "external-v1-run-001")
DECISION_LINE = re.compile(r"\] (ALLOW|BLOCK) \S+ \S+ reason=.* \(classifier ([\d.]+) ms\)")


def load_jsonl(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def observations(run_dir=RUN_DIR):
    results = load_jsonl(os.path.join(run_dir, "results.jsonl"))
    gateway = [r for r in results if r["channel"] == "gateway"]
    direct = load_jsonl(os.path.join(run_dir, "raw", "direct_raw.jsonl"))

    # The gateway values in results.jsonl are derived; check them against the log they
    # were parsed from, value for value and in order.
    with open(os.path.join(run_dir, "raw", "data-plane-phase-f.log"), encoding="utf-8") as f:
        log_values = [float(m.group(2)) for line in f if (m := DECISION_LINE.search(line))]
    gw_values = [r["model_latency_ms"] for r in gateway if r["model_latency_ms"] is not None]

    def by(rows, field, key, value):
        return [r[field] for r in rows if r.get(key) == value and r[field] is not None]

    return {
        "run_id": "external-v1-run-001",
        "kind": "observation — not a benchmark, not end-to-end (Issue #18 is pending)",
        "cross_check": {
            "data_plane_log_decision_lines": len(log_values),
            "gateway_records_with_latency": len(gw_values),
            "identical_values_in_order": log_values == gw_values,
        },
        "gateway_classifier_call_ms": {
            "measures": "data-plane wall time around POST /classify (integer ms)",
            "all": summarize(gw_values),
            "by_repetition": {rep: summarize(by(gateway, "model_latency_ms", "repetition", rep))
                              for rep in (1, 2, 3)},
            "by_decision": {d: summarize(by(gateway, "model_latency_ms", "decision", d))
                            for d in ("ALLOW", "BLOCK")},
        },
        "direct_generate_ms": {
            "measures": "control-plane generate()-only time from the /classify response",
            "all": summarize([r["model_latency_ms"] for r in direct
                              if r["model_latency_ms"] is not None]),
            "by_repetition": {rep: summarize(by(direct, "model_latency_ms", "repetition", rep))
                              for rep in (1, 2, 3)},
        },
        "direct_client_wall_ms": {
            "measures": "runner client-side wall time for POST /classify",
            "all": summarize([r["wall_ms"] for r in direct if r["wall_ms"] is not None]),
        },
    }


def line(label, s):
    return (f"  {label:<14} n={s['count']:<5} min={s['min_ms']:.2f}  mean={s['mean_ms']:.2f}  "
            f"P50={s['p50_ms']:.2f}  P95={s['p95_ms']:.2f}  P99={s['p99_ms']:.2f}  "
            f"max={s['max_ms']:.2f}  stdev={s['stdev_ms']:.2f}")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--json", action="store_true", help="print the full result as JSON")
    args = ap.parse_args(argv)
    obs = observations()
    if args.json:
        print(json.dumps(obs, indent=2))
        return 0
    print(f"{obs['run_id']}: {obs['kind']}")
    print(f"cross-check vs raw/data-plane-phase-f.log: {obs['cross_check']}")
    for key in ("gateway_classifier_call_ms", "direct_generate_ms", "direct_client_wall_ms"):
        block = obs[key]
        print(f"\n{key} — {block['measures']}")
        print(line("all", block["all"]))
        for rep, s in block.get("by_repetition", {}).items():
            print(line(f"repetition {rep}", s))
        for d, s in block.get("by_decision", {}).items():
            print(line(f"decision {d}", s))
    return 0


if __name__ == "__main__":
    sys.exit(main())
