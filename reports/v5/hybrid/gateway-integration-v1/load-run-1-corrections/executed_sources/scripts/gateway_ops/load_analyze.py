"""
Tables of a load run, recomputed from the per-request rows. No GPU, no service.

    .venv-dataplane/bin/python scripts/gateway_ops/load_analyze.py --run <evidence dir>

Percentiles over repetitions are computed on the pooled rows, nearest rank; percentiles are never
averaged. Rates are given per repetition, as mean and range, so that the spread stays visible.
"""
import argparse
import collections
import glob
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import load_lib as LL  # noqa: E402


def load_runs(run_dir):
    runs = {}
    for path in sorted(glob.glob(os.path.join(run_dir, "*.json"))):
        if os.path.basename(path) in ("protocol.json", "analysis.json"):
            continue
        with open(path, encoding="utf-8") as fh:
            runs[os.path.basename(path)[:-5]] = json.load(fh)
    return runs


def rows_of(run_dir, name):
    path = os.path.join(run_dir, "rows", f"{name}.jsonl")
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh]


def spread(values):
    values = [v for v in values if v is not None]
    if not values:
        return None
    return {"mean": sum(values) / len(values), "min": min(values), "max": max(values), "n": len(values)}


def ladder_tables(run_dir, runs):
    groups = collections.defaultdict(list)
    for name, run in runs.items():
        if name.startswith("ladder_"):
            config = name.split("_")[1]
            groups[(config, run["mode"])].append((name, run))
    out = {}
    for (config, mode), members in sorted(groups.items()):
        levels = collections.defaultdict(list)
        pooled = collections.defaultdict(list)
        for name, run in members:
            for step in run["steps"]:
                if step["label"].startswith("rate_"):
                    levels[step["offered_rate"]].append(step)
            for row in rows_of(run_dir, name):
                pooled[row["step"]].append(row)
        table = []
        for rate in sorted(levels):
            steps = levels[rate]
            rows = pooled[f"rate_{rate}"]
            good = [r["latency_ms"] for r in rows if LL.useful(r)]
            table.append({
                "offered_rate": rate, "repetitions": len(steps),
                "saturated_reps": sum(s["saturated"] for s in steps),
                "offered": sum(s["client"]["offered"] for s in steps),
                "useful_per_s": spread([s["client"]["useful_per_s"] for s in steps]),
                "useful_within_1s_per_s": spread([s["client"]["useful_within_1s_per_s"] for s in steps]),
                "rejected_503": sum(s["client"]["rejected_503"] for s in steps),
                "bad_gateway_502": sum(s["client"]["bad_gateway_502"] for s in steps),
                "client_timeouts": sum(s["client"]["client_timeouts"] for s in steps),
                "connection_errors": sum(s["client"]["connection_errors"] for s in steps),
                "latency_useful_ms": LL.dist(good),
                "latency_rejected_ms": LL.dist([r["latency_ms"] for r in rows if r["status"] == 503]),
                "l2_conformant_steps": sum(s["L2"]["conformant"] for s in steps),
                "gpu_util_mean": spread([s["resources"].get("gpu", {}).get("util_mean") for s in steps]),
                "generator_lag_p99_ms": max(s["client"]["generator_lag_ms"].get("p99") or 0 for s in steps),
            })
        out[f"{config}/{mode}"] = {
            "levels": table,
            "max_sustainable_per_rep": [run["max_sustainable_rate"] for _, run in members],
            "first_saturated_per_rep": [run["first_saturated_rate"] for _, run in members],
            "recovery_seconds_per_rep": [run["recovery_seconds"] for _, run in members],
            "recovered_per_rep": [run["recovered"] for _, run in members],
            "overload": overload_table(members),
        }
    return out


def overload_table(members):
    out = []
    for _, run in members:
        step = next(s for s in run["steps"] if s["label"] == "overload")
        out.append({"rate": step["offered_rate"], "useful_per_s": step["client"]["useful_per_s"],
                    "rejected_503": step["client"]["rejected_503"],
                    "client_timeouts": step["client"]["client_timeouts"], "L2": step["L2"]["conformant"],
                    "received_after_client_gave_up": step["L2"]["received_after_client_gave_up"],
                    "probe_statuses": step["probe_client"]["statuses"],
                    "v5_service": step["v5_service"]})
    return out


def merge_stage(steps):
    """Stage distributions per route. Each step's distribution is kept per level, since percentiles
    of different loads must not be mixed."""
    routes = collections.defaultdict(list)
    for step in steps:
        for route, data in step["decisions"]["routes"].items():
            routes[route].append(data)
    return {route: {"n": sum(d["n"] for d in data),
                    "reasons": dict(sum((collections.Counter(d["reasons"]) for d in data),
                                        collections.Counter())),
                    "gateway_p50_range": _range(d["gateway_ms"].get("p50") for d in data),
                    "gateway_p95_range": _range(d["gateway_ms"].get("p95") for d in data),
                    "stage_p95_range": {
                        name: _range(d["stages_ms"].get(name, {}).get("p95") for d in data)
                        for name in sorted({k for d in data for k in d["stages_ms"]})},
                    "decoder_paths": {
                        path: {"n": sum(d["decoder_pipeline_ms"].get(path, {}).get("n", 0) for d in data),
                               "p50_range": _range(d["decoder_pipeline_ms"].get(path, {}).get("p50")
                                                   for d in data),
                               "p95_range": _range(d["decoder_pipeline_ms"].get(path, {}).get("p95")
                                                   for d in data)}
                        for path in sorted({k for d in data for k in d["decoder_pipeline_ms"]})}}
            for route, data in sorted(routes.items())}


def _range(values):
    values = [v for v in values if v is not None]
    return [min(values), max(values)] if values else None


def stage_tables(runs):
    groups = collections.defaultdict(lambda: collections.defaultdict(list))
    for name, run in runs.items():
        if name.startswith("ladder_"):
            config = name.split("_")[1]
            for step in run["steps"]:
                if step["label"].startswith("rate_"):
                    groups[f"{config}/{run['mode']}"][step["offered_rate"]].append(step)
    return {group: {str(rate): merge_stage(steps) for rate, steps in sorted(levels.items())}
            for group, levels in sorted(groups.items())}


def observe_impact(run_dir, runs, tables):
    """V4 alone against V4 with the cascade computed beside it, at the same offered rate, repetition
    by repetition. Only levels both ran."""
    out = {}
    v4_levels = {row["offered_rate"]: row for row in tables.get("v4/V4_ONLY", {}).get("levels", [])}
    for config in ("reference", "verified"):
        key = f"{config}/CASCADE_OBSERVE"
        if key not in tables:
            continue
        rows = []
        for level in tables[key]["levels"]:
            rate = level["offered_rate"]
            alone = v4_levels.get(rate)
            if alone is None:
                continue
            rows.append({
                "rate": rate, "alone_p50": alone["latency_useful_ms"].get("p50"),
                "alone_p95": alone["latency_useful_ms"].get("p95"),
                "alone_p99": alone["latency_useful_ms"].get("p99"),
                "observe_p50": level["latency_useful_ms"].get("p50"),
                "observe_p95": level["latency_useful_ms"].get("p95"),
                "observe_p99": level["latency_useful_ms"].get("p99"),
                "alone_useful_per_s": alone["useful_per_s"], "observe_useful_per_s": level["useful_per_s"],
                "alone_503": alone["rejected_503"], "observe_503": level["rejected_503"],
                "v4_model_p95_alone": _v4_stage(runs, "v4", "V4_ONLY", rate, "v4_model_ms"),
                "v4_model_p95_observe": _v4_stage(runs, config, "CASCADE_OBSERVE", rate, "v4_model_ms"),
                "v4_gateway_p95_alone": _v4_stage(runs, "v4", "V4_ONLY", rate, "v4_gateway_ms"),
                "v4_gateway_p95_observe": _v4_stage(runs, config, "CASCADE_OBSERVE", rate, "v4_gateway_ms"),
                "observations": _observations(runs, config, rate)})
        out[config] = rows
    return out


def _v4_stage(runs, config, mode, rate, field):
    values = [step[field].get("p95") for name, run in runs.items()
              if name.startswith(f"ladder_{config}_{mode}_") for step in run["steps"]
              if step["offered_rate"] == rate and step["label"].startswith("rate_")]
    return _range(values)


def _observations(runs, config, rate):
    total = collections.Counter()
    for name, run in runs.items():
        if name.startswith(f"ladder_{config}_CASCADE_OBSERVE_"):
            for step in run["steps"]:
                if step["offered_rate"] == rate and step["label"].startswith("rate_"):
                    total.update(step["observations"])
    return dict(total)


def soak_tables(run_dir, runs):
    out = {}
    for name, run in sorted(runs.items()):
        if not name.startswith(("soak_", "soakhigh_")):
            continue
        step = next(s for s in run["steps"] if s["label"] == "soak")
        out[name] = {
            "rate": run["soak_rate"], "offered": step["client"]["offered"],
            "useful_per_s": step["client"]["useful_per_s"], "rejected_503": step["client"]["rejected_503"],
            "client_timeouts": step["client"]["client_timeouts"], "latency_useful_ms": step["client"]["latency_useful_ms"],
            "L2": step["L2"], "drift": run["drift"], "observations": step["observations"],
            "v4_gateway_ms": step["v4_gateway_ms"], "v4_model_ms": step["v4_model_ms"],
            "routes": merge_stage([step]), "resources": step["resources"],
            "metric_delta": {k: v for k, v in step["gateway_metric_delta"].items()
                             if "dropped" in k or "errors" in k or "admission" in k}}
    return out


def recovery_tables(runs):
    out = {}
    for name, run in sorted(runs.items()):
        if not name.startswith("recovery_"):
            continue
        step = next(s for s in run["steps"] if s["label"] == "overload")
        out[name] = {"overload_rate": run["overload_rate"], "recovery_seconds": run["recovery_seconds"],
                     "recovered": run["recovered"], "recovery_limit_ms": run["recovery_limit_ms"],
                     "probes": run["probes"], "probe_statuses": step["probe_client"]["statuses"],
                     "useful_per_s": step["client"]["useful_per_s"],
                     "rejected_503": step["client"]["rejected_503"], "L2": step["L2"],
                     "observations": step["observations"]}
    return out


def audit_tables(runs):
    out = {}
    for name, run in sorted(runs.items()):
        if not name.startswith("audit_"):
            continue
        step = next(s for s in run["steps"] if s["label"] == "audit")
        out[name] = {
            "sample_rate": run["sample_rate"], "audit": step["audit"],
            "permit_latency_ms": step["permit_client"]["latency_useful_ms"],
            "permit_statuses": step["permit_client"]["statuses"],
            "dev_latency_ms": step["dev_client"]["latency_useful_ms"],
            "dev_statuses": step["dev_client"]["statuses"], "dev_useful_fraction": step["dev_client"]["useful_fraction"],
            "L2": step["L2"], "v5_service": step["v5_service"],
            "metric_delta": {k: v for k, v in step["gateway_metric_delta"].items() if "audit" in k or "v5_client" in k}}
    return out


def failure_tables(runs):
    out = {}
    for name, run in sorted(runs.items()):
        if "failures_" not in name:
            continue
        step = next(s for s in run["steps"] if s["label"] == "timeline")
        out[name] = {"recovery_seconds": run.get("recovery_seconds"), "phases": run["phases"],
                     "L2": step["L2"], "egress": step["egress"], "observations": step["observations"],
                     "statuses": step["client"]["statuses"], "outcomes": step["client"]["outcomes"],
                     "metric_delta": {k: v for k, v in step["gateway_metric_delta"].items()
                                      if "guard" in k or "v5_client" in k or "canonical_failed" in k}}
    return out


def soak_rates(tables):
    """Fixed by the protocol: 0.7 x the lowest sustainable rate of each family, V4_ONLY included."""
    v4 = tables.get("v4/V4_ONLY", {}).get("max_sustainable_per_rep", [])
    out = {}
    for config in ("reference", "verified"):
        values = list(v4)
        for mode in ("V5_ONLY", "CASCADE_ACTIVE", "CASCADE_OBSERVE"):
            values += tables.get(f"{config}/{mode}", {}).get("max_sustainable_per_rep", [])
        values = [v for v in values if v is not None]
        if values:
            out[config] = round(0.7 * min(values), 2)
    return out


def pooled_stages(work):
    """Route and stage percentiles of the soak runs, pooled over repetitions. Reads the decision logs,
    which stay outside the repository; the percentiles carry no request data."""
    groups = collections.defaultdict(list)
    for path in sorted(glob.glob(os.path.join(work, "soak*", "decisions.jsonl"))):
        with open(path, encoding="utf-8") as fh:
            groups[os.path.basename(os.path.dirname(path)).rsplit("_rep", 1)[0]] += map(json.loads, fh)
    return {name: LL.decision_accounting(records) for name, records in groups.items()}


def soak_high_rate(tables):
    """0.7 x the lowest sustainable rate of the modes of verified that V4 does not bound."""
    values = [v for mode in ("V5_ONLY", "CASCADE_ACTIVE")
              for v in tables.get(f"verified/{mode}", {}).get("max_sustainable_per_rep", []) if v is not None]
    return round(0.7 * min(values), 2) if values else None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", required=True)
    parser.add_argument("--work", help="work directory of the run, for the pooled soak stages")
    args = parser.parse_args()
    runs = load_runs(args.run)
    tables = ladder_tables(args.run, runs)
    analysis = {"ladder": tables, "stages": stage_tables(runs),
                "observe_impact": observe_impact(args.run, runs, tables),
                "soak_rates": soak_rates(tables), "soak_high_rate": soak_high_rate(tables),
                "soak": soak_tables(args.run, runs), "recovery": recovery_tables(runs),
                "audit": audit_tables(runs), "failures": failure_tables(runs)}
    if args.work:
        analysis["soak_stages_pooled"] = pooled_stages(args.work)
    with open(os.path.join(args.run, "analysis.json"), "w", encoding="utf-8") as fh:
        json.dump(analysis, fh, indent=1, sort_keys=True)
        fh.write("\n")
    for key, table in tables.items():
        print(key, "sustainable", table["max_sustainable_per_rep"], "saturated at",
              table["first_saturated_per_rep"], "recovery", table["recovery_seconds_per_rep"])
        for row in table["levels"]:
            useful = row["useful_per_s"]
            latency = row["latency_useful_ms"]
            print(f"  {row['offered_rate']:>4}/s offered={row['offered']:>5} useful={useful['mean']:.2f}/s "
                  f"[{useful['min']:.2f}-{useful['max']:.2f}] sat={row['saturated_reps']}/{row['repetitions']} "
                  f"503={row['rejected_503']} to={row['client_timeouts']} p50={latency.get('p50')} "
                  f"p95={latency.get('p95')} p99={latency.get('p99')} L2={row['l2_conformant_steps']}")
    print("soak rates", analysis["soak_rates"], "soak high rate", analysis["soak_high_rate"])
    for name, row in analysis["recovery"].items():
        print(name, "recovered", row["recovered"], row["recovery_seconds"], "probes", row["probe_statuses"])


if __name__ == "__main__":
    main()
