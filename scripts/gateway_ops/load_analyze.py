"""
Tables of a load run, recomputed from the per-request rows. No GPU, no service.

    .venv-dataplane/bin/python scripts/gateway_ops/load_analyze.py --run <evidence dir> --out <new file>

Percentiles over repetitions are computed on the pooled rows, nearest rank; percentiles are never
averaged. Rates are given per repetition, as mean and range, so that the spread stays visible.

It never replaces an analysis: `--out` must not exist. `--markdown` also writes the tables of a run.
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
        if os.path.basename(path) in ("protocol.json", "protocol_addendum.json", "analysis.json"):
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
                "complete": sum(s["client"]["completed"] for s in steps),
                "incomplete_body": sum(s["client"].get("incomplete_body", 0) for s in steps),
                "rejected_503": sum(s["client"]["rejected_503"] for s in steps),
                "bad_gateway_502": sum(s["client"]["bad_gateway_502"] for s in steps),
                "client_timeouts": sum(s["client"]["client_timeouts"] for s in steps),
                "connection_errors": sum(s["client"]["connection_errors"] for s in steps),
                "queue_peak": queue_peaks(steps),
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


def queue_peaks(steps):
    """Deepest sample of each queue over these steps. A peak, so a maximum and never a mean of means."""
    peaks = {}
    for step in steps:
        for name, value in step["resources"].get("queues", {}).items():
            peaks[name] = max(peaks.get(name, 0), value["max"])
    return peaks


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


def soak_pooled(run_dir, runs):
    """End-to-end latency of the soak runs, each mode's repetitions pooled into one distribution."""
    groups = collections.defaultdict(list)
    for name in runs:
        if name.startswith(("soak_", "soakhigh_")):
            groups[name.rsplit("_rep", 1)[0]] += [r for r in rows_of(run_dir, name) if r["step"] == "soak"]
    return {name: {"offered": len(rows), "complete": sum(r["status"] is not None for r in rows),
                   "useful": sum(LL.useful(r) for r in rows),
                   "latency_useful_ms": LL.dist([r["latency_ms"] for r in rows if LL.useful(r)])}
            for name, rows in sorted(groups.items())}


def soak_rates(tables):
    """Fixed by the protocol: 0.7 x the lowest sustainable rate of each family, V4_ONLY included."""
    v4 = tables.get("v4/V4_ONLY", {}).get("max_sustainable_per_rep", [])
    out = {}
    for config in sorted({key.split("/")[0] for key in tables} - {"v4"}):
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
    """0.7 x the lowest sustainable rate of the modes that V4 does not bound, for the configuration
    under test."""
    config = "candidate" if any(key.startswith("candidate/") for key in tables) else "verified"
    values = [v for mode in ("V5_ONLY", "CASCADE_ACTIVE")
              for v in tables.get(f"{config}/{mode}", {}).get("max_sustainable_per_rep", []) if v is not None]
    return round(0.7 * min(values), 2) if values else None


def _cell(value, digits=1):
    return "–" if value is None else f"{value:.{digits}f}"


def markdown(analysis):
    """The tables of a run, with the status of what they are. Only numbers of this run."""
    lines = ["# Tablas de la corrida", "",
             "Generado por `load_analyze.py`. Percentiles agrupados sobre las filas, nunca promediados. "
             "Tasas por repetición como media [mín-máx]. Criterios de saturación descriptivos: no son un "
             "SLO. Nada aquí aprueba un candidato.", "",
             "| Configuración y modo | r/s | Ofrecidas | Completas | Útil r/s | 503 | 502 | Timeouts | "
             "Errores | Cortadas | P50 | P95 | P99 | Saturadas |", "|---|---:|---:|---:|---:|---:|---:|"
             "---:|---:|---:|---:|---:|---:|---:|"]
    for key, table in analysis["ladder"].items():
        for row in table["levels"]:
            useful, latency = row["useful_per_s"], row["latency_useful_ms"]
            lines.append(
                f"| {key} | {row['offered_rate']} | {row['offered']} | {row['complete']} | "
                f"{_cell(useful['mean'], 2)} [{_cell(useful['min'], 2)}-{_cell(useful['max'], 2)}] | "
                f"{row['rejected_503']} | {row['bad_gateway_502']} | {row['client_timeouts']} | "
                f"{row['connection_errors']} | {row['incomplete_body']} | {_cell(latency.get('p50'))} | "
                f"{_cell(latency.get('p95'))} | {_cell(latency.get('p99'))} | "
                f"{row['saturated_reps']}/{row['repetitions']} |")
    lines += ["", "| Soak agrupado | Ofrecidas | Completas | Útiles | P50 | P95 | P99 |",
              "|---|---:|---:|---:|---:|---:|---:|"]
    for name, row in analysis.get("soak_pooled", {}).items():
        latency = row["latency_useful_ms"]
        lines.append(f"| {name} | {row['offered']} | {row['complete']} | {row['useful']} | "
                     f"{_cell(latency.get('p50'))} | {_cell(latency.get('p95'))} | {_cell(latency.get('p99'))} |")
    pooled = analysis.get("soak_stages_pooled", {})
    if pooled:
        lines += ["", "| Soak por ruta y etapa, agrupado | n | P50 | P95 | P99 |", "|---|---:|---:|---:|---:|"]
        for name, data in sorted(pooled.items()):
            for route, values in data["routes"].items():
                for stage, dist in [("gateway", values["gateway_ms"]), *values["stages_ms"].items(),
                                    *((f"decoder {k}", v) for k, v in values["decoder_pipeline_ms"].items())]:
                    lines.append(f"| {name} / {route} / {stage} | {dist.get('n')} | {_cell(dist.get('p50'))} "
                                 f"| {_cell(dist.get('p95'))} | {_cell(dist.get('p99'))} |")
    lines += ["", "| Recuperación | Recuperó | Segundos | Sondas |", "|---|---|---:|---:|"]
    for name, row in analysis["recovery"].items():
        lines.append(f"| {name} | {row['recovered']} | {_cell(row['recovery_seconds'])} | {row['probes']} |")
    for name, row in analysis["failures"].items():
        lines += ["", f"Fallos de `{name}`: " + ", ".join(
            f"{k} {_cell(v)} s" for k, v in (row["recovery_seconds"] or {}).items())]
    return "\n".join(lines) + "\n"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", required=True)
    parser.add_argument("--work", help="work directory of the run, for the pooled soak stages")
    parser.add_argument("--out", help="default: analysis.json in the run; must not exist")
    parser.add_argument("--markdown", help="also write the tables here; must not exist")
    args = parser.parse_args()
    runs = load_runs(args.run)
    tables = ladder_tables(args.run, runs)
    analysis = {"ladder": tables, "stages": stage_tables(runs),
                "observe_impact": observe_impact(args.run, runs, tables),
                "soak_rates": soak_rates(tables), "soak_high_rate": soak_high_rate(tables),
                "soak": soak_tables(args.run, runs), "soak_pooled": soak_pooled(args.run, runs),
                "recovery": recovery_tables(runs),
                "audit": audit_tables(runs), "failures": failure_tables(runs)}
    if args.work:
        analysis["soak_stages_pooled"] = pooled_stages(args.work)
    with open(args.out or os.path.join(args.run, "analysis.json"), "x", encoding="utf-8") as fh:
        json.dump(analysis, fh, indent=1, sort_keys=True)
        fh.write("\n")
    if args.markdown:
        with open(args.markdown, "x", encoding="utf-8") as fh:
            fh.write(markdown(analysis))
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
