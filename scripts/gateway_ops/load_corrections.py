"""
What the corrections to `load_lib.py` change in a finished load run. No GPU, no service.

    .venv-dataplane/bin/python scripts/gateway_ops/load_corrections.py --run <evidence dir> \
        --work <private dir> --executed <measured load_lib.py> --out <new directory>

The run is only read. `--out` must be new: a correction is published beside the evidence, never over
it. The measured copy of the library is imported and run on the same records as the current one, so
each number below is the difference between the two versions of the code and nothing else.

Two questions, answered from different evidence:

  DECODER PATH. The decision records keep `decoder_verified`, `decoder_fallback` and
  `generated_tokens`, so the corrected accounting is exact.

  RESPONSE COMPLETENESS. The rows of a past run do not say how many body bytes arrived, so a cut body
  cannot be counted directly. What can be established is where one could have come from: which rows
  ended at a moment the peer could have died. That gives a bound, and it is reported as a bound.

`--out` receives closed codes and numbers only. The private directory is not copied.
"""
import argparse
import collections
import glob
import hashlib
import importlib.util
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import load_lib as LL  # noqa: E402

# Seconds after a process was killed in which a row with a status would need explaining. The event is
# stamped just before the signal, and a client sees the end of the connection within milliseconds.
KILL_WINDOW_S = 1.0
INFORME_GROUPS = ("soak_reference_CASCADE_ACTIVE", "soak_verified_CASCADE_ACTIVE",
                  "soakhigh_verified_CASCADE_ACTIVE", "soakhigh_verified_V5_ONLY")


def load_measured(path):
    spec = importlib.util.spec_from_file_location("load_lib_measured", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_jsonl(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def percentiles(dist):
    return {k: dist.get(k) for k in ("n", "p50", "p95", "p99")}


def flags(record):
    service = record.get("v5_service") or {}
    return service if service.get("service_ms") is not None else None


def run_decisions(work):
    runs = {}
    for path in sorted(glob.glob(os.path.join(work, "*", "decisions.jsonl"))):
        runs[os.path.basename(os.path.dirname(path))] = read_jsonl(path)
    return runs


def compare(old, new, records):
    """Both versions over one set of records, route by route."""
    before, after = old.decision_accounting(records), new.decision_accounting(records)
    out = {}
    for route, data in after["routes"].items():
        prior = before["routes"][route]
        out[route] = {
            "inference_before": percentiles(prior["stages_ms"].get("v5_inference", {})),
            "inference_after": percentiles(data["stages_ms"].get("v5_inference", {})),
            "no_generation": data["stages_ms"].get("v5_no_generation", {}).get("n", 0),
            "paths_before": {k: percentiles(v) for k, v in prior["decoder_pipeline_ms"].items()},
            "paths_after": {k: percentiles(v) for k, v in data["decoder_pipeline_ms"].items()}}
    return out


def largest_shift(comparisons):
    """Largest change in a percentile of V5 inference, where each side has enough samples for it."""
    worst = {"p50": 0.0, "p95": 0.0, "p99": 0.0}
    for routes in comparisons.values():
        for data in routes.values():
            for key in worst:
                a, b = data["inference_before"].get(key), data["inference_after"].get(key)
                if a is not None and b is not None:
                    worst[key] = max(worst[key], abs(a - b))
    return worst


def decoder_report(old, new, runs, run_dir):
    pairs = collections.Counter()
    by_path = collections.defaultdict(collections.Counter)
    for name, records in runs.items():
        family = name.split("_")[0]
        for record in records:
            service = flags(record)
            if service is None:
                continue
            pairs[(service.get("decoder_verified"), service.get("decoder_fallback"),
                   "no tokens" if service.get("generated_tokens") == 0 else "tokens")] += 1
            by_path[family][LL.decoder_path(service)] += 1
    per_run = {name: compare(old, new, records) for name, records in runs.items()}

    steps = {}
    for name, records in runs.items():
        path = os.path.join(run_dir, f"{name}.json")
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8") as fh:
            document = json.load(fh)
        for step in document["steps"]:
            window = [r for r in records if step["t0"] <= r.get("utc", 0) <= step["t1"]]
            if window:
                steps[f"{name}/{step['label']}"] = compare(old, new, window)

    grouped = collections.defaultdict(list)
    for name, records in runs.items():
        grouped[name.rsplit("_rep", 1)[0]] += records
    informe = {name: compare(old, new, grouped[name]) for name in INFORME_GROUPS if name in grouped}
    soak_verified = [r for name, records in runs.items() if name.startswith("soak_verified_")
                     for r in records]
    return {
        "flag_pairs_kept": {f"verified={k[0]} fallback={k[1]} {k[2]}": v
                            for k, v in sorted(pairs.items(), key=str)},
        "corrected_paths_by_phase": {k: dict(v) for k, v in sorted(by_path.items())},
        "soak_stage_tables_of_the_report": informe,
        "decoder_table_of_the_report": compare(old, new, soak_verified),
        "largest_inference_shift_ms": {"per_run": largest_shift(per_run), "per_step": largest_shift(steps)},
        "steps_compared": len(steps), "runs_compared": len(per_run),
        "per_run": per_run}


def row_end(row):
    return row["t_sched"] + row["latency_ms"] / 1000


def completeness_report(run_dir):
    totals = collections.Counter()
    timed_rows = {}
    for path in sorted(glob.glob(os.path.join(run_dir, "rows", "*.jsonl"))):
        name = os.path.basename(path)[:-len(".jsonl")]
        rows = read_jsonl(path)
        timed_rows[name] = rows
        faulted = "failures" in name
        for row in rows:
            totals[("fault timeline" if faulted else "no process killed",
                    row["outcome"].split(":")[0], "status" if row["status"] is not None else "no status")] += 1
    kills = []
    for name, rows in sorted(timed_rows.items()):
        path = os.path.join(run_dir, f"{name}.json")
        if not os.path.exists(path):
            continue
        with open(path, encoding="utf-8") as fh:
            document = json.load(fh)
        for event, stamp in document.get("events", ()):
            if event != "gateway_killed":
                continue
            with_status = sorted(row_end(r) - stamp for r in rows if r["status"] is not None)
            after = [d for d in with_status if d >= 0]
            before = [d for d in with_status if d < 0]
            kills.append({
                "run": name, "rows": len(rows),
                "rows_with_status_ending_within_window_after_kill":
                    sum(1 for d in after if d <= KILL_WINDOW_S),
                "last_row_with_status_before_kill_s": before[-1] if before else None,
                "first_row_with_status_after_kill_s": after[0] if after else None,
                "rows_without_status_ending_within_window": sum(
                    1 for r in rows if r["status"] is None and 0 <= row_end(r) - stamp <= KILL_WINDOW_S)})
    return {
        "rows_keep_body_bytes": False,
        "rows_by_outcome": {" / ".join(k): v for k, v in sorted(totals.items())},
        "kill_window_s": KILL_WINDOW_S, "gateway_kills": kills,
        "candidates_for_a_cut_body": sum(k["rows_with_status_ending_within_window_after_kill"]
                                         for k in kills)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--executed", required=True, help="the load_lib.py that measured this run")
    parser.add_argument("--out", required=True)
    args = parser.parse_args()
    os.makedirs(args.out, exist_ok=True)
    with open(args.executed, "rb") as fh:
        executed = hashlib.sha256(fh.read()).hexdigest()
    with open(os.path.join(HERE, "load_lib.py"), "rb") as fh:
        current = hashlib.sha256(fh.read()).hexdigest()
    old = load_measured(args.executed)
    provenance = {"schema": "firewall-load-corrections/v1", "run": args.run,
                  "load_lib_measured_sha256": executed, "load_lib_corrected_sha256": current,
                  "private_records_copied": False}
    decoder = decoder_report(old, LL, run_decisions(args.work), args.run)
    completeness = completeness_report(args.run)
    for name, payload in (("decoder_accounting.json", decoder),
                          ("response_completeness.json", completeness)):
        with open(os.path.join(args.out, name), "x", encoding="utf-8") as fh:
            json.dump({**provenance, **payload}, fh, indent=1, sort_keys=True)
            fh.write("\n")
    print(json.dumps({k: decoder[k] for k in ("flag_pairs_kept", "largest_inference_shift_ms",
                                              "corrected_paths_by_phase")}, indent=1))
    print(json.dumps({k: completeness[k] for k in ("candidates_for_a_cut_body", "gateway_kills",
                                                   "rows_by_outcome")}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
