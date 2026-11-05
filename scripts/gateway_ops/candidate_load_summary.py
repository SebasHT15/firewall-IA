"""
One summary of a candidate's load run, from its results and rows. No GPU, no service.

    .venv-dataplane/bin/python scripts/gateway_ops/candidate_load_summary.py --run <evidence dir> \
        --work <private dir> --inputs <private inputs.jsonl> --out <new file>

Percentiles across repetitions come from the pooled rows, by nearest rank, never from an average. The
run keeps its own tables in `analysis.json`; this adds what they spread over many files: totals of every
step, peaks of resources and queues, audit cells pooled, and which cases V5 could not answer. Case ids
and closed codes only, read from the private logs. Nothing here is a capacity of any deployment.
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

SKIP = ("protocol.json", "rates_from_ladder.json")
TOTALS = ("offered", "completed", "useful", "rejected_503", "bad_gateway_502", "client_timeouts",
          "connection_errors", "closed_without_response", "incomplete_body", "close_delimited", "excess_body",
          "other_status")
SOAK_STAGES = ("v5_inference", "v5_queue", "v5_service", "v5", "model2", "canonical", "binding", "admission")


def results(run):
    out = {}
    for path in sorted(glob.glob(os.path.join(run, "*.json"))):
        name = os.path.basename(path)
        if name not in SKIP and not name.startswith("analysis"):
            with open(path, encoding="utf-8") as fh:
                out[name[:-5]] = json.load(fh)
    return out


def rows_of(run, name):
    with open(os.path.join(run, "rows", f"{name}.jsonl"), encoding="utf-8") as fh:
        return [json.loads(line) for line in fh]


def totals(runs):
    """Every step of every run. `L2_not_conformant` must stay empty: no denial reached the sink."""
    out = collections.Counter()
    bad = []
    for name, run in runs.items():
        for step in run["steps"]:
            for key in TOTALS:
                out[key] += step["client"].get(key) or 0
            if not step["L2"]["conformant"]:
                bad.append(f"{name}/{step['label']}")
    return {**dict(out), "steps": sum(len(r["steps"]) for r in runs.values()), "L2_not_conformant": bad}


def peaks(runs):
    gpu = collections.defaultdict(list)
    roles = collections.defaultdict(list)
    queues = collections.defaultdict(list)
    for run in runs.values():
        for step in run["steps"]:
            resources = step["resources"]
            for key, value in resources.get("gpu", {}).items():
                gpu[key].append(value)
            for role, value in resources.get("roles", {}).items():
                roles[role].append(value["rss_mib_max"])
            for name, value in resources.get("queues", {}).items():
                queues[name].append(value["max"])
    return {"gpu": {"memory_mib_max": max(gpu["memory_mib_max"]), "temp_c_max": max(gpu["temp_c_max"]),
                    "clock_mhz_min": min(gpu["clock_mhz_min"])},
            "rss_mib_max": {role: max(values) for role, values in sorted(roles.items())},
            "queue_max": {name: max(values) for name, values in sorted(queues.items())}}


def audit_cells(run, runs):
    """Per sampling rate and budget, pooled over repetitions."""
    cells = collections.defaultdict(list)
    for name, document in runs.items():
        if name.startswith("audit_"):
            cells[(document["sample_rate"], document["audit_budget"])].append(name)
    out = []
    for (rate, budget), names in sorted(cells.items()):
        rows = [r for name in names for r in rows_of(run, name) if r["step"] == "audit"]
        steps = [next(s for s in runs[n]["steps"] if s["label"] == "audit") for n in names]
        accounting = collections.Counter()
        for step in steps:
            for key in ("requested", "completed", "discarded", "failed"):
                accounting[key] += (step["audit_accounting"] or {}).get(key) or 0
        verdicts = collections.Counter()
        for step in steps:
            verdicts.update(step["audit"])
        out.append({"sample_rate": rate, "budget": budget, "repetitions": len(names),
                    "dev_ms": LL.dist([r["latency_ms"] for r in rows if r["kind"] == "dev" and LL.useful(r)]),
                    "permit_ms": LL.dist([r["latency_ms"] for r in rows
                                          if r["kind"] == "permit" and LL.useful(r)]),
                    "accounting": dict(accounting), "verdicts": dict(verdicts)})
    return out


def soak_stage_table(analysis):
    out = {}
    for name, document in analysis["soak_stages_pooled"].items():
        routes = {}
        for route, part in document["routes"].items():
            stages = {stage: part["stages_ms"][stage] for stage in SOAK_STAGES if stage in part["stages_ms"]}
            routes[route] = {"n": part["n"], "gateway_ms": part["gateway_ms"], "stages_ms": stages,
                             "decoder_pipeline_ms": part["decoder_pipeline_ms"]}
        out[name] = routes
    return out


def drift(run, runs):
    """First and last third of every soak of one family, pooled."""
    out = {}
    for prefix in ("soak_candidate_V5_ONLY", "soak_candidate_CASCADE_ACTIVE", "soakhigh_candidate_V5_ONLY",
                   "soakhigh_candidate_CASCADE_ACTIVE"):
        first, last = [], []
        for name in runs:
            if name.startswith(prefix):
                rows = sorted((r for r in rows_of(run, name) if r["step"] == "soak"), key=lambda r: r["t_sched"])
                third = len(rows) // 3
                first += rows[:third]
                last += rows[-third:]
        if first:
            out[prefix] = {"first_third_ms": LL.dist([r["latency_ms"] for r in first if LL.useful(r)]),
                           "last_third_ms": LL.dist([r["latency_ms"] for r in last if LL.useful(r)]),
                           "first_third_503": sum(r["status"] == 503 for r in first),
                           "last_third_503": sum(r["status"] == 503 for r in last)}
    return out


def unanswered(work, inputs):
    """V5 answers that were not a decision, per case. The gateway denied every one of them."""
    with open(inputs, encoding="utf-8") as fh:
        known = {r["wire_sha256"]: r for r in map(json.loads, fh) if r.get("wire_ok")}
    counts = collections.Counter()
    calls = 0
    for path in glob.glob(os.path.join(work, "*", "decisions.jsonl")):
        with open(path, encoding="utf-8") as fh:
            for record in map(json.loads, fh):
                v5 = record.get("v5") or {}
                if record.get("kind") != "decision" or v5.get("status") is None:
                    continue
                calls += 1
                if v5["status"] == "invalid":
                    case = known.get(record.get("wire_sha256"), {})
                    counts[(v5.get("invalid_reason"), case.get("id"), case.get("cohort"), case.get("label"))] += 1
    return {"v5_answers_in_all_runs": calls,
            "cases": [{"invalid_reason": k[0], "case": k[1], "cohort": k[2], "reference": k[3], "times": v}
                      for k, v in counts.most_common()]}


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--run", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--inputs", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    runs = results(args.run)
    with open(os.path.join(args.run, "analysis.json"), encoding="utf-8") as fh:
        analysis = json.load(fh)
    document = {"schema": "firewall-candidate-load-summary/v1", "runs": len(runs), "totals": totals(runs),
                "peaks": peaks(runs), "soak_pooled": analysis["soak_pooled"],
                "soak_stages": soak_stage_table(analysis), "drift": drift(args.run, runs),
                "audit_cells": audit_cells(args.run, runs), "recovery": analysis["recovery"],
                "failures": {name: {"recovery_seconds": part["recovery_seconds"], "statuses": part["statuses"],
                                    "L2_conformant": part["L2"]["conformant"]}
                             for name, part in analysis["failures"].items()},
                "v5_without_decision": unanswered(args.work, args.inputs),
                "scope": "This machine, this DEV mix, loopback, inert sink. Not a deployment capacity. "
                         "200 ms is aspirational and D36 is not rewritten."}
    with open(args.out, "x", encoding="utf-8") as fh:
        json.dump(document, fh, indent=1, sort_keys=True)
        fh.write("\n")
    print(args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
