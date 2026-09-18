"""
firewall-IA — controlled V4 model-side inference benchmark (Issue #9).

WHAT THIS MEASURES
    The time `inference_core.classify_timed()` spends inside `generate()`,
    with the device synchronized on both sides so the stopwatch covers work
    that has actually finished, not work that has merely been submitted.

    IN  scope (the primary metric):  generate()
    OUT of scope (timed separately, reported separately, never pooled into the
    primary metric):  prompt construction · tokenization · host->device
    transfer · decoding · contract parsing

    This is NOT API latency and NOT gateway latency. End-to-end measurement is
    Issue #18. The D36 latency objective (P95 of the inference pipeline
    <= 200 ms, steady state) is read from the pipeline statistic this harness
    also records (`steady_pipeline_p95_ms`), not from the generate()-only
    primary metric.

FOUR POPULATIONS, KEPT SEPARATE
    1. model_load        loading base + adapter in a fresh process
    2. first_inference   the FIRST generate() in that process (cold start)
    3. warmup            a fixed, predefined set of additional generations
    4. steady_state      the measurement set -> the reported statistics

    The requests used for (2) and (3) are chosen deterministically from a seed
    BEFORE any measurement, and are recorded in `protocol.json`. Populations 2
    and 3 are never pooled into 4. Nothing is discarded: every sample of every
    population is written to the per-run JSONL.

NO OUTLIER REMOVAL. Extreme samples are characterized, never dropped.

RUNS AND PROCESSES
    One run = one fresh OS process. `protocol` spawns N of them, so each run has
    a genuine cold start. The model is loaded ONCE per process and reused for
    every request in that run; batch size 1, concurrency 1.

USAGE
    python3.12 benchmark_inference.py self-test              # no model needed
    python3.12 benchmark_inference.py smoke                  # small functional check
    python3.12 benchmark_inference.py estimate               # duration estimate only
    python3.12 benchmark_inference.py protocol \\
        --experiment baseline-local-v1 --runs 3              # the real measurement
    python3.12 benchmark_inference.py summarize \\
        --experiment baseline-local-v1                       # re-aggregate existing runs
"""

import argparse
import hashlib
import json
import math
import os
import random
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone

import benchmark_env as envmod

REPO_ROOT = os.path.dirname(os.path.abspath(__file__))
BENCH_ROOT = os.path.join(REPO_ROOT, "reports", "benchmarks")

DEFAULT_DATASET = os.path.join(REPO_ROOT, "datasets", "v4_clean", "eval.jsonl")
DEFAULT_MANIFEST = os.path.join(REPO_ROOT, "datasets", "manifest_v4_clean.json")

# ── Protocol constants ─────────────────────────────────────────────────────
# Bumped when a change would make new numbers incomparable with old ones.
PROTOCOL_VERSION = "1.0.0"

# Identifies WHAT the stopwatch covers. Two reports with different timing
# scopes are NOT comparable, whatever units they are printed in. The historical
# V4 evaluation ran an unsynchronized generate()-only timer and therefore has a
# different scope id — see `HISTORICAL_TIMING_SCOPE`.
TIMING_SCOPE_ID = "generate-only/device-synchronized/v1"
HISTORICAL_TIMING_SCOPE = "generate-only/unsynchronized/v0"

# Fixed for this reference: one process, one request at a time.
BATCH_SIZE = 1
CONCURRENCY = 1

# Warm-up selection. Deterministic, fixed before measuring, recorded in
# protocol.json: 1 request for the cold-start sample + 4 further warm-ups.
WARMUP_SEED = 42
N_FIRST_INFERENCE = 1
N_WARMUP = 4

PERCENTILE_METHOD = "nearest-rank (ceil(q*n), 1-indexed, no interpolation)"

# Direction of improvement per reported metric. Embedded in every summary so a
# report stays self-describing and the comparator never has to guess.
METRIC_DIRECTIONS = {
    "steady_generate_mean_ms": {"unit": "ms", "lower_is_better": True, "family": "latency"},
    "steady_generate_p50_ms": {"unit": "ms", "lower_is_better": True, "family": "latency"},
    "steady_generate_p95_ms": {"unit": "ms", "lower_is_better": True, "family": "latency"},
    "steady_generate_p99_ms": {"unit": "ms", "lower_is_better": True, "family": "latency"},
    "steady_generate_min_ms": {"unit": "ms", "lower_is_better": True, "family": "latency"},
    "steady_generate_max_ms": {"unit": "ms", "lower_is_better": True, "family": "latency"},
    "steady_generate_stdev_ms": {"unit": "ms", "lower_is_better": True, "family": "latency"},
    "steady_pipeline_p95_ms": {"unit": "ms", "lower_is_better": True, "family": "latency"},
    "first_inference_ms": {"unit": "ms", "lower_is_better": True, "family": "cold_start"},
    "model_load_ms": {"unit": "ms", "lower_is_better": True, "family": "cold_start"},
    "peak_vram_allocated_mib": {"unit": "MiB", "lower_is_better": True, "family": "memory"},
    "peak_vram_reserved_mib": {"unit": "MiB", "lower_is_better": True, "family": "memory"},
    "quality_attack_detection_rate": {"unit": "ratio", "lower_is_better": False,
                                      "family": "quality"},
    "quality_false_positive_rate": {"unit": "ratio", "lower_is_better": True,
                                    "family": "quality"},
    "quality_false_negative_rate": {"unit": "ratio", "lower_is_better": True,
                                    "family": "quality"},
    "quality_invalid_output_rate": {"unit": "ratio", "lower_is_better": True,
                                    "family": "quality"},
    "quality_accuracy": {"unit": "ratio", "lower_is_better": False, "family": "quality"},
    "generated_tokens_mean": {"unit": "tokens", "lower_is_better": None,
                              "family": "workload"},
    "prompt_tokens_mean": {"unit": "tokens", "lower_is_better": None, "family": "workload"},
}


# ── Statistics ─────────────────────────────────────────────────────────────
def percentile(sorted_vals, q):
    """Nearest-rank percentile, q in [0,1].

    Identical definition to `test_model.percentile`, so benchmark percentiles
    and the E5 evaluation percentiles mean the same thing. Enforced by
    `tests/test_benchmark.py::TestPercentileMatchesEvaluationHarness`.
    """
    if not sorted_vals:
        return None
    k = max(1, math.ceil(q * len(sorted_vals)))
    return sorted_vals[min(k, len(sorted_vals)) - 1]


def summarize(samples, scope=None, unit="ms"):
    """mean / P50 / P95 / P99 / min / max / stdev over `samples`.

    Keys carry the unit (`mean_ms`, `mean_tokens`, ...) so a distribution can
    never be read as milliseconds when it counts tokens.

    Every sample is included. Nothing is trimmed, winsorized or dropped: a
    slow sample is a real observation of this system.
    """
    vals = [float(v) for v in samples]
    if not vals:
        return {"count": 0, "scope": scope, "unit": unit}
    s = sorted(vals)
    u = unit
    out = {
        "count": len(s),
        "unit": unit,
        f"mean_{u}": statistics.mean(s),
        f"p50_{u}": percentile(s, 0.50),
        f"p95_{u}": percentile(s, 0.95),
        f"p99_{u}": percentile(s, 0.99),
        f"min_{u}": s[0],
        f"max_{u}": s[-1],
        f"stdev_{u}": statistics.stdev(s) if len(s) > 1 else 0.0,
        "percentile_method": PERCENTILE_METHOD,
    }
    if scope:
        out["scope"] = scope
    # Outliers are characterized, never removed.
    out["samples_above_p99"] = sum(1 for v in s if v > out[f"p99_{u}"])
    out["outlier_policy"] = "none removed; all samples retained and reported"
    return out


def spread(values):
    """Run-to-run variation of one statistic across runs.

    `spread_pct` is the peak-to-peak range as a percentage of the mean — a
    direct answer to "how repeatable is this number?".
    """
    vals = [v for v in values if v is not None]
    if not vals:
        return {"count": 0}
    mean = statistics.mean(vals)
    out = {
        "count": len(vals),
        "values": vals,
        "min": min(vals),
        "max": max(vals),
        "mean": mean,
        "median": statistics.median(vals),
        "stdev": statistics.stdev(vals) if len(vals) > 1 else 0.0,
        "range": max(vals) - min(vals),
    }
    out["spread_pct"] = (100.0 * out["range"] / mean) if mean else None
    return out


# ── Dataset ────────────────────────────────────────────────────────────────
def load_dataset(path, manifest_path):
    """Load the eval split and verify it against the dataset manifest.

    A benchmark measured on an unverified dataset is not reproducible, so a
    hash mismatch is fatal rather than a warning.
    """
    sha = envmod.sha256_file(path)
    if sha is None:
        raise SystemExit(f"FATAL: dataset not readable: {path}")

    expected, manifest_version = None, None
    try:
        with open(manifest_path) as f:
            man = json.load(f)
        expected = (man.get("artifact_sha256") or {}).get("eval")
        manifest_version = man.get("version")
    except (OSError, ValueError):
        pass

    if expected is None:
        raise SystemExit(
            f"FATAL: no eval sha256 in manifest {manifest_path}; refusing to "
            f"benchmark an unverified dataset.")
    if expected != sha:
        raise SystemExit(
            f"FATAL: dataset hash mismatch.\n  file     {sha}\n  manifest {expected}\n"
            f"The V4-clean split on disk is not the one the manifest pins.")

    rows = []
    with open(path) as f:
        for line in f:
            if line.strip():
                rows.append(json.loads(line))
    return rows, {
        "path": path,
        "sha256": sha,
        "verified_against_manifest": True,
        "manifest_path": manifest_path,
        "manifest_version": manifest_version,
        "rows": len(rows),
    }


def select_warmup(n_rows, seed=WARMUP_SEED):
    """Pick the cold-start and warm-up requests deterministically, in advance.

    Same seed -> same indices on any machine, so "which requests were the
    warm-up" is a fact of the protocol rather than of a particular run.
    """
    rng = random.Random(seed)
    picks = rng.sample(range(n_rows), N_FIRST_INFERENCE + N_WARMUP)
    return picks[:N_FIRST_INFERENCE], picks[N_FIRST_INFERENCE:]


def build_protocol(experiment_id, dataset_meta, rows, limit=0, note=None):
    """The measurement plan — written to disk BEFORE anything is measured."""
    n_total = len(rows)
    n_measured = min(limit, n_total) if limit else n_total
    first_idx, warm_idx = select_warmup(n_total)

    def _row_id(i):
        return {"row_index": i,
                "request_sha256": envmod.sha256_text(rows[i]["input"]),
                "expected": rows[i]["output"].partition("|")[0].strip().upper()}

    reduced = n_measured < n_total
    return {
        "protocol_schema": "firewall-IA/benchmark-protocol/1",
        "protocol_version": PROTOCOL_VERSION,
        "experiment_id": experiment_id,
        "written_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "note": note,
        "objective": ("Model-side generation latency of the V4 classifier, "
                      "measured under a fixed, reproducible protocol (Issue #9)."),
        "timing": {
            "scope_id": TIMING_SCOPE_ID,
            "primary_metric": "steady_generate_p95_ms",
            "in_scope": ["generate()"],
            "out_of_scope": ["prompt construction", "tokenization",
                             "host->device transfer", "decoding",
                             "contract parsing"],
            "out_of_scope_handling": ("timed and reported separately as "
                                      "pipeline stages; never pooled into the "
                                      "primary metric"),
            "synchronization": ("torch.cuda.synchronize() immediately before "
                                "starting and immediately after stopping the "
                                "generate() timer, so completed GPU work is "
                                "measured rather than submitted work"),
            "not_measured": ("API latency, proxy overhead and end-to-end gateway "
                             "latency. Those belong to Issue #18. The D36 "
                             "objective (P95 of the inference pipeline <= 200 ms, "
                             "steady state) is read from steady_pipeline_p95_ms, "
                             "not from the primary metric."),
        },
        "dataset": dataset_meta,
        "selection": {
            "policy": "full-split" if not reduced else "first-N-of-split",
            "n_requests_per_run": n_measured,
            "n_requests_available": n_total,
            "reduced_set": reduced,
            "reduction_justification": (
                None if not reduced else
                f"Reduced to the first {n_measured} rows of the split. This is "
                f"NOT the full evaluation: quality metrics computed on it are "
                f"not comparable with the {n_total}-row E5 baseline."),
            "order": "file order of the eval split (as generated by "
                     "parse_dataset_v4.py); labels are interleaved, not grouped",
            "seed": WARMUP_SEED,
            "seed_scope": "warm-up request selection only; request order is not shuffled",
        },
        "populations": {
            "model_load": "load_model() in a fresh process — 1 sample per run",
            "first_inference": {
                "n": N_FIRST_INFERENCE,
                "description": "first generate() in a fresh process (cold start)",
                "requests": [_row_id(i) for i in first_idx],
            },
            "warmup": {
                "n": N_WARMUP,
                "description": "additional generations before measurement begins",
                "requests": [_row_id(i) for i in warm_idx],
            },
            "steady_state": {
                "n": n_measured,
                "description": ("the measurement set — the only population in the "
                                "reported latency statistics"),
                "note": ("The cold-start and warm-up rows are members of the split "
                         "and are therefore executed again inside this pass. Their "
                         "cold/warm samples stay in their own populations; the "
                         "steady sample of the same row is a separate, later "
                         "observation. Greedy decoding is deterministic, so "
                         "re-running a row cannot change its decision."),
            },
        },
        "excluded_from_steady_statistics": ["model_load", "first_inference", "warmup"],
        "runs": {
            "process_model": "one fresh OS process per run; model loaded once per process",
            "batch_size": BATCH_SIZE,
            "concurrency": CONCURRENCY,
            "reuse": "the loaded model is reused for every request in a run",
        },
        "generation": {
            "do_sample": False,
            "greedy": True,
            "max_new_tokens": "inference_core.MAX_NEW_TOKENS (safety bound, not a target)",
            "termination": "native EOS",
            "unchanged": ("model, adapter, prompt, parsing, generation parameters "
                          "and quantization are exactly those of the V4 runtime "
                          "configuration (D27). Nothing was tuned for this benchmark."),
        },
        "statistics": {
            "reported": ["mean", "p50", "p95", "p99", "min", "max", "stdev"],
            "percentile_method": PERCENTILE_METHOD,
            "outlier_policy": "no outlier removal; extreme samples are characterized",
            "aggregation_across_runs": (
                "Two views, both reported. POOLED: every steady sample from every "
                "run in one distribution — the headline figure. PER-RUN: each run's "
                "own statistics, plus their min/median/max/mean/stdev/range, which "
                "is the run-to-run variation."),
            "headline": "pooled steady-state generate() P95",
        },
        "quality": {
            "metrics": "E5 binary metrics via test_model.score_binary (BLOCK positive)",
            "reported": ["attack detection rate", "false positives",
                         "false negatives", "invalid outputs"],
            "purpose": ("a latency result is only meaningful next to the quality "
                        "produced at that latency"),
        },
    }


# ── One run ────────────────────────────────────────────────────────────────
def execute_run(args):
    """Execute exactly ONE run in THIS process, and write its artifacts.

    Imports of the heavy stack happen here so `self-test` and `estimate` stay
    usable on a machine without the ML environment.
    """
    import torch
    import inference_core as core
    from test_model import score_binary, split_output

    out_dir = args.out_dir
    os.makedirs(out_dir, exist_ok=True)
    rows, dataset_meta = load_dataset(args.dataset, args.manifest)
    protocol = build_protocol(args.experiment, dataset_meta, rows, args.limit, args.note)

    proto_path = os.path.join(out_dir, "protocol.json")
    if not os.path.exists(proto_path):
        _write_json(proto_path, protocol)

    n = protocol["selection"]["n_requests_per_run"]
    first_idx, warm_idx = select_warmup(len(rows))
    samples_path = os.path.join(out_dir, f"run-{args.run_index:02d}.samples.jsonl")

    cond_before = envmod.runtime_conditions("immediately before this run")

    # ── 1. model load, in this fresh process ──────────────────────────────
    if torch.cuda.is_available():
        torch.cuda.reset_peak_memory_stats()
    t0 = time.perf_counter()
    tok, mdl = core.load_model(args.adapter)
    device = core.resolve_device()
    core.device_sync(device)
    model_load_ms = (time.perf_counter() - t0) * 1000
    placement = envmod.effective_placement(mdl)
    vram_after_load = _vram(torch)

    sink = open(samples_path, "w")
    records, steady, phase_samples = [], [], {"first_inference": [], "warmup": []}

    def one(idx, phase, seq):
        row = rows[idx]
        raw, m = core.classify_timed(tok, mdl, row["input"], device)
        tp = time.perf_counter()
        decision, reason, status = core.parse_prediction(raw)
        parse_ms = (time.perf_counter() - tp) * 1000
        expected, _ = split_output(row["output"])
        rec = {
            "run": args.run_index, "phase": phase, "seq": seq, "row_index": idx,
            "request_sha256": envmod.sha256_text(row["input"]),
            "request_chars": len(row["input"]),
            "expected": expected, "predicted": decision, "status": status,
            "predicted_reason": reason,
            "generate_ms": m["generate_ms"],
            "prompt_build_ms": m["prompt_build_ms"],
            "tokenize_ms": m["tokenize_ms"],
            "transfer_ms": m["transfer_ms"],
            "decode_ms": m["decode_ms"],
            "parse_ms": parse_ms,
            "prompt_tokens": m["prompt_tokens"],
            "generated_tokens": m["generated_tokens"],
            "stopped_on_eos": m["stopped_on_eos"],
        }
        rec["pipeline_ms"] = (rec["prompt_build_ms"] + rec["tokenize_ms"]
                              + rec["transfer_ms"] + rec["generate_ms"]
                              + rec["decode_ms"] + rec["parse_ms"])
        sink.write(json.dumps(rec) + "\n")
        return rec

    # ── 2. first inference (cold start) ───────────────────────────────────
    seq = 0
    for idx in first_idx:
        seq += 1
        rec = one(idx, "first_inference", seq)
        phase_samples["first_inference"].append(rec)

    # ── 3. warm-up ────────────────────────────────────────────────────────
    for idx in warm_idx:
        seq += 1
        rec = one(idx, "warmup", seq)
        phase_samples["warmup"].append(rec)

    # ── 4. steady state ───────────────────────────────────────────────────
    # Peak memory is re-armed here so the reported steady peak is the peak of
    # the measured phase, not of the load.
    if torch.cuda.is_available():
        torch.cuda.reset_peak_memory_stats()
    t_phase = time.perf_counter()
    for i in range(n):
        seq += 1
        rec = one(i, "steady", seq)
        steady.append(rec)
        records.append({"expected": rec["expected"], "predicted": rec["predicted"],
                        "status": rec["status"]})
        if args.progress and (i + 1) % args.progress == 0:
            done, elapsed = i + 1, time.perf_counter() - t_phase
            rate = done / elapsed
            print(f"  run {args.run_index}: {done}/{n} "
                  f"({elapsed / 60:.1f} min elapsed, "
                  f"~{(n - done) / rate / 60:.1f} min left)", flush=True)
    steady_wall_s = time.perf_counter() - t_phase
    sink.close()

    vram_steady = _vram(torch)
    cond_after = envmod.runtime_conditions("immediately after this run")

    gen = [r["generate_ms"] for r in steady]
    run_doc = {
        "run_schema": "firewall-IA/benchmark-run/1",
        "experiment_id": args.experiment,
        "run_index": args.run_index,
        "started_utc": cond_before["sampled_utc"],
        "finished_utc": cond_after["sampled_utc"],
        "pid": os.getpid(),
        "protocol_version": PROTOCOL_VERSION,
        "timing_scope_id": TIMING_SCOPE_ID,
        "samples_file": os.path.basename(samples_path),
        "device": device,
        "model_placement": placement,
        "model_load_ms": model_load_ms,
        "first_inference": {
            "policy": "EXCLUDED from steady-state statistics; reported separately",
            "samples_ms": [r["generate_ms"] for r in phase_samples["first_inference"]],
            "rows": [r["row_index"] for r in phase_samples["first_inference"]],
            "generated_tokens": [r["generated_tokens"]
                                 for r in phase_samples["first_inference"]],
        },
        "warmup": {
            "policy": "EXCLUDED from steady-state statistics; reported separately",
            "samples_ms": [r["generate_ms"] for r in phase_samples["warmup"]],
            "rows": [r["row_index"] for r in phase_samples["warmup"]],
        },
        "steady_state": {
            "wall_clock_s": steady_wall_s,
            "generate_ms": summarize(gen, scope=TIMING_SCOPE_ID),
            "pipeline_ms": summarize([r["pipeline_ms"] for r in steady],
                                     scope="prompt+tokenize+transfer+generate+decode+parse"),
            "stages_ms": {
                stage: summarize([r[stage] for r in steady])
                for stage in ("prompt_build_ms", "tokenize_ms", "transfer_ms",
                              "decode_ms", "parse_ms")
            },
            "workload": {
                "prompt_tokens": summarize([r["prompt_tokens"] for r in steady],
                                           unit="tokens"),
                "generated_tokens": summarize([r["generated_tokens"] for r in steady],
                                              unit="tokens"),
                "request_chars": summarize([r["request_chars"] for r in steady],
                                           unit="chars"),
                "stopped_on_eos_count": sum(1 for r in steady if r["stopped_on_eos"]),
                "hit_token_cap_count": sum(1 for r in steady if not r["stopped_on_eos"]),
            },
        },
        "memory": {
            "what_this_measures": (
                "PyTorch caching-allocator accounting for THIS process only. "
                "`allocated` is live tensor memory, `reserved` is what the "
                "allocator holds from the driver. Neither includes the CUDA "
                "context (~250-500 MiB) nor memory used by other processes, so "
                "neither equals nvidia-smi's figure for the GPU."),
            "after_model_load": vram_after_load,
            "peak_during_steady_state": vram_steady,
            "gpu_total_used_mib_before": _gpu_used(cond_before),
            "gpu_total_used_mib_after": _gpu_used(cond_after),
        },
        "quality": _quality(score_binary(records)),
        "conditions_before": cond_before,
        "conditions_after": cond_after,
    }
    _write_json(os.path.join(out_dir, f"run-{args.run_index:02d}.json"), run_doc)

    print(f"\nrun {args.run_index} done — steady n={len(gen)} "
          f"P50 {run_doc['steady_state']['generate_ms']['p50_ms']:.1f} ms "
          f"P95 {run_doc['steady_state']['generate_ms']['p95_ms']:.1f} ms "
          f"({steady_wall_s / 60:.1f} min)")
    return 0


def _vram(torch):
    if not torch.cuda.is_available():
        return {"available": False}
    return {
        "available": True,
        "allocated_mib": round(torch.cuda.memory_allocated() / (1024 ** 2), 1),
        "max_allocated_mib": round(torch.cuda.max_memory_allocated() / (1024 ** 2), 1),
        "reserved_mib": round(torch.cuda.memory_reserved() / (1024 ** 2), 1),
        "max_reserved_mib": round(torch.cuda.max_memory_reserved() / (1024 ** 2), 1),
    }


def _gpu_used(cond):
    gpus = cond.get("gpu") or []
    return gpus[0].get("memory_used_mib") if gpus else None


def _quality(binary):
    """E5 binary metrics, reduced to the fields Issue #9 asks for. The full
    `score_binary` output is kept alongside so nothing is lost."""
    return {
        "source": "test_model.score_binary (E5 frozen methodology, BLOCK positive)",
        "attack_detection_rate": binary.get("attack_detection_rate"),
        "false_positives": binary.get("false_positives"),
        "false_positive_rate": binary.get("false_positive_rate"),
        "false_negatives": binary.get("false_negatives"),
        "false_negative_rate": binary.get("false_negative_rate"),
        "invalid_outputs": binary.get("invalid_outputs"),
        "invalid_output_rate": binary.get("invalid_output_rate"),
        "accuracy": binary.get("accuracy"),
        "support": binary.get("support"),
        "confusion_matrix": binary.get("confusion_matrix"),
        "full": binary,
    }


# ── Aggregation across runs ────────────────────────────────────────────────
def summarize_experiment(experiment_id, out_dir, environment=None):
    """Aggregate every run-NN.json in `out_dir` into one comparable summary."""
    run_files = sorted(f for f in os.listdir(out_dir)
                       if f.startswith("run-") and f.endswith(".json")
                       and not f.endswith(".samples.jsonl"))
    runs = []
    for f in run_files:
        with open(os.path.join(out_dir, f)) as fh:
            runs.append(json.load(fh))
    if not runs:
        raise SystemExit(f"FATAL: no run-NN.json found in {out_dir}")

    with open(os.path.join(out_dir, "protocol.json")) as fh:
        protocol = json.load(fh)
    if environment is None:
        env_path = os.path.join(out_dir, "environment.json")
        environment = json.load(open(env_path)) if os.path.exists(env_path) else None

    # Pooled: every steady sample from every run in one distribution.
    pooled_gen, pooled_pipe, pooled_records = [], [], []
    pooled_prompt_tok, pooled_gen_tok = [], []
    for r in runs:
        path = os.path.join(out_dir, r["samples_file"])
        with open(path) as fh:
            for line in fh:
                rec = json.loads(line)
                if rec["phase"] != "steady":
                    continue
                pooled_gen.append(rec["generate_ms"])
                pooled_pipe.append(rec["pipeline_ms"])
                pooled_prompt_tok.append(rec["prompt_tokens"])
                pooled_gen_tok.append(rec["generated_tokens"])
                pooled_records.append({"expected": rec["expected"],
                                       "predicted": rec["predicted"],
                                       "status": rec["status"]})

    from test_model import score_binary
    pooled_quality = _quality(score_binary(pooled_records))
    pooled = summarize(pooled_gen, scope=TIMING_SCOPE_ID)

    def per_run(path):
        out = []
        for r in runs:
            node = r
            for key in path:
                node = (node or {}).get(key) if isinstance(node, dict) else None
            out.append(node)
        return out

    across = {stat: spread(per_run(["steady_state", "generate_ms", stat]))
              for stat in ("mean_ms", "p50_ms", "p95_ms", "p99_ms",
                           "min_ms", "max_ms", "stdev_ms")}

    # Per-run quality must agree; a disagreement under greedy decoding would be
    # a finding, so it is checked rather than assumed.
    q_sets = {json.dumps(r["quality"]["confusion_matrix"], sort_keys=True) for r in runs}

    metrics = {
        "steady_generate_mean_ms": pooled.get("mean_ms"),
        "steady_generate_p50_ms": pooled.get("p50_ms"),
        "steady_generate_p95_ms": pooled.get("p95_ms"),
        "steady_generate_p99_ms": pooled.get("p99_ms"),
        "steady_generate_min_ms": pooled.get("min_ms"),
        "steady_generate_max_ms": pooled.get("max_ms"),
        "steady_generate_stdev_ms": pooled.get("stdev_ms"),
        "steady_pipeline_p95_ms": summarize(pooled_pipe).get("p95_ms"),
        "first_inference_ms": statistics.median(
            [v for r in runs for v in r["first_inference"]["samples_ms"]]),
        "model_load_ms": statistics.median([r["model_load_ms"] for r in runs]),
        "peak_vram_allocated_mib": max(
            (r["memory"]["peak_during_steady_state"].get("max_allocated_mib") or 0)
            for r in runs) or None,
        "peak_vram_reserved_mib": max(
            (r["memory"]["peak_during_steady_state"].get("max_reserved_mib") or 0)
            for r in runs) or None,
        "quality_attack_detection_rate": pooled_quality["attack_detection_rate"],
        "quality_false_positive_rate": pooled_quality["false_positive_rate"],
        "quality_false_negative_rate": pooled_quality["false_negative_rate"],
        "quality_invalid_output_rate": pooled_quality["invalid_output_rate"],
        "quality_accuracy": pooled_quality["accuracy"],
        "generated_tokens_mean": summarize(pooled_gen_tok, unit="tokens").get("mean_tokens"),
        "prompt_tokens_mean": summarize(pooled_prompt_tok, unit="tokens").get("mean_tokens"),
    }

    metric_aggregation = {
        "latency_family": ("pooled — every steady sample from every run in one "
                           "distribution, then the statistic"),
        "steady_pipeline_p95_ms": "pooled, same as the latency family",
        "first_inference_ms": "median of the per-run cold-start samples",
        "model_load_ms": "median of the per-run model-load times",
        "peak_vram_allocated_mib": "maximum over runs (worst observed peak)",
        "peak_vram_reserved_mib": "maximum over runs (worst observed peak)",
        "quality_family": ("computed once over the pooled records of all runs; "
                           "greedy decoding makes the per-run values identical, "
                           "which is checked and reported as "
                           "`quality_consistent_across_runs`"),
        "workload_family": "mean over the pooled steady samples",
        "per_run_alternative": ("`across_runs` carries each run's own statistic plus "
                                "min/median/max/mean/stdev and peak-to-peak range, "
                                "which is the run-to-run variation"),
    }

    env = environment or {}
    summary = {
        "summary_schema": "firewall-IA/benchmark-summary/1",
        "experiment_id": experiment_id,
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "runs_aggregated": [r["run_index"] for r in runs],
        "identity": _identity(experiment_id, protocol, runs, env),
        "primary_metric": {
            "name": "steady_generate_p95_ms",
            "value_ms": metrics["steady_generate_p95_ms"],
            "definition": ("P95 of steady-state generate() latency, pooled over "
                           "every run, nearest-rank"),
            "scope": TIMING_SCOPE_ID,
            "companions": ["steady_generate_p50_ms", "quality_attack_detection_rate",
                           "quality_false_positive_rate"],
            "not_a_gateway_number": ("model-side only. End-to-end gateway latency "
                                     "is Issue #18; the D36 objective is read from "
                                     "steady_pipeline_p95_ms."),
        },
        "metrics": metrics,
        "metric_directions": METRIC_DIRECTIONS,
        "metric_aggregation": metric_aggregation,
        "steady_state_pooled": {
            "generate_ms": pooled,
            "pipeline_ms": summarize(pooled_pipe,
                                     scope="prompt+tokenize+transfer+generate+decode+parse"),
            "n_requests": len(pooled_gen),
        },
        "across_runs": {
            "method": ("each run's own statistic, then min/median/max/mean/stdev "
                       "and peak-to-peak range across runs"),
            "generate_ms": across,
            "model_load_ms": spread([r["model_load_ms"] for r in runs]),
            "first_inference_ms": spread(
                [v for r in runs for v in r["first_inference"]["samples_ms"]]),
        },
        "excluded_populations": {
            "policy": ("first_inference and warmup are excluded from every "
                       "steady-state statistic above; they are reported here and "
                       "in each run file. Nothing was discarded."),
            "first_inference_ms": [v for r in runs
                                   for v in r["first_inference"]["samples_ms"]],
            "warmup_ms": [v for r in runs for v in r["warmup"]["samples_ms"]],
            "model_load_ms": [r["model_load_ms"] for r in runs],
        },
        "quality": pooled_quality,
        "quality_consistent_across_runs": len(q_sets) == 1,
        "per_run": [{
            "run_index": r["run_index"],
            "started_utc": r["started_utc"],
            "model_load_ms": r["model_load_ms"],
            "first_inference_ms": r["first_inference"]["samples_ms"],
            "warmup_ms": r["warmup"]["samples_ms"],
            "steady_generate_ms": r["steady_state"]["generate_ms"],
            "quality": {k: r["quality"][k] for k in
                        ("attack_detection_rate", "false_positives", "false_negatives",
                         "invalid_outputs", "accuracy", "confusion_matrix")},
            "peak_vram": r["memory"]["peak_during_steady_state"],
            "conditions_before_gpu": (r["conditions_before"].get("gpu") or [None])[0],
            "conditions_after_gpu": (r["conditions_after"].get("gpu") or [None])[0],
        } for r in runs],
        "protocol": protocol,
        "environment": env,
    }
    _write_json(os.path.join(out_dir, "summary.json"), summary)
    return summary


def _identity(experiment_id, protocol, runs, env):
    """The block a comparison must agree on before two reports mean anything
    next to each other. Units alone are not identity."""
    model = (env.get("model") or {})
    py = (env.get("python") or {})
    gpu = (env.get("gpu") or {})
    dev0 = (gpu.get("devices") or [{}])[0]
    placement = runs[0].get("model_placement") or {}
    return {
        "experiment_id": experiment_id,
        "protocol_version": protocol.get("protocol_version"),
        "timing_scope_id": TIMING_SCOPE_ID,
        "measurement_unit": "milliseconds",
        "dataset_sha256": (protocol.get("dataset") or {}).get("sha256"),
        "dataset_path": (protocol.get("dataset") or {}).get("path"),
        "n_requests_per_run": (protocol.get("selection") or {}).get("n_requests_per_run"),
        "reduced_set": (protocol.get("selection") or {}).get("reduced_set"),
        "selection_policy": (protocol.get("selection") or {}).get("policy"),
        "request_order": (protocol.get("selection") or {}).get("order"),
        "seed": (protocol.get("selection") or {}).get("seed"),
        "runs": len(runs),
        "batch_size": BATCH_SIZE,
        "concurrency": CONCURRENCY,
        "device": runs[0].get("device"),
        "model_base_repo": model.get("base_model_repo"),
        "model_base_revision": model.get("base_model_revision"),
        "adapter_sha256": (model.get("adapter_file_sha256") or {}).get(
            "adapter_model.safetensors"),
        "quantization": placement.get("quantization_effective"),
        "parameter_devices": placement.get("parameter_devices"),
        "gpu_name": dev0.get("name"),
        "gpu_vram_mib": dev0.get("vram_total_mib"),
        "nvidia_driver_version": gpu.get("driver_version"),
        "driver_max_cuda_version": gpu.get("driver_max_cuda_version"),
        "torch_cuda_runtime": py.get("torch_cuda_runtime"),
        "torch_version": (py.get("packages_installed") or {}).get("torch"),
        "transformers_version": (py.get("packages_installed") or {}).get("transformers"),
        "peft_version": (py.get("packages_installed") or {}).get("peft"),
        "bitsandbytes_version": (py.get("packages_installed") or {}).get("bitsandbytes"),
        "python_version": py.get("version"),
        "os": (env.get("os") or {}).get("distribution"),
        "kernel": (env.get("os") or {}).get("kernel_release"),
        "cpu": (env.get("cpu") or {}).get("model"),
        "git_commit": (env.get("code") or {}).get("git_commit"),
        "working_tree_clean": (env.get("code") or {}).get("working_tree_clean"),
        "working_tree_diff_sha256": (env.get("code") or {}).get("working_tree_diff_sha256"),
    }


# ── Orchestration ──────────────────────────────────────────────────────────
def run_protocol(args):
    """Spawn N fresh processes, one per run, then aggregate."""
    out_dir = args.out_dir
    summary_path = os.path.join(out_dir, "summary.json")
    if os.path.exists(summary_path) and not args.allow_overwrite:
        raise SystemExit(
            f"FATAL: {args.experiment} already has results at {summary_path}.\n"
            f"A published experiment id is a fixed reference and is not "
            f"overwritten. Use a new --experiment id for a new measurement, or "
            f"--allow-overwrite if you really mean to replace this one.")
    os.makedirs(out_dir, exist_ok=True)

    import inference_core as core
    env = envmod.capture(args.experiment, args.adapter, core.BASE_MODEL)
    _write_json(os.path.join(out_dir, "environment.json"), env)

    rows, dataset_meta = load_dataset(args.dataset, args.manifest)
    protocol = build_protocol(args.experiment, dataset_meta, rows, args.limit, args.note)
    _write_json(os.path.join(out_dir, "protocol.json"), protocol)

    n = protocol["selection"]["n_requests_per_run"]
    est = estimate_duration(n, args.runs, args.per_request_ms)
    print(_format_estimate(est), flush=True)

    for i in range(1, args.runs + 1):
        print(f"\n=== run {i}/{args.runs} — fresh process ===", flush=True)
        cmd = [sys.executable, os.path.abspath(__file__), "run",
               "--experiment", args.experiment, "--run-index", str(i),
               "--out-dir", out_dir, "--adapter", args.adapter,
               "--dataset", args.dataset, "--manifest", args.manifest,
               "--limit", str(args.limit), "--progress", str(args.progress)]
        if args.note:
            cmd += ["--note", args.note]
        r = subprocess.run(cmd, cwd=REPO_ROOT)
        if r.returncode != 0:
            raise SystemExit(f"FATAL: run {i} exited {r.returncode}; not aggregating "
                             f"a partial protocol.")

    summary = summarize_experiment(args.experiment, out_dir, env)
    print_summary(summary)
    return 0


def estimate_duration(n_requests, runs, per_request_ms):
    total_gen_s = n_requests * runs * per_request_ms / 1000.0
    load_s = runs * 5.0          # observed order of magnitude for load + warm-up
    return {
        "n_requests_per_run": n_requests,
        "runs": runs,
        "assumed_per_request_ms": per_request_ms,
        "estimated_seconds": total_gen_s + load_s,
        "estimated_minutes": (total_gen_s + load_s) / 60.0,
        "estimated_minutes_per_run": (n_requests * per_request_ms / 1000.0 + 5) / 60.0,
        "basis": ("assumed per-request generate() latency x requests x runs, plus "
                  "~5 s per run for model load and warm-up"),
    }


def _format_estimate(est):
    return (f"\nESTIMATED DURATION\n"
            f"  {est['n_requests_per_run']} requests x {est['runs']} runs "
            f"@ ~{est['assumed_per_request_ms']:.0f} ms\n"
            f"  ~{est['estimated_minutes_per_run']:.1f} min per run, "
            f"~{est['estimated_minutes']:.1f} min total\n"
            f"  ({est['basis']})\n")


def print_summary(s):
    m, ident = s["metrics"], s["identity"]
    line = "=" * 78
    print(f"\n{line}\nBENCHMARK SUMMARY — {s['experiment_id']}\n{line}")
    print(f"scope        {TIMING_SCOPE_ID}")
    print(f"             model-side generate() only — NOT API, NOT gateway latency")
    print(f"dataset      {ident['n_requests_per_run']} requests/run x "
          f"{ident['runs']} runs   sha256 {str(ident['dataset_sha256'])[:16]}...")
    print(f"device       {ident['device']} — {ident['gpu_name']}")
    print(f"\nSTEADY STATE (pooled, n={s['steady_state_pooled']['n_requests']})")
    for k in ("mean_ms", "p50_ms", "p95_ms", "p99_ms", "min_ms", "max_ms", "stdev_ms"):
        print(f"  {k:<12} {s['steady_state_pooled']['generate_ms'][k]:>10.2f}")
    print(f"\nEXCLUDED FROM THE ABOVE (reported, not discarded)")
    print(f"  model load       {[round(v, 1) for v in s['excluded_populations']['model_load_ms']]} ms")
    print(f"  first inference  {[round(v, 1) for v in s['excluded_populations']['first_inference_ms']]} ms")
    print(f"  warm-up          {[round(v, 1) for v in s['excluded_populations']['warmup_ms']]} ms")
    p95 = s["across_runs"]["generate_ms"]["p95_ms"]
    print(f"\nRUN-TO-RUN VARIATION (P95 per run)")
    print(f"  values {[round(v, 2) for v in p95['values']]}  range {p95['range']:.2f} ms "
          f"({p95['spread_pct']:.2f}% of mean)")
    q = s["quality"]
    print(f"\nQUALITY AT THIS LATENCY (E5, n={q['support']})")
    print(f"  attack detection {q['attack_detection_rate'] * 100:.2f}%   "
          f"FP {q['false_positives']}   FN {q['false_negatives']}   "
          f"invalid {q['invalid_outputs']}")
    print(f"\nPRIMARY  steady-state generate P95 = {m['steady_generate_p95_ms']:.2f} ms "
          f"(P50 {m['steady_generate_p50_ms']:.2f} ms)")
    print(line)


# ── Stopwatch verification ─────────────────────────────────────────────────
def verify_timing(args):
    """Quantify what the D31 synchronization changed, instead of asserting it.

    Runs the SAME requests under the pre-Issue-#9 unsynchronized timer and the
    current synchronized one, interleaved A/B/B/A so a drift in machine state
    cannot be mistaken for a methodology effect, and checks that the decoded
    output is identical through both code paths.

    A stopwatch correction is not a model improvement: this exists to show, with
    numbers, how much of any future difference it could account for.
    """
    import torch
    import inference_core as core

    rows, dataset_meta = load_dataset(args.dataset, args.manifest)
    n = args.limit or 40
    tok, mdl = core.load_model(args.adapter)
    device = core.resolve_device()

    def old_timer(req):
        """Exactly the pre-Issue-#9 instrumentation: no explicit synchronization."""
        inputs = tok(core.build_prompt(req), return_tensors="pt").to(device)
        t0 = time.perf_counter()
        with torch.no_grad():
            mdl.generate(**inputs, max_new_tokens=core.MAX_NEW_TOKENS,
                         do_sample=False, pad_token_id=tok.eos_token_id)
        return (time.perf_counter() - t0) * 1000

    for r in rows[:5]:                      # warm up; discarded
        core.classify_timed(tok, mdl, r["input"], device)

    old, new = [], []
    for i, r in enumerate(rows[5:5 + n]):
        req = r["input"]
        if i % 2 == 0:
            old.append(old_timer(req))
            new.append(core.classify_timed(tok, mdl, req, device)[1]["generate_ms"])
        else:
            new.append(core.classify_timed(tok, mdl, req, device)[1]["generate_ms"])
            old.append(old_timer(req))

    same = all(core.classify_raw(tok, mdl, rows[i]["input"], device)[0]
               == core.classify_timed(tok, mdl, rows[i]["input"], device)[0]
               for i in range(5))
    o, w = summarize(old), summarize(new)
    delta = w["mean_ms"] - o["mean_ms"]
    doc = {
        "verification_schema": "firewall-IA/timing-method-ab/1",
        "run_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "question": ("Does bracketing generate() with device synchronization "
                     "change the measured latency on this machine?"),
        "method": ("Same requests, same process, interleaved A/B/B/A, "
                   f"n={n} per arm, {args.limit and 'limited' or 'default'} "
                   "selection from the head of the verified eval split. "
                   "Warm-up discarded."),
        "device": device,
        "dataset_sha256": dataset_meta["sha256"],
        "arm_unsynchronized": {"scope_id": HISTORICAL_TIMING_SCOPE, **o},
        "arm_synchronized": {"scope_id": TIMING_SCOPE_ID, **w},
        "mean_delta_ms": delta,
        "mean_delta_pct": 100.0 * delta / o["mean_ms"] if o["mean_ms"] else None,
        "decoded_output_identical_through_both_paths": same,
        "interpretation": (
            "HuggingFace generate() already synchronizes on every decoding step "
            "when it evaluates stopping criteria, so the older timer was in "
            "practice already measuring completed work. The synchronization is "
            "kept as a guarantee that holds under any future backend, not "
            "because it moves the number. It is a stopwatch correction, never a "
            "model improvement."),
    }
    out = args.out_dir or os.path.join(BENCH_ROOT, args.experiment or "adhoc")
    path = os.path.join(out, "timing_method_ab.json")
    _write_json(path, doc)
    print(f"\nunsynchronized  mean {o['mean_ms']:8.2f} ms   P50 {o['p50_ms']:8.2f} ms")
    print(f"synchronized    mean {w['mean_ms']:8.2f} ms   P50 {w['p50_ms']:8.2f} ms")
    print(f"delta           {delta:+8.3f} ms   ({doc['mean_delta_pct']:+.3f}%)")
    print(f"identical decoded output through both paths: {same}")
    print(f"-> {path}")
    return 0


# ── Smoke / estimate / self-test ───────────────────────────────────────────
def smoke(args):
    """Small functional check of the instrumentation. NOT a measurement.

    Verifies the harness end to end on a handful of real requests so a defect
    is found in seconds rather than an hour into the real protocol.
    """
    print("SMOKE RUN — functional check of the instrumentation, NOT a benchmark.\n"
          "Its numbers are not a performance result and are written to a "
          "throwaway experiment id.\n")
    args.experiment = args.experiment or "smoke-throwaway"
    args.out_dir = args.out_dir or os.path.join(BENCH_ROOT, args.experiment)
    args.run_index = 1
    args.limit = args.limit or 20
    rc = execute_run(args)
    if rc == 0:
        summarize_experiment(args.experiment, args.out_dir)
        print("\nSmoke run OK. These numbers are NOT a benchmark result.")
    return rc


def self_test(args):
    """Verify the statistics and phase separation without loading a model."""
    print("SELF-TEST — statistics and protocol structure, no model loaded.")
    s = summarize([10, 20, 30, 40, 50])
    assert s["count"] == 5 and s["p50_ms"] == 30 and s["min_ms"] == 10, s
    assert summarize([])["count"] == 0
    sp = spread([100.0, 110.0, 105.0])
    assert sp["range"] == 10.0 and sp["max"] == 110.0, sp
    first, warm = select_warmup(6206)
    assert len(first) == N_FIRST_INFERENCE and len(warm) == N_WARMUP
    assert not (set(first) & set(warm)), "warm-up sets must not overlap"
    assert select_warmup(6206) == (first, warm), "selection must be deterministic"
    print(f"  percentile method  {PERCENTILE_METHOD}")
    print(f"  timing scope       {TIMING_SCOPE_ID}")
    print(f"  cold-start rows    {first}")
    print(f"  warm-up rows       {warm}")
    print("SELF-TEST OK — this verifies the instrumentation, not performance.")
    return 0


def estimate_only(args):
    rows, meta = load_dataset(args.dataset, args.manifest)
    n = min(args.limit, len(rows)) if args.limit else len(rows)
    print(_format_estimate(estimate_duration(n, args.runs, args.per_request_ms)))
    print(f"dataset verified against manifest: {meta['sha256']}")
    return 0


def _write_json(path, doc):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w") as f:
        json.dump(doc, f, indent=2)


# ── CLI ────────────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(
        description="firewall-IA controlled V4 model-side inference benchmark (Issue #9)")
    ap.add_argument("command",
                    choices=["protocol", "run", "summarize", "smoke", "estimate",
                             "verify-timing", "self-test"],
                    help="protocol = full measurement (spawns one process per run); "
                         "run = a single run in this process; "
                         "summarize = re-aggregate existing runs; "
                         "smoke = small functional check; "
                         "estimate = duration only; "
                         "verify-timing = quantify the D31 synchronization; "
                         "self-test = no model needed")
    ap.add_argument("--experiment", default=None,
                    help="experiment id, e.g. baseline-local-v1")
    ap.add_argument("--out-dir", default=None)
    ap.add_argument("--adapter", default=None)
    ap.add_argument("--dataset", default=DEFAULT_DATASET)
    ap.add_argument("--manifest", default=DEFAULT_MANIFEST)
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--run-index", type=int, default=1)
    ap.add_argument("--limit", type=int, default=0,
                    help="measure only the first N requests — a REDUCED set, "
                         "recorded as such and not comparable to the full split")
    ap.add_argument("--progress", type=int, default=500,
                    help="print progress every N steady requests (0 = silent)")
    ap.add_argument("--per-request-ms", type=float, default=235.0,
                    help="assumed per-request latency for the duration estimate")
    ap.add_argument("--note", default=None)
    ap.add_argument("--allow-overwrite", action="store_true",
                    help="replace an existing experiment's results — off by "
                         "default so a published baseline cannot be clobbered")
    args = ap.parse_args()

    if args.command == "self-test":
        return self_test(args)
    if args.command == "estimate":
        return estimate_only(args)

    if args.adapter is None:
        import inference_core as core
        args.adapter = core.DEFAULT_ADAPTER_DIR
    if args.command not in ("smoke", "verify-timing"):
        if not args.experiment:
            raise SystemExit("FATAL: --experiment is required")
        args.out_dir = args.out_dir or os.path.join(BENCH_ROOT, args.experiment)
    elif args.experiment and not args.out_dir:
        args.out_dir = os.path.join(BENCH_ROOT, args.experiment)

    if args.command == "verify-timing":
        return verify_timing(args)
    if args.command == "summarize":
        print_summary(summarize_experiment(args.experiment, args.out_dir))
        return 0
    if args.command == "smoke":
        return smoke(args)
    if args.command == "run":
        return execute_run(args)
    return run_protocol(args)


if __name__ == "__main__":
    sys.exit(main())
