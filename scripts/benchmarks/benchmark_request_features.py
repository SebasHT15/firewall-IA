"""
firewall-IA — request feature extraction overhead (Hybrid Architecture Phase 1, Issue #49).

Times `request_features.extract_features()` in-process, one call at a time:

  corpus  the D1 texts of `datasets/v4_clean/eval.jsonl` (only the `input` field
          is read, never the label), verified against the dataset manifest,
          `--runs` passes in file order after one warm-up pass reported apart;
  sizes   synthetic form bodies of 1 KiB to 1 MiB, to show how the cost grows
          with body size.

Scope: the extractor call alone (`perf_counter_ns` around it). Not
render_request, not logging, not the gateway. An observation of this machine, in
the environment it runs in production — not a D32 inference benchmark and not
comparable to `baseline-local-v1`. Statistics come from
`benchmark_inference.summarize()` (nearest-rank, no sample removed).

RUN (from the repository root, in the data plane environment):
    .venv-dataplane/bin/python scripts/benchmarks/benchmark_request_features.py \
        --out reports/hybrid/<experiment-id>/extractor_overhead.json
"""

import argparse
import hashlib
import json
import os
import platform
import sys
import time
from datetime import datetime, timezone

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO_ROOT, "data_plane"))
sys.path.insert(0, os.path.join(REPO_ROOT, "scripts", "benchmarks"))

import request_features  # noqa: E402
from benchmark_inference import summarize  # noqa: E402

EVAL_PATH = os.path.join(REPO_ROOT, "datasets", "v4_clean", "eval.jsonl")
MANIFEST_PATH = os.path.join(REPO_ROOT, "datasets", "manifest_v4_clean.json")
SIZES_BYTES = (1024, 10 * 1024, 100 * 1024, 1024 * 1024)


def time_calls(texts):
    """Extraction time of each text, in ms, one call at a time."""
    extract = request_features.extract_features
    samples = []
    for text in texts:
        t0 = time.perf_counter_ns()
        extract(text)
        samples.append((time.perf_counter_ns() - t0) / 1e6)
    return samples


def cpu_model():
    try:
        with open("/proc/cpuinfo", encoding="utf-8") as f:
            for line in f:
                if line.startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or None


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--runs", type=int, default=3, help="measured passes over the corpus")
    ap.add_argument("--size-reps", type=int, default=20, help="calls per synthetic body size")
    ap.add_argument("--out", help="write the JSON result here (refuses to overwrite)")
    args = ap.parse_args()
    if args.out and os.path.exists(args.out):
        raise SystemExit(f"FATAL: {args.out} exists; measurements are never overwritten")

    with open(EVAL_PATH, "rb") as f:
        raw = f.read()
    sha256 = hashlib.sha256(raw).hexdigest()
    with open(MANIFEST_PATH, encoding="utf-8") as f:
        expected = json.load(f)["artifact_sha256"]["eval"]
    if sha256 != expected:
        raise SystemExit(f"FATAL: {EVAL_PATH} SHA-256 {sha256} != manifest {expected}")
    texts = [json.loads(line)["input"] for line in raw.decode("utf-8").splitlines()]

    warmup = time_calls(texts)
    runs = [time_calls(texts) for _ in range(args.runs)]
    pooled = [s for run in runs for s in run]

    sizes = {}
    for size in SIZES_BYTES:
        body = ("a=1&b=2&" * (size // 8 + 1))[:size]
        text = ("POST /submit HTTP/1.1\nContent-Type: application/x-www-form-urlencoded"
                "\n\n" + body)
        request_features.extract_features(text)  # warm-up, not recorded
        sizes[str(size)] = summarize(time_calls([text] * args.size_reps), scope="extractor-call")

    result = {
        "what": "request_features.extract_features() call time, in-process (Hybrid Architecture Phase 1)",
        "scope": "extractor call only: not render_request, not logging, not the gateway",
        "kind": "observation on this machine; not a D32 inference benchmark",
        "measured_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "feature_schema_version": request_features.FEATURE_SCHEMA_VERSION,
        "corpus": {"path": os.path.relpath(EVAL_PATH, REPO_ROOT), "sha256": sha256,
                   "matches_manifest": True, "texts": len(texts),
                   "fields_read": ["input"], "order": "file order"},
        "environment": {"python": platform.python_version(),
                        "executable": os.path.relpath(sys.executable, REPO_ROOT)
                        if sys.executable.startswith(REPO_ROOT) else sys.executable,
                        "platform": platform.platform(), "cpu": cpu_model()},
        "warmup_pass": summarize(warmup, scope="extractor-call"),
        "runs": [summarize(run, scope="extractor-call") for run in runs],
        "steady_pooled": summarize(pooled, scope="extractor-call"),
        "synthetic_form_body_by_size_bytes": sizes,
    }
    text = json.dumps(result, indent=2) + "\n"
    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "x", encoding="utf-8") as f:
            f.write(text)
    print(text, end="")


if __name__ == "__main__":
    main()
