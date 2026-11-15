# Hybrid shadow Analyzer — separate-process runtime

**Status: PROPOSED for D52. Not ratified.** Nothing here is a decision of the owner, and
nothing here changes enforcement: V4, through `/classify`, is the only decision (D43, D4/D25/D34).
The shadow Analyzer is **off by default** and **observe-only**: it has no ALLOW path, no
threshold, no Model 2, no fast path.

## What it is

```
mitmdump + data_plane.py (data plane venv, stdlib only)         worker (analyzer venv: numpy, scikit-learn)
  V4 verdict enforced (unchanged)                                 hybrid_shadow_worker.py
  after the verdict, a background task:                           1. read artifact once, SHA-256 vs frozen evidence
    extract_features(D1 text)  --- 1 JSON line, stdin ---->       2. only then import numpy/sklearn, unpickle
    <-------------------------- 1 JSON line, stdout ------        3. feature-contract check, handshake "ready"
  re-validate (D50) -> "HYBRID SHADOW" log line, same [tag]       analyze_strict(features) per request
```

Files: `data_plane/hybrid_shadow.py` (statuses, result, strict inference, verified loader, the
in-process runner kept for tests/injected providers), `data_plane/hybrid_shadow_process.py`
(runner + IPC protocol), `data_plane/hybrid_shadow_worker.py` (the worker),
`data_plane/hybrid_boundary.py` (Model 2 / fallback boundary, **unimplemented**).

Why a process: D33 keeps numpy/scikit-learn out of the data plane environment, and the in-process
thread runtime measurably stalled the gateway's event loop (see *Measured* below).

## Analyzer environment and artifact procedure

```bash
# once; versions pinned in requirements-analyzer-research.txt (Python 3.12)
uv venv --python 3.12 --seed .venv-analyzer
.venv-analyzer/bin/python -m pip install -r requirements-analyzer-research.txt
```

The artifact `model-output-hybrid-analyzer-v2/recommended.pkl` is gitignored (D55) and is
**produced by the Phase 2B run-002 pipeline**, not by this feature. Its identity is the
SHA-256 in `reports/hybrid/phase2b-analyzer-v2-run-002/frozen_selection.json`
(`recommended.sha256`, `79eb7265…`). To check an artifact and an environment without the gateway:

```bash
.venv-analyzer/bin/python -I data_plane/hybrid_shadow_worker.py \
    --artifact model-output-hybrid-analyzer-v2/recommended.pkl < /dev/null
# {"ready":true,...}  exit 0     or     {"ready":false,"detail":"<reason>"}  exit 2
```

**Integrity before loading.** The worker reads the artifact **once**, hashes those bytes against
the frozen evidence, and unpickles *those same bytes* (a file swapped after the check is never
used). A different file is refused with `artifact_hash_mismatch` and never reaches `pickle`.
Only then are the ML dependencies imported (`dependencies_missing` if absent), the pickle's
class and version checked (`load_failed`), and the encoders' fields compared with the current
extractor (`feature_contract_mismatch`). Each of these is a deterministic start-up failure: the
runtime does not retry it.

## Configuration (`config.yaml`, `data_plane.shadow_analyzer`, absent = off)

Every key is required when `enabled: true`; none has a default. See the commented block in
`config.yaml`. `runtime` must be `process`. `timeout_seconds` bounds one analysis;
`startup_timeout_seconds` bounds worker start; `restart_backoff_seconds` is the minimum wait before
replacing a dead worker; `max_consecutive_failures` ends retrying until the gateway restarts.
The values in the commented example are illustrative, not chosen or measured defaults.

## Outcomes (all explicit, in the `HYBRID SHADOW` line)

| status | meaning |
|---|---|
| `OK` | answer received and re-validated here against the D50 contract; carries `attack`, auxiliary `category`, `analyze=` (worker's own time), `overhead=` (everything else), `elapsed=` |
| `UNAVAILABLE` | no usable worker: `worker_starting`, `worker_restarting`, `worker_spawn_failed`, `worker_startup_timeout`, `worker_protocol_error`, `worker_disabled`, or an artifact/environment reason (`artifact_missing`, `artifact_hash_mismatch`, `dependencies_missing`, `load_failed`, `feature_contract_mismatch`, …) |
| `BUSY` | one analysis already in flight; **no queue**, the request is not analysed |
| `INVALID_OUTPUT` | the answer violates the contract, contains NaN/Infinity, or breaks the protocol (`ipc_*`) |
| `FAILED` | the worker raised, or exited (`worker_exited:rc=N`) |
| `TIMEOUT` | no answer in `timeout_seconds` **and the worker was killed (SIGKILL) and reaped** (`detail=worker_killed`) |

A failure never carries a score. `v4=` in the same line is V4's outcome (`FAIL_CLOSED` is a
fail-closed BLOCK, not a model BLOCK); the line shares the request's `[tag]`.

## Hung or dead worker

* **Timeout:** the worker is SIGKILLed, awaited (reaped), its pipe closed; only then is `TIMEOUT`
  reported. The PID is gone (tested for both the stand-in and the real worker).
* **Crash / exit / protocol violation / over-long line / wrong id:** same cleanup, then
  `FAILED` or `INVALID_OUTPUT`; a desynchronised worker is never reused.
* **Replacement:** started in the background by the *next* request after `restart_backoff_seconds`;
  requests meanwhile are `UNAVAILABLE`. A healthy answer resets the failure count. After
  `max_consecutive_failures` consecutive failures: `UNAVAILABLE(worker_disabled)` until restart.
* **Gateway shutdown:** `done()` SIGKILLs the worker; if the gateway dies, the worker reads EOF
  on stdin and exits.
* **Not claimed:** no memory/CPU rlimit on the worker; only the worker PID is killed.

## The NaN-to-zero defect

`scripts/training/hybrid_analyzer.py:453` builds the attack signal as `min(1.0, max(0.0, attack))`.
`max(0.0, nan)` is `0.0`, so a NaN from the model reached the D50 contract as a valid
`attack = 0.0` (a finite out-of-range value was clamped just as silently). That frozen file is **not
modified.** `hybrid_shadow.analyze_strict` (guard `nonfinite-reject/strict-v1`, named in the worker
handshake) runs the same frozen encoders and models and rejects, **before** clamping, a
non-finite `attack` or category probability and an `attack` outside [0, 1] by more than 1e-6,
as `INVALID_OUTPUT`. It is bit-identical to `AnalyzerModel.analyze` on 304 requests with the real
artifact (test). `tests/test_hybrid_shadow.py` also pins the unmodified defect
(`test_the_frozen_analyze_masks_nan_as_a_valid_zero`). The wire refuses NaN/Infinity both ways
(`allow_nan=False`, `parse_constant`).

An isolated patch that would make the frozen `AnalyzerModel.analyze` itself reject
(`analyzer-nonfinite-guard-PROPOSED.patch`, in the session notes folder) is **not applied**.

## Measured (2026-10-20, this machine, Python 3.12.15, 3,000 V4 eval requests)

Not an end-to-end gateway measurement, and **not** evidence about the D36 P95 ≤ 200 ms target.

| | mean | p95 | p99 | max |
|---|---|---|---|---|
| worker's own analysis (`analyze_ms`), 1 OpenMP thread | 8.36 ms | 8.74 | 9.52 | 24.0 |
| scheduling + IPC + serialisation (`overhead_ms`), real worker | 0.26 ms | 0.42 | 0.50 | 1.46 |
| same overhead against an instant stand-in worker (floor) | 0.07 ms | 0.09 | 0.17 | 0.38 |
| gateway request hook, shadow off → on (mock classifier) | 0.120 → 0.189 ms | 0.175 → 0.272 | 0.191 → 0.321 | |
| parent event-loop lag during runs, process runtime | 0.16 ms | 0.87 | 1.05 | 4.1 |
| same, idle loop with no worker (baseline) | 0.10 ms | 0.22 | 0.26 | 0.48 |
| same, previous in-process thread runtime | — | 3.3–6.3 | 7.0–9.0 | 12.5–13.6 |

## D52 — proposed wording (for the owner)

> The Lightweight Request Analyzer runs, in shadow mode only, in a separate worker process under
> the analyzer environment's own interpreter (D33 unchanged: nothing is installed in the data plane
> environment). The data plane sends the extracted features over a bounded pipe, verifies the
> artifact's SHA-256 against the frozen evidence before it is unpickled, bounds each analysis, kills
> and replaces a worker that exceeds the bound, and records every outcome as an explicit status.
> This decides where the Analyzer *runs*; it does not authorise any stage to take or influence an
> enforcement decision (D43/D29 stand).

Decisions this proposal needs from the owner, none taken here: (1) ratify or reject the
separate-process runtime as D52; (2) whether the frozen `AnalyzerModel.analyze` may receive the
non-finite guard (patch) or `analyze_strict` stays the only guarded path; (3) the operational
values for the four bounds above; (4) how the analyzer interpreter and artifact are provisioned
where the gateway runs (Docker Lab, `compose.yaml`, are untouched).
