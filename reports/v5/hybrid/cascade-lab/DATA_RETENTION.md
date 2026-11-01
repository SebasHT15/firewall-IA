# Cascade lab — data retention & reproduction

The cascade-lab dev trial is built from `eval.jsonl`, the **legacy, non-protected**
V4-era labeled set. Per `docs/data_sources.md`, `eval.jsonl` is derived from the
CSIC-2010 HTTP dataset and PayloadsAllTheThings; its **redistribution terms are not
confirmed**, so it is gitignored and not distributed by this repository. The lab
follows the same policy: material that carries verbatim third-party request content
is **kept locally only**, and reproduction is preserved here by hash + recipe, not by
publishing the excluded material.

## Not committed (verbatim third-party-derived content)

| File | SHA-256 | Bytes | Rows | Why excluded |
|---|---|---:|---:|---|
| `dev_sample_v1.jsonl` | `d29a4ccb6bc35fef2f0b74f84ca69010fa881425127924cf4703b8de0eefcbfe` | 211,822 | 600 | Each row's `wire` field is a verbatim HTTP request sampled from `eval.jsonl`, with a `source` index back into it. Legacy-eval derivative; redistribution terms unconfirmed. |

## Committed (no request payloads)

| File | SHA-256 | Bytes | Rows | Contents |
|---|---|---:|---:|---|
| `results/dev_paired_v1.jsonl` | `a4dd747c6a5456f8a4f209645dc13c882d6d27b802850fd38d271752a41eaa74` | 468,346 | 600 | Per-request **decisions, timings, framing, canonical outcome, Model 2 / V5 summaries, category label** — no `wire`, no canonical text, no payload. This is the record the metrics recomputation reads. |

The metrics summaries/CSVs (`results/metrics_v1/`, `results/metrics_v2/`), the
operational summaries (`results/operational_v1/`) and the run logs
(`run-logs/`, model outputs and progress only — no request payloads) are aggregates
or model-side evidence and are committed.

## Reproduce `dev_sample_v1.jsonl` locally

Deterministic under the recorded seed; requires a local copy of `eval.jsonl`
obtained under its own upstream terms (expected SHA-256
`2d01fd0266ffb15a148d17af4275af1efd69ca932388dbb50a7bb19d92f6f8da`, per
`docs/data_sources.md`) at the repository root:

```bash
.venv-dataplane/bin/python scripts/cascade_lab/make_dev_sample.py \
    --n 600 --seed 20261026 \
    --out reports/v5/hybrid/cascade-lab/dev_sample_v1.jsonl
sha256sum reports/v5/hybrid/cascade-lab/dev_sample_v1.jsonl   # expect d29a4ccb…
```

Then regenerate the paired pass and the metrics (see `ACCEPTANCE_REPORT.md` §8).
Keep all local copies; do not redistribute `dev_sample_v1.jsonl` or `eval.jsonl`.
