# Data sources

What data the project uses, what this repository distributes, and how to reproduce the
current V4 dataset without redistributing third-party raw data. Written for the v0.1.0
stage close (2026-09-22).

**The v0.1.0 tree does not distribute** `csic_database.csv`, the historical root
`train.jsonl` or the historical root `eval.jsonl`. They were removed from tracking (not from
Git history) and are gitignored; copies kept locally are unaffected. The repository's MIT
License covers its original code and documentation only; every external dataset, corpus
and tool named here remains subject to its upstream terms. No download location or license
is asserted here for any of them.

---

## Files not distributed by v0.1.0

| File (expected location) | Bytes | Rows | SHA-256 | Role | Status |
|---|---:|---:|---|---|---|
| `csic_database.csv` (repository root) | 29,539,583 | 61,065 + header | `c420f0bc0464376de75b6c419a0ac226fe69fe12c8ac4908843273721e44e637` | **source input** for regenerating V4 | not distributed — redistribution terms not confirmed |
| `train.jsonl` (repository root) | 36,460,219 | 79,305 | `94fc5e3a93d5a78d8272bc95a5932ae1b75c410701046a67b13283656bb06936` | historical, superseded corpus | not distributed; not required |
| `eval.jsonl` (repository root) | 9,092,901 | 19,827 | `2d01fd0266ffb15a148d17af4275af1efd69ca932388dbb50a7bb19d92f6f8da` | historical, superseded corpus | not distributed; not required |

The same hashes are recorded in the committed E0 reports, which are unchanged:
`reports/e0_dataset_integrity_v4_clean.txt` (CSV) and
`reports/e0_dataset_integrity_current.txt` (all three).

### `csic_database.csv`

- Derived from the **CSIC 2010 HTTP dataset** (Spanish National Research Council). The file
  used here is a tabular CSV (61,065 rows × 17 columns, beginning
  `,Method,User-Agent,Pragma,Cache-Control,...` and including `classification` and `URL`).
  Which distribution of the dataset this copy was obtained from is not recorded in the
  repository; the SHA-256 identifies the exact copy used.
- **Required by `scripts/dataset/parse_dataset_v4.py`**, which reads it from the repository
  root (`CSIC_PATH`) to build the CSIC-derived ALLOW and BLOCK rows of V4. Without it,
  regeneration stops with `FileNotFoundError`.
- To reproduce V4 byte-for-byte, place a copy obtained under its own terms at the
  repository root and verify:

  ```bash
  sha256sum csic_database.csv
  ```

  The expected value is the one in the table above.
- Not required by the control plane, the data plane, the Docker demo, the smoke test,
  External Test v1 verification or any unit test.

### Historical `train.jsonl` / `eval.jsonl`

- The superseded pre-V4 corpus (99,132 rows), written by the historical generator
  `scripts/dataset/parse_dataset.py`. It is kept in the record only because the E0 audit
  that rejected it — 26.65% train→eval leakage, a `Host`-only shortcut at 93.72%, 9
  deterministic label reveals — is part of the project's history
  (`reports/e0_dataset_integrity_current.txt`).
- It contains rows derived from CSIC 2010 and from PayloadsAllTheThings.
- **Not required** by the current V4 runtime, the demo, External Test v1 or any test.
  Training, evaluation and the benchmark read `datasets/v4_clean/`, and
  `scripts/dataset/check_dataset.py` now defaults to `datasets/v4_clean/` as well.
- The historical generator is recorded as non-deterministic, so these files cannot be
  regenerated bit-identically; the hashes above identify the copies that were audited.

---

## Reproducing the current V4 dataset

`datasets/v4_clean/train.jsonl` and `eval.jsonl` are not tracked either. Their identity is
pinned in [`../datasets/manifest_v4_clean.json`](../datasets/manifest_v4_clean.json):
train `4459f6861629279395acc57f99173d82bbda4dc8205a5f3bd08750dd528d262b`, eval
`61f15591203609b4c583773184cd25edd6d1adc5f86959e009cfd47f6d370859`. Regeneration is
deterministic (verified bit-identical under four `PYTHONHASHSEED` values) and needs two
external inputs:

1. **PayloadsAllTheThings** — a separate clone at `~/PayloadsAllTheThings`
   (`PAYLOADS_REPO` in `parse_dataset_v4.py`), at the recorded commit **`e961fef`**
   (`e961fef231d8327bae83b563fab50aec2e6b77c0`, in the manifest). Not vendored in this
   repository; subject to its upstream terms.
2. **`csic_database.csv`** at the repository root, matching the SHA-256 above.

```bash
python3.12 scripts/dataset/parse_dataset_v4.py
```

```bash
sha256sum datasets/v4_clean/train.jsonl datasets/v4_clean/eval.jsonl
```

Then compare with the manifest and run the E0 gate
(`python3.12 scripts/dataset/check_dataset.py`), which must report WARNING with 0 blocking
failures.

The TinyLlama-1.1B-Chat base model and the V4 adapter (`model-output-v4-clean/`) are not
distributed either; see [`../docker/README.md`](../docker/README.md) for what the lab
expects locally.

---

## Third-party excerpts retained in committed reports

Kept unchanged as historical experimental evidence; they remain subject to their source's
terms, not to this repository's MIT License.

- **`reports/diagnostics/real-http-fp-v1/cases.jsonl`** — the EVALSWAP family reuses ten
  ALLOW rows of `datasets/v4_clean/eval.jsonl` as in-distribution contexts. Two of them are
  re-rendered CSIC 2010 requests: row 127 (`GET /publico/autenticar.jsp?...`, cases
  EVALSWAP-001 to -003) and row 597 (`GET /index.jsp`, cases EVALSWAP-007 to -009). They
  appear only in that file, whose SHA-256 is pinned in the experiment's `manifest.json`
  (`design.cases_file_sha256`), so the file is not edited.
- The same experiment's PATH family uses a CSIC-style path
  (`/miembros/imagenes/zarauz.jpg`); the file served under it in `www/` is a placeholder
  written for the experiment.
- Counts and statistics about the CSIC and PayloadsAllTheThings sources (manifests, E0 /
  E2-E3 reports) are measurements, not copies of the data.

External Test v1 was built from traffic captured in the project's own lab. Its
pre-registered CSIC-ancestry warning check was **not** executed (see the status note in
[`external_test_v1_protocol.md`](external_test_v1_protocol.md)), so no statement is made
here about CSIC-derived substrings in the frozen cases.

---

## Git history

Removing the three files from the v0.1.0 tree does not remove them from earlier commits
(`7a4411b` for the CSV; `1ebf812` and `ef8da2b` for the root JSONL files). History was not
rewritten; purging it would be a separate decision.
