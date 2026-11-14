# HANDOFF → Codex — flag-acquisition-2026-11-14 / run-1

**Subsequent review:** [AUDIT_CORRECTIONS.md](AUDIT_CORRECTIONS.md) qualifies the historical
interpretation below. The combined 9/9 is six prevented flag retrievals and three prevented
credential disclosures; the fixed-credential An0nB0ard login returns its flag on every arm.

Claude delivered the campaign and its results only. **No staging, commit, push, PR or merge
was done.** Codex owns repo consolidation, general README/CONTEXT updates and the single PR.

## Conclusion

Against the three real HTTP exploits (CatP1cs path traversal, An0nB0ard SQLi credential
disclosure, Inf3ct header SSTI), the candidate `fastv5-public-v3-headerguard-v2-20261111`
(`fastv5_guard`) prevented **9/9** flag/credential acquisitions over 3 reps each:

- V5.1 blocks the traversal and the SQLi credential read (target‑visible attacks).
- The `request-header-sink-guard/v2` blocks the header SSTI **before any V5 call** — a
  deterministic guard, not a model detection.
- `v5only`, `fastv5` and **CRS** each prevent only **6/9**: none stops the header SSTI
  (PERSISTED). This is the sole differentiator and the reason the guard exists.
- D33pTh0ught `answer=42` (legitimate flag) is correctly allowed on every arm; the An0nB0ard
  benign admin login is correctly allowed on every arm.
- ObC00ki3s has no HTTP‑acquirable flag (client‑side only); the Fast Path additionally
  **rescues** the `cks.js` benign over‑block that `v5only` still shows (FP 2→0).
- ag3ncy flag not retrieved (correct password undetermined within the pre‑declared budget).
- Candidate is Model2‑free everywhere (`model2_present:false`, `mode:FAST_PATH_V5`,
  0 unexpected Model2 rows across 156 firewall rows), 0 new benign damage, 0 new harmful
  delivery, audit rate 0. All 30 stacks `clean:true`; GPU released.

## New public files (this directory, `reports/v5/flag-acquisition-2026-11-14/run-1/`)

| File | Purpose |
|---|---|
| `PROTOCOL.md` | objectives, fixed budget, Phase‑1 flag audit, sequences, oracles, arms, reps |
| `RESULTS.md` | professor‑facing explanation + main table + per‑arm prevention |
| `METRICS.json` | machine‑readable per‑app/per‑arm outcomes and summary |
| `metrics_table.csv` | the main table |
| `EVIDENCE_INDEX.json` | private raw paths, ids and SHA‑256 of every run |
| `CLEANUP_GPU.json` | cleanup + GPU‑release evidence |
| `HANDOFF_CODEX.md` | this file |

No private keys or non‑lab credentials are in the public material (the flags are lab
fixtures / the D33p flag is the `answer=42` decrypt; `password123` is the An0nB0ard DB seed).

## Private evidence (outside Git, per convention)

Root: `/home/sebas/Documents/Codex/2026-11-02/fwlab-architecture-private/2026-11-14/`

- `cases/<App>.cases.jsonl` — sealed raw cases (hashes in each `runs/<App>/seal/SEAL.json`).
- `runs/<App>/{direct,seal,v5only,fastv5,fastv5_guard,crs}/` — `ROWS.jsonl`, `SUMMARY.json`,
  `CLEAN.json`, plus `SCORE.json` per app. `EVIDENCE_INDEX.json` carries their SHA‑256.
- `gen_cases.py`, `assemble.py`, `run_matrix.sh` — reproducible generator / scorer‑aggregator /
  driver. `work/` holds per‑run private stack logs.

## Reproduce (from repo root `/home/sebas/Desktop/firewall-IA`)

```bash
PRIV=/home/sebas/Documents/Codex/2026-11-02/fwlab-architecture-private/2026-11-14
PY=.venv-dataplane/bin/python
# 1. regenerate + validate cases
$PY -I "$PRIV/gen_cases.py" "$PRIV/cases"
# 2. per app: direct draft (double) -> seal -> 4 firewall arms (real V5.1) -> covered by run_matrix.sh
#    direct example:
$PY -B scripts/local_stack/challenges/trial.py run --app CatP1cs --arm direct \
   --cases "$PRIV/cases/CatP1cs.cases.jsonl" --transport h1_tls_new --v5 double \
   --out "$PRIV/runs/CatP1cs/direct" --work "$PRIV/work/CatP1cs.direct"
$PY -B scripts/local_stack/challenges/trial.py seal --app CatP1cs \
   --cases "$PRIV/cases/CatP1cs.cases.jsonl" --direct-rows "$PRIV/runs/CatP1cs/direct/ROWS.jsonl" \
   --population L2_SCRIPTED_LAB --out "$PRIV/runs/CatP1cs/seal"
#    firewall arms for the 5 remaining apps:
bash "$PRIV/work/run_matrix.sh"
# 3. score + assemble public deliverables
$PY -I "$PRIV/assemble.py"
```

Model arms use `--v5 real --handoff-gpu`; `crs` uses `--v5 real` (no GPU). Transport
`h1_tls_new`.

## Limits / caveats to carry in the write-up

- **Transport: `h1_tls_new` only.** run-1 is single‑transport by design. No HTTP/2 subset is
  part of run-1, and the 13 November campaign's separate h2 subset is not attributed to this
  campaign. (During the measurement session an Inf3ct h2 check was explored; its raw rows live
  privately at `runs/Inf3ct/h2/` and are **deliberately excluded** from run-1's cases, seal,
  metrics and evidence index — they are not part of this deliverable. A scored h2 confirmation
  would require its own declared run.)
- ag3ncy admin branch unmeasured (password unknown); ObC00ki3s flag is out of scope for a
  network firewall (client‑side).
- The three exploit flags are lab placeholders; the result is about the *retrieval mechanism*,
  with the full flag string oracle‑verified, not a unique secret.
- Prevention is attributed by stage; CRS blocks are CRS, guard blocks are `request_guard`,
  model blocks are V5 — never conflated.

## No runtime defect observed

The frozen candidate behaved as specified on every app; no runtime defect to report. Nothing
in the candidate (weights, decoder, representation, policies, frozen sources) was modified.
