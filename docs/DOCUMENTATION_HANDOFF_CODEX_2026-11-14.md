# Documentation handoff → Codex — 2026-11-14

**Subsequent Codex review:** An0nB0ard's login credential was fixed before replay and its
login flag is returned on every arm. Read the
[audit corrections](../reports/v5/flag-acquisition-2026-11-14/run-1/AUDIT_CORRECTIONS.md)
before using the historical interpretation below. The 9/9 result is six prevented flag
retrievals plus three prevented credential disclosures. Existing H2 exploration is retained
and indexed separately; the documentation task prohibited new runs, not preservation of
measurements that already existed.

Prepared by Claude after delivering the 14 November flag-acquisition campaign. This pass is
**documentation only**. No staging, commit, push, PR, merge, issue change, new campaign, attack,
training, service, Docker or model run was performed. Reuse the current checkout and branch
(`feat/hybrid-cascade-integration`, HEAD `f61fa108aebe6e3431a32c36d0c3977b0a4f812a`).

## 1. Summary of what was completed

- Reconciled the flag campaign to **`h1_tls_new` only** (see §5) and verified its internal
  coherence against the retained private evidence.
- Incorporated the 14 November flag campaign into the live documentation (README, CONTEXT,
  project_status, index, challenge_apps, DECISIONS), as a **separate experiment** with its own
  denominators, never pooled with the 13 November architecture metrics.
- Preserved every scientific distinction required: V5 vs Fast Path vs deterministic guard vs CRS;
  effect-prevention (13 Nov) vs flag-prevention (14 Nov); exploitation vs legitimate retrieval;
  requests/sessions/techniques/repetitions; placeholder fixtures vs original secrets.
- Completed the issue-disposition matrix with explicit categories and per-issue reasons.
- Ran documentation-integrity checks (links, hashes, `git diff --check`, secret scan).

README.md, CONTEXT.md and DECISIONS.md were already rewritten by Codex earlier in the session;
the large HEAD→worktree delta on those files is mostly Codex's rewrite. Claude's edits are
**surgical additions** applied on top of Codex's current versions (exact-match edits, nothing
clobbered). The `docs/*` pages below appear untracked because Codex created them this session.

## 2. Files created or modified (this pass)

Documentation (tracked/untracked under the current worktree):

| File | Change |
| --- | --- |
| `README.md` | flag-campaign result section + Evidence link; replaced the "pending incorporation" line |
| `CONTEXT.md` | checkpoint + next-step reflect delivered/incorporated flag evidence |
| `DECISIONS.md` | new **D86** (flag campaign, evidence-scope record) + index line |
| `docs/project_status.md` | replaced "Flags … being completed" with the incorporated results + distinctions |
| `docs/index.md` | flag-campaign rows; "pending" wording removed |
| `docs/challenge_apps.md` | new "Flag-acquisition campaign (2026-11-14)" section; status line updated |
| `docs/issue_closure_2026-11-14.md` | categorised matrix (IV/RN/DS/FS/CP) + flag evidence for #24/#28; step 1 marked delivered |
| `docs/future_work.md` | header-aware representation reconfirmed by the flag campaign |
| `docs/DOCUMENTATION_HANDOFF_CODEX_2026-11-14.md` | this file |

Flag campaign deliverables (public, untracked, under
`reports/v5/flag-acquisition-2026-11-14/run-1/`), reconciled to h1-only this pass:

| File | Change |
| --- | --- |
| `METRICS.json`, `metrics_table.csv`, `EVIDENCE_INDEX.json` | regenerated h1-only (h2 subset removed) |
| `RESULTS.md` | h2 "Transport check" replaced by a "Transport scope" note (h1 only) |
| `HANDOFF_CODEX.md` | transport note: h1 only; h2 exploration excluded and kept private |
| `CLEANUP_GPU.json` | h1-only (30 runs); excluded-h2 note |
| `PROTOCOL.md` | unchanged (already h1 only) |

Private raw evidence stays outside Git under
`/home/sebas/Documents/Codex/2026-11-02/fwlab-architecture-private/2026-11-14/`
(`cases/`, `runs/`, `gen_cases.py`, `assemble.py`, `run_matrix.sh`, `work/`).

## 3. Results and limits incorporated

- 4/6 apps have an HTTP-retrievable flag; all four obtained on `direct` (CatP1cs traversal,
  An0nB0ard SQLi credential disclosure, Inf3ct header SSTI, D33pTh0ught legitimate `answer=42`),
  3/3 reps, full-string oracle-verified.
- Three exploit sequences × 3 reps = 9 acquisitions. Candidate `fastv5_guard` prevents **9/9**
  (V5 for traversal + SQLi; `request_guard` for header SSTI). `v5only`, `fastv5`, `crs` prevent
  **6/9** each — none stops the header SSTI. Guard block attributed to `request_guard`, not V5.
- Limits preserved: ObC00ki3s has no server-side flag (client-side only); ag3ncy's admin branch
  unmeasured (password undetermined within a fixed budget); the three exploit flags are the **same
  placeholder** (mechanism result, not three secrets); 9/9 is repeated sequences, not nine
  techniques or six exploited apps; the An0nB0ard benign login is correctly allowed on every arm.
- No Model 2 anywhere (`model2_present:false`); audit rate 0; 30/30 runs clean; GPU released.
- The 13 November findings are untouched and not overwritten: three benign FP, two persistent
  stored-HTML-via-header effects, the architecture denominators, the h2 subset of that campaign,
  the V5.2/Model 2/Q4_K_M negative results, and the asynchronous auditor (distinct from Model 2).

## 4. Verifications executed and their results

Documentation/integrity only; no services, Docker, GPU or model were started.

| Check | Result |
| --- | --- |
| `git diff --check` | PASS (no whitespace/conflict markers) |
| Local links in edited docs | 93 checked, 0 broken |
| Run-1 markdown links | 0 broken |
| `EVIDENCE_INDEX.json` row hashes vs private files | 30/30 match, 0 missing |
| Run-1 coherence | `h1_tls_new`, 3 reps, 4 apps retrieved, 3 exploit sequences, candidate id correct |
| Cleanup record | 30/30 runs `clean:true`, GPU released, no `h2_subset` key |
| Secret scan (run-1 + edited docs) | no private keys/tokens/weights/foreign emails; lab fixtures only |
| Candidate id consistency | `fastv5-public-v3-headerguard-v2-20261111` / `fastv5_guard` consistent across docs |

Note: `score_trial.py` and `assemble.py` were re-run **only to score existing private rows and
regenerate the public tables**; they read ROWS.jsonl and write JSON/CSV. They start no Docker,
model, GPU or network service. This is documental verification of existing evidence, not a new run.

## 5. Discrepancies and concrete pending items

- **H2 reconciliation (resolved, traceable).** During Claude's measurement session an Inf3ct h2
  subset had been folded into run-1. Per this task's direction, run-1 is reverted to **`h1_tls_new`
  only**: the h2 subset was removed from METRICS/EVIDENCE/CLEANUP/RESULTS/HANDOFF. The h2 raw rows
  remain **private** at `…/fwlab-architecture-private/2026-11-14/runs/Inf3ct/h2/` and are
  **excluded** from run-1 and not attributed to the 13 November h2 subset. This makes the repo
  consistent with the recovered Codex context, which recorded run-1 as h1-only.
- **ag3ncy flag** not retrieved (password undetermined within the declared offline budget); admin
  branch unmeasured. Left as a documented limit, not a gap filled by guessing.
- **ObC00ki3s flag** is out of scope for a network firewall (client-side); documented, not scored.
- The run-1 directory is **untracked**; it is not yet in a commit. Codex stages it in batch 4.
- Documentation integrity was checked; a **final staged-diff review and the code-batch tests**
  remain Codex's step (not part of this documentation pass).

## 6. Evidence useful for the issues

- **#24 / #28:** the flag campaign is now incorporated; #28 gains a second CRS data point — CRS
  prevents 6/9 flag acquisitions and **misses the header SSTI**, consistent with the 13 Nov report.
- **#23 / #25:** README/CONTEXT/project_status/challenge_apps/index/DECISIONS updated and link-checked;
  the public/private boundary (weights, raw rows) is stated.
- **#18 (CP):** the matrix now itemises the five distinct latency/throughput criteria; do not close
  on "load reports exist". Do not subtract two arms' P95 to claim added latency.
- **#65 (CP):** V4's prompt-input security issue is unresolved and **V5 does not fix V4**; separate
  V4 from V5 and either fix/validate V4 or retire supported V4 operation with a reason.
- **#68 (CP):** controlled egress (`gateway-framing/v1`) does **not** attest to preservation of the
  original client wire bytes; map each requirement one by one and preserve/transfer remnants.
- **#83 (RN) / #35, #81 (DS):** Model 2 BLOCK/DEFER research is complete with a negative result and
  the component is withdrawn; the heuristic score and the V4-only shadow observer are superseded.
- **#27/#29/#30/#31, #10–#14, #19–#22 (FS):** retained in `future_work.md`; a `not_planned`
  disposition records a scope decision, not completion.

Issue categories: IV implemented & verified · RN research-done negative · DS design superseded ·
FS future scope · CP criterion pending. Full matrix: `docs/issue_closure_2026-11-14.md`.

## 7. Recommended documentation grouping for the commits

Aligns with the batches in Codex's `ordenamiento_repo_2026-11-14/RESUMEN_Y_LOTES.md`:

1. **docs: align project state with the evaluated V5.1 architecture** — README, CONTEXT,
   project_status, index, cascade/stack/candidate guides, DECISIONS D83–D85, future_work,
   issue_closure. (Codex's batch 3.)
2. **test(lab): document controlled flag retrieval and prevention** — the
   `reports/v5/flag-acquisition-2026-11-14/run-1/` deliverables, plus the flag-campaign additions
   to README/project_status/challenge_apps/index/future_work and **DECISIONS D86** and this handoff.
   (Codex's batch 4.)

Keep the flag-campaign doc additions and D86 with the report directory so the commit is
self-contained. Stage explicit files (no `git add -A`); raw private rows stay out of Git.

## 8. Confirmation

No staging, commit, push, PR, merge, issue mutation, new campaign, attack, training, service,
Docker, or model/GPU run was performed in this pass. Frozen sources, models, datasets and
historical evidence were preserved. Any code defect would be described for Codex; none was found in
this documentation pass.
