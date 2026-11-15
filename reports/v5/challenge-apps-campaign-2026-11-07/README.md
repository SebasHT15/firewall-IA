# Six-app cascade measurement campaign — 2026-11-07

L2 laboratory campaign over the six `sec-challenges/Web` apps
(`be8e4e8f1c6aa12a17430146d569870d96d43dd5`) behind the common TLS/HTTP-2 front, comparing
**direct / v5only / guarded / crs** (+ the separate **guarded_fast** active-policy arm) with
**real V5.1**. Contract: `METRICAS_CASCADA_PAPER_2026-11-04.md` (sha `fb8ce839…`). These are
agent/scripted laboratory populations — **not human or organic traffic**. No git commit/push;
app vulnerabilities unmodified.

## Documents

- [INDEPENDENCE.md](INDEPENDENCE.md) — Phase 1 audit (apps absent from train/select corpus).
- [PROTOCOL.md](PROTOCOL.md) — pre-registered protocol, frozen before results; incl. the
  pre-seal `load_trial.py` collector fix.
- [RESULTS.md](RESULTS.md) — per-app × per-arm matrices, load, fault, paired analysis, Fast Path,
  transports, Inf3ct 2-request SSTI.
- [CLOSING.md](CLOSING.md) — measured / not-measured / deviations table, repetition caveat, and the
  pre-registered prospective FPR population (kept separate from this opened test).
- `independence_audit.summary.json` — corpus file hashes + token counts.
- Private raw area (outside repo): `…/fwlab-campaign-private/2026-11-07/` — cases, seals,
  stack logs, ROWS. Public artifacts carry ids/hashes/aggregates only.

## What was executed (this session)

| Phase | Scope | Status |
|---|---|---|
| 1 Independence audit | all 6 apps vs shared V5.1+Model2 corpus (254 files/2.8M lines) | **done** |
| 2 Populations + direct oracles | An0nB0ard, CatP1cs, Inf3ct (benign+attack); D33pTh0ught, ag3ncy, ObC00ki3s (benign); ObC00ki3s DEV regression | **done** |
| 3 Seal + protocol | per population/transport (h1_tls_new); collector fix pre-seal | **done** |
| 4 Replay arms (real V5.1) | 4 arms × populations, scored | **done** (An0nB0ard full incl. load+fault+reproducibility; others: detection/FPR) |

## Primary findings (transport `h1_tls_new`, real V5.1, pilot)

- **Application independence holds** (§INDEPENDENCE): zero app-identifying tokens in the
  train/select corpus; attack *vocabulary* overlap is expected and bounds claims to
  "unseen application", not "unseen payload".
- **Detection (An0nB0ard SQLi):** report two denominators separately — **recall over all
  attempts** (V5.1 6/6 = 1.000; **CRS 4/6 = 0.667**) and **effect-prevention over the 3
  effect-bearing positive controls** (UNION exploits), where **both V5.1 and CRS prevent 3/3**.
  Separately: CRS **forwards** the `addentry` POST-body SQLi (→500 at the DB) and `login_bypass`;
  V5.1 blocks both. (The status-500 `addentry_err` is excluded from the primary effect metric per
  PROTOCOL §2; `score_trial`'s raw eligible=4 includes it — deviation recorded.)
- **False blocks:** **FPR 0.000** (CI [0,0]·5 session-groups) on all arms for An0nB0ard benign;
  **5/5 sessions delivered**, but **0/5 oracle-completed** (the benign v1 seal carries a
  per-request oracle on only 3/8 cases — a coverage limit, not a firewall failure; the other five
  apps are 5/5 on both).
- **Model2 contribution (guarded − v5only):** **0 rescues, 0 new benign damage, 0 V5 calls
  avoided — Model2 deferred all 46 requests.** On this app the cascade is **neutral**: it
  neither improves detection nor harms benign traffic versus V5_ONLY, so it does not clear
  the "must beat V5_ONLY" bar here.
- **Collector fix verified:** corrected `useful_rps` equals the offered rate over the full
  offered window (no early-drain inflation).

**All-apps headline results** (full matrices in [RESULTS.md](RESULTS.md)):
- **V5.1 benign over-blocking (primary risk):** CatP1cs **FPR 0.280** (6 static-image fetches
  "Open redirect" + 1 `/show` "File inclusion"), breaking **0/5 sessions**; CRS **FPR 0.000**,
  5/5. Same open-redirect FP root cause as the ObC00ki3s cks.js regression. D33pTh0ught, ag3ncy,
  ObC00ki3s (excl. cks.js), An0nB0ard, Inf3ct benign: FPR 0.000, 5/5.
- **Traversal (CatP1cs):** v5only **and** CRS detect the percent-encoded bypass 7/7, 4/4 effects
  prevented.
- **SSTI (Inf3ct):** the **header-vector SSTI bypasses every arm** (v5only/guarded/CRS); its
  `/log` effect evaluates through all of them. V5.1 catches only the body `{{7*7}}`.
- **Model2 is neutral everywhere:** it deferred all requests on all six apps — 0 rescues,
  0 new benign damage, 0 V5 calls avoided — so `guarded ≡ v5only` and the cascade does not clear
  the "beat V5_ONLY" bar in this campaign.

Negative/null results are reported, not hidden (CRS misses, Model2 neutrality, V5 reason
misattribution of 2 SQLi as "Command injection").

## N/A and pending (explicit)

**N/A (no legitimate reference in this environment):**
- **Organic population R / FPR_universal** — no authorized users, logs, privacy/retention
  plan; cannot be inferred from lab apps.
- **Human-task traffic** — all benign traffic is agent-generated (`claude-user-agent-v1`).
- **Model2 AUROC / average precision** — each sealed population is single-class (attack all
  BLOCK, benign all ALLOW); AUROC needs both classes. Brier/ECE/threshold-curve reported.
- **Energy/power** — no reliable instrument.
- **Browser-pane capture** — name-based TLS vhosts not resolvable by a browser without an
  `/etc/hosts` change (not made); agent HTTP emulates the browser instead.

**Executed in the follow-up expansion (2026-11-07):**
- **Load ladder + recovery** (PROTOCOL §4): 2→4→8→16 rps × 3 reps on v5only/guarded (+ direct
  reference) and a front-restart recovery run. **No saturation at ≤16 rps** for read-only GETs;
  recovery 5 requests / 0.69 s. See RESULTS §Load ladder / §Recovery.
- **Fast Path** demonstrated with a rule-matching case: exact asset short-circuits (`fast_path`,
  no V5 call); `?x=1` or an extra header falls through to V5. See RESULTS §Fast Path.
- **Transports** h2_tls_new (HTTP/2) and h1_tls_keepalive (persistent) with own seals: decisions
  transport-invariant. See RESULTS §Transports.
- **Corrections** applied to RESULTS/README vs PROTOCOL + sealed rows (effect-prevention = 3
  effect-bearing controls → both arms 3/3; `addentry_err` status-500 reported as a separate
  finding; recall-over-attempts vs effect-bearing recall split; delivered vs oracle-completed
  sessions; stability-not-independent-samples note).

**Closing phase (2026-11-07, all executed):**
- **All six TLS transports + plain-gateway diagnostic** (own seals) on attack/benign/FP sets:
  decisions **transport-invariant**; TLS resume (39/40) and connection reuse (40/conn) confirmed.
- **Load under SLO:** **16 rps meets the SLO at the fixed 4-worker profile**; an **exploratory
  8-worker extension** (workers changed 4→8, and 64 rps run after the stop criterion fired — both
  deviations) fails the SLO at 32 rps (only ~2.5–2.6 useful-under-SLO rps; `useful_rps` ≈22 counts
  late responses). The overload is in the **client queue** (P95 ~7–8 s) not the V5 stage (P95
  ~0.35 s), so it is **not** attributable to V5.1 inference alone. **direct and CRS stay clean to
  ≥64 rps.** The fixed-profile threshold is **not yet measured**; a same-workers 16/20/24/28/32 rps
  annex (3 reps) is pre-registered.
- **Inf3ct SSTI formal 2-request test** (clean state/arm, exploratory): among the four firewall
  arms, POST detection **0/4** and effect-prevention **0/4** (direct is the positive control, not a
  detector) — the effective SSTI passes every firewall arm.
- **Fast Path, all six apps:** fires only on the byte-exact header-free GET (identical bytes to
  direct, no V5 call); **benign-session coverage = 0** (real requests always carry headers), so
  observed operational benefit = 0. It does deliver two assets V5.1 false-blocks (CatP1cs favicon,
  ObC00ki3s cks.js), but only for the fabricated header-free request.

**Still pending / N/A:** organic population R and human-task traffic (N/A — no users/privacy plan);
the fixed-profile 16/20/24/28/32 rps threshold annex (same workers, 3 reps); a larger pre-registered FPR
population (proposed in [CLOSING.md](CLOSING.md), kept separate from this opened test).

See [RESULTS.md](RESULTS.md) for the full matrices and the other apps.
