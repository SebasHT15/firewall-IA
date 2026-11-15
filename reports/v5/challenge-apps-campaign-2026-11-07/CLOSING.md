# Closing table — measured, not measured, deviations (2026-11-07)

Scope: L2 laboratory campaign, six `sec-challenges/Web` apps @ `be8e4e8…`, real V5.1, transport
`h1_tls_new` for detection unless stated. Negatives are kept visible (see the three called-out
findings at the end). No commit; no V5.1/Model2/CRS/case changes after sealing.

## Measured (sealed, real V5.1)

| area | scope | where |
|---|---|---|
| Independence audit | all 6 apps vs shared train/select corpus | INDEPENDENCE.md |
| Detection recall (all attempts) + effect-prevention (effect-bearing controls) | An0nB0ard SQLi, CatP1cs traversal, Inf3ct SSTI | RESULTS §per-app |
| Benign FPR per app, session delivery/oracle-completion | 6 apps (+ ObC00ki3s cks.js DEV regression) | RESULTS §benign |
| Paired guarded − v5only (Model2 rescues/damage/defer/calls-avoided) | all apps | RESULTS §paired |
| Fault matrix + pinned-restart recovery | An0nB0ard (v5/model2/app down) | RESULTS §Fault |
| Reproducibility (0 field diffs) | An0nB0ard direct replay | RESULTS §Reproducibility |
| Load ladder ≤16 rps (4 workers: v5only/guarded/crs ×3 reps, **direct ×1**) + front-restart recovery; exploratory 32/64 rps (8 workers, ×2 reps) | direct/v5only/guarded/crs | RESULTS §Load |
| Fast Path rule-match + benign coverage | all 6 apps | RESULTS §Fast Path |
| Transports (own seals) | h1_tls_new, h2_tls_new, h1_tls_keepalive (full); h1_tls_resumed, h2_tls_resumed, h2_tls_keepalive (representative); h1_plain_gateway (diagnostic) | RESULTS §Transports |
| Inf3ct SSTI 2-request test (exploratory) | direct + 4 arms, clean state | RESULTS §Inf3ct SSTI 2-request |

## Not measured / N/A (no legitimate reference here)

| item | why |
|---|---|
| Organic population R, universal FPR | no authorized users/logs, no privacy/retention plan |
| Human-task traffic | all benign traffic is agent-generated (`claude-user-agent-v1`) |
| Model2 AUROC / average precision | each sealed population is single-class; Brier/ECE/threshold-curve only |
| Operational capacity threshold under a fixed concurrency profile | 16 rps meets the SLO at 4 workers; 32 rps fails the SLO in an exploratory 8-worker extension; the fixed-profile threshold is not yet measured (profile changed 4→8 and 64 rps ran post-stop) |
| Energy / power | no reliable instrument |
| Real browser-pane capture | name-based TLS vhost unresolvable without an `/etc/hosts` change (not made) |
| Full 7-transport × 6-app grid | only a representative transport set on An0nB0ard (+CatP1cs FP) was run |

## Deviations from the original protocol (all recorded in-report)

1. `score_trial.eligible_effect_positive_direct` counted the status-500 `addentry_err`; the primary
   effect metric **excludes status-only error effects** (PROTOCOL §2) → corrected to 3 controls.
2. An0nB0ard benign v1 carries a per-request oracle on only 3/8 cases → oracle-completed 0/5
   (delivery 5/5); later apps carry it on every case.
3. Fast Path first attempt used browser-headered cases that do not match the header-free rule →
   corrected with header-free cases; the rule is byte-exact.
4. **Inf3ct 2-request SSTI effect model** was not fixed in the original protocol → **exploratory**.
5. **Load ladder beyond 16 rps** is exploratory w.r.t. the original protocol: it **changed the
   concurrency profile (4→8 workers)**, ran only **2 reps** (vs 3), and executed the **64 rps rung
   after the stop criterion had already fired at 32 rps**. SLO, duration and stop criterion were
   preserved. The supported claim is only: **16 rps meets the SLO at 4 workers; 32 rps fails it at
   8 workers; the fixed-profile threshold is unmeasured.** The same-workers annex (RESULTS §Load)
   would measure it.
6. The `useful_rps` ≈22 figure at 32 rps counts late-finishing responses (incl. drain), **not**
   useful capacity under the SLO (~2.5 rps); the overload is client-queue-bound (P95 ~7–8 s) rather
   than V5-stage-bound (P95 ~0.35 s), so capacity is not attributed to V5.1/GPU alone.

## On repetitions

Identical replays of the same sealed cases measure **stability/reproducibility**, not additional
independent observations. Independent units = distinct cases/groups/sessions, never the replay or
load-request count (metric contract §3, §8).

## Prospective population to strengthen FPR (pre-registered, NOT mixed with this opened test)

The current benign FPR rests on 5 sessions/app. To bound the benign risk tightly (contract §8:
~300 independent benign groups give a ~1 % one-sided upper bound at 95 %), a **new, separate**
population is proposed and must be **sealed before any firewall decision is seen**:

- **Distinct** tasks, templates and sessions from the opened 2026-11-07 cases; a new
  `generator_id` (e.g. `claude-user-agent-v2`); `label_basis=agent_task`, `L2_AGENT_LAB`.
- Target ≥ 300 independent benign session-groups across the six apps, emphasising the paths that
  produced V5.1 false blocks (static assets / `/show`) with **realistic, varied browser header
  profiles**, to estimate the open-redirect FP rate with a confidence interval.
- Per-request status-200 oracle on **every** case (so oracle-completed is scored directly).
- Sealed per transport; scored only after sealing; **never merged** with the opened test.
- Organic/human populations remain out of scope until real users + a privacy/retention plan exist.

## Negatives kept visible

1. **Model2 defers every request on all six apps** → `guarded ≡ v5only` (0 rescues, 0 new damage,
   0 V5 calls avoided); the cascade does not beat V5_ONLY here.
2. **V5.1 false-blocks benign CatP1cs traffic** (FPR 0.280, 0/5 sessions; "Open redirect" on static
   assets) and the ObC00ki3s `cks.js`; CRS does not.
3. **The effective SSTI (header vector) passes every firewall arm** — V5.1 and CRS both fail to
   detect or prevent it: **0/4 firewall arms detected the POST, 0/4 prevented the effect** (direct
   is the positive control, not a detector; one effective attack per arm).
