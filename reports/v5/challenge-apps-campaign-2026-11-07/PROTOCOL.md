# Pre-registered protocol — six-app cascade measurement campaign (2026-11-07)

**Frozen before any firewall-arm result was opened.** After this point no code, case,
model, threshold or rule is changed on the basis of a firewall result. Governing metric
contract: `METRICAS_CASCADA_PAPER_2026-11-04.md`, SHA-256
`fb8ce839151d9bb842700c8ea4a1a591fe55d62ae5c680e1f3feaf6a3d58c4e8` (recorded in every seal).
App source: `sec-challenges/Web` @ `be8e4e8f1c6aa12a17430146d569870d96d43dd5`.

## 0. Pre-seal collector correction (reviewer finding 2026-11-07)

`load_trial.py` computed `useful_rps` over `elapsed_until_last_response_s`, which inflates
the rate above the offered rate when responses drain before the offer window ends. Fixed
**before sealing** (no final result used to decide the change): rates now use explicit
denominators — `offered_rps` over `seconds_target`, and `completed/useful/useful_under_slo`
over `observed_window_s = max(seconds_target, elapsed_until_last_response_s)`. Prior
preparation summaries keep their published `useful_rps` as historical evidence and are not
reinterpreted. The seals pin the corrected `load_trial.py` (source sha `7b33ba32…`).

## 1. Populations, labels, adjudication

| Population | Seal tag | Label | Label basis | Adjudication |
|---|---|---|---|---|
| Benign agent sessions | `L2_AGENT_LAB` | ALLOW | `agent_task` | Delivery/status oracle on **direct**; never a firewall verdict |
| Scripted lab attacks | `L2_SCRIPTED_LAB` | BLOCK | `constructed_effect` | Per-case **effect oracle** confirmed on **direct** |
| ObC00ki3s benign-JS regression | separate DEV tag | ALLOW | `agent_task` | Known V5.1 FP; **excluded from primary metric**, kept visible |

Benign traffic is **agent-generated laboratory HTTP** (`generator_id=claude-user-agent-v1`),
browser-emulating (real Chrome UA/Accept/Accept-Language headers, CSS/asset fetches, form
posts). It is **never** described as human or organic. True browser-pane capture is **not
available**: the stack serves name-based TLS vhosts (`*.fwlab.test`) on loopback with no
`/etc/hosts` entry, which a browser cannot resolve without a system change that was not made
(documented limit). No request is labeled from a firewall decision; disagreements/indeterminate
stay `UNKNOWN`.

## 2. Grouping, exclusions, independence

- **Benign** grouped by session (`group_id = session_id`): a session that fails on an
  identical `GET /` is one failure, not eight. Pilot = 5 sessions/app.
- **Attacks** grouped by sub-family/template (`an0n.sqli.union`, `an0n.sqli.ineffective`).
  Independent units are reported, not payload-template variations.
- **Effect-prevention denominator = attacks whose direct control produced the predefined
  effect** (positive controls only). Ineffective attacks (`boolean_true`, `login_bypass`) and
  error-only effects (`addentry_err` → 500) are **kept separately** and excluded from the
  effect-prevention denominator; they are never silently called detector TPs.
- Fail-closed denials are reported separately and never counted as detector TPs.

## 3. Arms and pins (sealed configs)

Same TLS/HTTP-2 front and same app image across arms; only the layer between front and app
changes. Gateway body limit **16 MiB**, front request cap **64 KiB**, V5.1 decoded-body cap
19,920 B.

| Arm | `--arm` | config sha | Firewall | Model2 | Fast Path |
|---|---|---|---|---|---|
| direct | direct | `fb00c13a…` | none | — | — |
| v5only | v5only | `fb00c13a…` | cascade `V5_ONLY` | not enforced | off |
| guarded | guarded | `f7c4d9df…` | cascade `CASCADE_ACTIVE` | `GUARDED_ENFORCE` θ=0.9, `c1-selective-abstention/v1` | off |
| guarded_fast | guarded+fp | `3c5c6830…` | cascade | guarded | one app-bound `FAST_ALLOW` (policy `aac07c76…`), audit rate 0.0 |
| crs | crs | `fb00c13a…` | ModSecurity + OWASP CRS 4.25.2 PL1, anomaly 5/4 | — | — |

- **V5.1 (real):** manifest `v51-model2-guarded-lab-20261105`; adapter
  `v51-policy-20261101T210119Z` sha `f101b2f1…`; base TinyLlama-1.1B-Chat-v1.0
  `fe8a4ea1…`; canonical-request/v1 B=415, max_decoded_body 19920.
- **Model2:** `baseline34.json` (`v4-d82`) sha `da6f6eb8…`, policy sha `4d2e4202…`.
- Main causal contrast: **guarded − v5only** with identical V5.1 and identical sealed cases.
  Fast Path is a separate active-policy arm (policy `PROPOSED`); not part of the main contrast.

## 4. Transports, SLO, load ladder, repetitions, arm order

- **Transport (pilot):** `h1_tls_new` (sealed). Full campaign adds the other six
  (`h1_plain_gateway` diagnostic, `h1_tls_resumed/keepalive`, `h2_tls_new/resumed/keepalive`);
  each needs its own per-transport seal because paired comparison requires identical transport.
- **SLO (predeclared, illustrative on Flask dev servers):** end-to-end ≤ 1000 ms; absolute
  latency is **not representative** (dev servers) and reported as diagnostic.
- **Load ladder (predeclared):** offered 2 → 4 → 8 → 16 rps, 20 s per rung, 4 workers, warmup 2;
  **stop point** = first rung where `useful_under_slo_rps < 0.90 × offered_rps` or
  `completed_rps < 0.90 × offered_rps`. Read-only benign direct-positive case IDs only.
  Repeated load traffic is **not** independent quality evidence.
- **Repetitions:** ≥ 3 per important load rung; publish each repetition and percentiles over
  pooled observations (never average P95). Seeds fixed: dataset/data seed from the V5 recipe
  (`20261019`); load request scheduling is deterministic round-robin over selected case IDs.
- **Arm order:** alternate `direct, v5only, guarded, crs, guarded_fast` ↔ reverse across
  repetitions where the environment allows.
- **GPU:** real-V5.1 arms acquire the owner-authorized temporary hand-off only when
  `GPU_STATUS.json=AVAILABLE`, released after each run's cleanup (even on failure).

## 5. Primary metrics (pre-specified) and closing table

Primary: **benign FPR**, **attack-effect prevention / recall on eligible (positive-control)
attacks**, **complete legitimate sessions**, **useful throughput under SLO**. Model2 must add
incremental benefit over `v5only` (rescues − new damage) without exceeding the agreed benign
risk. Report per-arm × per-app: identity/hash; N requests and N groups/sessions; TP/TN/FP/FN +
invalids; recall/FPR with cluster intervals; eligible/prevented effects; complete sessions;
Model2 rescues/new-damage; V5 calls avoided; P95/P99; useful rps + saturation; 502/503/timeouts;
GPU/CPU/RAM; layer of each rejection; limits and missing data. Negative results and `N/A`
(no legitimate reference for a rate) are published. No model/profile/threshold/exclusion is
chosen after the test is opened.

## 6. Seals (frozen)

| Population | Seal | cases/groups/sessions |
|---|---|---|
| L2_SCRIPTED_LAB (An0nB0ard) | `…/an0n/attack/seal/SEAL.json` | 6 / 2 / 6 |
| L2_AGENT_LAB (An0nB0ard) | `…/an0n/benign/seal/SEAL.json` | 40 / 5 / 5 |

Remaining apps (CatP1cs, Inf3ct, D33pTh0ught, ag3ncy, ObC00ki3s) follow the identical
order (author → direct oracle → seal → replay) and are sealed per population/transport before
their results are opened.
