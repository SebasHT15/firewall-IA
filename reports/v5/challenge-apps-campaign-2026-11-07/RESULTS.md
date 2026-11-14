# Results — six-app cascade campaign (2026-11-07)

Transport `h1_tls_new`, real V5.1, one deterministic replay per detection point; load has 3
reps/rung. Public aggregates; raw rows are private. `guarded_fast` ≡ `guarded` wherever no
case hits the single FAST_ALLOW static asset (see the Fast Path section for cases that do).

**On repetition:** replaying the *same* sealed cases measures **stability/reproducibility of the
pipeline**, not additional independent observations. The number of independent units is the count
of distinct cases/groups/sessions, not the number of replays or load requests (metric contract
§3, §8). Detection recall/FPR here come from one deterministic replay; the load rungs use 3 reps
to show stability of the rate, not 3× the sample.

**Effect-prevention denominator** is the set of **effect-bearing positive controls** — attacks
whose direct control produced the *predefined exploit effect*. Status-only error effects (e.g. a
500 from a malformed injection) are **excluded** from this primary metric and reported as separate
findings (PROTOCOL §2).

---

## An0nB0ard — SQLi (detection-relevant) — COMPLETE

### Attacks (L2_SCRIPTED_LAB, 6 cases / 2 groups)

Two recall denominators are reported separately (metric contract §3): **recall over all
labeled attempts** and **effect-prevention over the effect-bearing positive controls only**.

| arm | TP | FN | recall (all attempts) | recall CI95 (grp) | effect-bearing controls | effect prevented | prevention | V5-reason acc | P95 ms |
|---|--:|--:|--:|---|--:|--:|--:|--:|--:|
| v5only | 6 | 0 | 1.000 | [1.000,1.000]·2 | 3 | 3 | 1.000 | 0.667 | 364.7 |
| guarded | 6 | 0 | 1.000 | [1.000,1.000]·2 | 3 | 3 | 1.000 | 0.667 | 279.4 |
| crs | 4 | 2 | 0.667 | [0.333,1.000]·2 | 3 | 3 | 1.000 | — | 47.9 |
| guarded_fast | 6 | 0 | 1.000 | [1.000,1.000]·2 | 3 | 3 | 1.000 | 0.667 | 280.5 |

- **Effect-bearing positive controls = 3** (PROTOCOL §2): `union_literal` (echoes
  `SQLI_PROOF_7f3a`), `union_cred` (exfiltrates `password123`), `union_marker2` (echoes a
  marker). **Both V5.1 and CRS prevent 3/3.** (Deviation note: `score_trial`'s raw
  `eligible_effect_positive_direct` = 4 because `addentry_err` fired a **status-500** oracle on
  direct; the protocol **excludes status-only error effects** from the primary effect metric, so
  the corrected primary denominator is 3. The 2 ineffective attacks `boolean_true`/`login_bypass`
  have no direct effect and were already excluded.)
- **Recall over all attempts: V5.1 6/6 (1.000), CRS 4/6 (0.667).** This differs from
  effect-prevention: all three effect-bearing exploits are prevented by **both** arms; the CRS
  gap is in *detection of attempts that did not produce the primary effect*.
- **V5.1** blocks all 6 at the V5 stage (403, no receipt). Reason accuracy 4/6 (the 3 UNIONs +
  boolean labeled "SQL injection…"; `login_bypass`/`addentry_err` blocked but mis-labeled
  "Command injection…", still TP).
- **CRS** blocks the 3 UNIONs (rules 942100/942190/942360/949110, anomaly 15–20) + boolean
  (942100/949110, anomaly 5); **forwards** `login_bypass` (→200) and `addentry_err` (→200→**500**).

**Separate finding (not in primary effect-prevention):** `addentry_err` is an error-based SQLi
in the `POST /addentry` body. On direct it causes a 500 (SQL syntax error at the DB). **CRS
forwards it → the 500 reaches the application** (injection reached the DB); **V5.1 blocks it at
the gateway** (403, no receipt). This is reported as a CRS detection miss and an error reaching
the app, not as a prevented/eligible exploit effect.

### Benign agent (L2_AGENT_LAB, 40 cases / 5 sessions)

| arm | FP | TN | FPR | FPR CI95 (grp) | sessions delivered | sessions oracle-completed | P95 ms |
|---|--:|--:|--:|---|--:|--:|--:|
| v5only | 0 | 40 | 0.000 | [0.000,0.000]·5 | 5/5 | **0/5** | 123.5 |
| guarded | 0 | 40 | 0.000 | [0.000,0.000]·5 | 5/5 | **0/5** | 120.8 |
| crs | 0 | 40 | 0.000 | [0.000,0.000]·5 | 5/5 | **0/5** | 67.0 |
| guarded_fast | 0 | 40 | 0.000 | [0.000,0.000]·5 | 5/5 | **0/5** | 117.6 |

These are **two different measures and must not be conflated**. *Delivered* = every request in
the session returned 200, was app-received and not denied (5/5 here). *Oracle-completed* =
score_trial's `benign_sessions_complete`, which requires a per-request success oracle on **every**
case; the An0nB0ard benign v1 seal carries that oracle on only 3/8 cases, so oracle-completed is
**0/5** — a measurement-coverage limitation of this seal, **not** a firewall failure. The other
five apps carry the status-200 oracle on every benign case, so for them delivered = oracle-completed
= 5/5. (Deviation recorded; cases are not changed.)

### Paired guarded − v5only (Model2 incremental value)

| metric | attack pop | benign pop |
|---|--:|--:|
| Model2 rescues (V5-missed attacks Model2 blocked) | 0 | — |
| Model2 new benign damage | — | 0 |
| Model2 early blocks | 0 | 0 |
| Model2 DEFER | 6 | 40 |
| V5 calls avoided | 0 | 0 |
| V5 ms saved (observed) | 110.7 | 93.0 |
| effect-prevention delta | 0.000 | — |
| FPR delta (CI95) | — | 0.000 ([0,0]·5) |
| recall delta (CI95) | 0.000 ([0,0]·2) | — |

**Model2 deferred every request**, so the cascade equals V5_ONLY on this app: no rescue, no
new damage, no V5 calls avoided. Model2 does **not** clear the "beat V5_ONLY" bar here. The
observed V5-ms differences are within run-to-run noise (single rep), not a saving from avoided
calls. Model2 per-population calibration: AUROC/AP **N/A** (single-class populations);
Brier 0.083 (attack) / 0.143 (benign), ECE₁₀ 0.221 / 0.195.

### Load ladder (protocol §4: 2→4→8→16 rps, 20 s/rung, 4 workers, SLO 1000 ms; read-only benign direct-positive GETs)

Rates pooled over reps (count ÷ Σ observed windows); percentiles over pooled observations (never
averaged). direct = 1 reference rep/rung; v5only & guarded = 3 reps/rung.

| arm | offered rps | reps | offered | completed | useful | completed/offered | useful_rps | useful_under_slo_rps | P95 ms | P99 ms |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|--:|
| direct | 2 | 1 | 40 | 40 | 40 | 1.00 | 2.00 | 2.00 | 34 | 38 |
| direct | 4 | 1 | 80 | 80 | 80 | 1.00 | 4.00 | 4.00 | 35 | 41 |
| direct | 8 | 1 | 160 | 160 | 160 | 1.00 | 8.00 | 8.00 | 36 | 42 |
| direct | 16 | 1 | 320 | 320 | 320 | 1.00 | 16.00 | 16.00 | 36 | 40 |
| v5only | 2 | 3 | 120 | 120 | 120 | 1.00 | 2.00 | 2.00 | 89 | 95 |
| v5only | 4 | 3 | 240 | 240 | 240 | 1.00 | 4.00 | 4.00 | 87 | 97 |
| v5only | 8 | 3 | 480 | 480 | 480 | 1.00 | 8.00 | 8.00 | 84 | 91 |
| v5only | 16 | 3 | 960 | 960 | 960 | 1.00 | 16.00 | 16.00 | 72 | 80 |
| guarded | 2 | 3 | 120 | 120 | 120 | 1.00 | 2.00 | 2.00 | 90 | 99 |
| guarded | 4 | 3 | 240 | 240 | 240 | 1.00 | 4.00 | 4.00 | 87 | 95 |
| guarded | 8 | 3 | 480 | 480 | 480 | 1.00 | 8.00 | 8.00 | 85 | 93 |
| guarded | 16 | 3 | 960 | 960 | 960 | 1.00 | 16.00 | 16.00 | 72 | 82 |

- **16 rps meets the SLO at the fixed 4-worker profile** for read-only GETs: completion 100%,
  useful_rps = offered, SLO met; the stop point is not hit ≤16 rps. An **exploratory 8-worker
  extension** (workers changed 4→8) shows v5only/guarded fail the SLO at 32 rps (see the
  Load-ladder/CRS section). The fixed-profile operational threshold is **not yet measured**.
- `useful_rps` equals offered at 16 rps too — the corrected collector shows no inflation at load.
- guarded ≈ v5only latency (Model2 defers, adds ~sub-ms); both ~2–3× direct. Absolute latency is
  diagnostic (Flask dev servers), and the 3 reps measure **stability**, not added samples.

### Recovery — front restart under offered load (protocol §4)

guarded, 8 rps × 20 s, `--restart-front-at-seconds 8`: restart spanned 8.00–8.26 s; **158/160
completed** (2 lost during the interruption); **5 requests / 0.69 s to five consecutive clean
responses under the SLO** after the restart ended (`success=true`). A manual/pinned restart, not
autonomous recovery.

### Fault (guarded, real V5.1, pinned-restart recovery)

| scenario | impaired status | app received | effect | recovery s | requests to clean |
|---|---|---|---|--:|--:|
| v5_down | 503 (fail-closed) | no | none | 12.8 | 1 |
| model2_down | 200 (graceful: continues via V5) | yes | served | 12.9 | 1 |
| app_down | 499 (client timeout, ~10 s) | no | none | 13.0 | 1 |

V5 failure fails closed (no app receipt); Model2 failure is non-fatal (request continues
through V5); all recover after the pinned restart.

### Reproducibility

Direct replay against a fresh clean stack: **0 field diffs** over all 46 cases (status,
effect_observed, app_received), confirming ordering, app state and oracles reproduce.

### Fast Path — targeted cases that match the rule (real V5.1)

The experimental guarded Fast Path allows exactly one `GET` for one static asset
(`/static/css/style.css`) with **exact Host, no query, no body, no extra headers**. Cases built
to match / not-match the rule, run on `guarded_fast` vs `v5only`:

| case | request | guarded_fast deciding stage | v5only |
|---|---|---|---|
| `fp.match` | `GET /static/css/style.css`, no extra headers | **fast_path — no V5 call**, delivered 200 | v5 (200) |
| `fp.query` | `…/style.css?x=1` | **v5** (query disqualifies), delivered 200 | v5 (200) |
| `fp.extrahdr` | `…/style.css` + `X-Foo: bar` | **v5** (extra header disqualifies), delivered 200 | v5 (200) |

Confirms the rule is **strict**: only the exact bytes short-circuit (no V5 invocation); any query
or extra header falls through to V5. (An earlier case carrying browser UA/Accept/Referer headers
did **not** match — recorded as a deviation and corrected; the Fast Path is narrower than a
browser's real request, so in practice it fires only for byte-exact fetches.) This is a separate
active-policy arm (`PROPOSED`), not part of the main contrast.

### Transports — representative set with own seals (real V5.1)

An0nB0ard both populations re-sealed and replayed per transport (each transport has its own seal,
since a paired comparison needs identical transport):

| transport | wire confirmation | v5only recall | crs recall | benign FPR (all arms) |
|---|---|--:|--:|--:|
| h1_tls_new | ALPN http/1.1, new conn/req | 6/6 | 4/6 | 0.000 |
| h2_tls_new | **ALPN h2** (HTTP/2) | 6/6 | 4/6 | 0.000 |
| h1_tls_keepalive | **40 requests on one connection** | 6/6 | 4/6 | 0.000 |

**Decisions are transport-invariant** (the gateway canonicalises the request regardless of
transport): identical recall, effect-prevention and FPR across HTTP/2 and persistent HTTP/1.1.
The transports genuinely differed at the wire (ALPN, connection reuse) — this is a check of
equivalence, not a latency comparison.

---

## Cross-app summary (transport `h1_tls_new`, real V5.1, 1 replay)

| app | class | v5only recall | crs recall | v5 eff-prev | crs eff-prev | **v5/guarded benign FPR** | crs benign FPR | Model2 incremental |
|---|---|--:|--:|--:|--:|--:|--:|---|
| An0nB0ard | SQLi | 6/6 (1.000) | 4/6 (0.667) | 3/3 | 3/3 | 0.000 | 0.000 | neutral (defer all) |
| CatP1cs | traversal | 7/7 (1.000) | 7/7 (1.000) | 4/4 | 4/4 | **0.280 (0/5 sessions)** | 0.000 (5/5) | neutral |
| Inf3ct | SSTI | 1/2 (0.500) | 0/2 (0.000) | see note | see note | 0.000 | 0.000 | neutral |
| D33pTh0ught | crypto/OOV | — | — | — | — | 0.000 | 0.000 | neutral |
| ag3ncy | crypto/OOV | — | — | — | — | 0.000 | 0.000 | neutral |
| ObC00ki3s | client-side | — | — | — | — | 0.000 (excl. cks.js) | 0.000 | neutral |
| ObC00ki3s cks.js (DEV reg, excluded) | — | — | — | — | — | **FP (blocked)** | ok | — |

`guarded ≡ v5only` on every app (Model2 **deferred all** requests → 0 rescues, 0 new damage,
0 V5 calls avoided). `guarded_fast ≡ guarded` (no case hits the single FAST_ALLOW asset).

**Headline negatives:** (1) **V5.1 benign over-blocking** — CatP1cs 28% FPR (6 static-image
fetches "Open redirect", 1 `/show` "File inclusion") breaking all 5 sessions, plus the ObC00ki3s
cks.js "Open redirect" FP; CRS has none of these. (2) **Header-vector SSTI bypasses every arm**
(Inf3ct). (3) **CRS misses the `addentry` POST-body SQLi** (reached the DB). (4) **Model2 adds
nothing** on any app in this campaign.

---

## CatP1cs — path traversal (detection-relevant)

### Attacks (L2_SCRIPTED_LAB, 7 cases / 3 groups)

| arm | TP | FN | recall | recall CI95 | eligible | prevented | prevention | V5-reason acc | P95 ms |
|---|--:|--:|--:|---|--:|--:|--:|--:|--:|
| v5only | 7 | 0 | 1.000 | [1,1]·3 | 4 | 4 | 1.000 | 0.429 | 275.5 |
| guarded | 7 | 0 | 1.000 | [1,1]·3 | 4 | 4 | 1.000 | 0.429 | 276.8 |
| crs | 7 | 0 | 1.000 | [1,1]·3 | 4 | 4 | 1.000 | — | 16.6 |
| guarded_fast | 7 | 0 | 1.000 | [1,1]·3 | 4 | 4 | 1.000 | 0.429 | 265.5 |

Eligible effects = `flag_d3/d4` (read `/flag.txt` via encoded blocklist bypass) + `passwd_d3/d4`
(read `/etc/passwd`); d2 variants under-depth (no direct effect, kept separate); literal `../`
app-blocked (no effect). **Both V5.1 and CRS detect the percent-encoded traversal (7/7, 4/4
prevented)** — V5.1 canonicalisation decodes `%2e%2e`. V5 reason accuracy only 0.429 (encoded
flag reads mislabeled "Open redirect"/"File inclusion"; CRS rules 930100/930110/932160).

### Benign agent (L2_AGENT_LAB, 25 cases / 5 sessions) — **V5.1 FALSE-BLOCK FINDING**

| arm | FP | TN | FPR | FPR CI95 | sessions complete (delivery) | P95 ms |
|---|--:|--:|--:|---|--:|--:|
| v5only | 7 | 18 | **0.280** | [0.200,0.440]·5 | **0/5** | 250.7 |
| guarded | 7 | 18 | **0.280** | [0.200,0.440]·5 | **0/5** | 261.9 |
| crs | 0 | 25 | 0.000 | [0,0]·5 | 5/5 | 115.0 |
| guarded_fast | 7 | 18 | **0.280** | [0.200,0.440]·5 | **0/5** | 264.6 |

V5.1 false-blocks **6 static-image fetches** (`/static/img/*`, "Open redirect payload detected.")
and **1 `/show?img=<cat>.jpg`** ("File inclusion attack detected."), breaking **every** benign
session. CRS passes all 25. This is the campaign's largest benign-risk finding and is a primary
metric (not the excluded cks.js case).

## Inf3ct — SSTI (detection-relevant)

### Attacks (L2_SCRIPTED_LAB, 3 cases) — **SSTI BYPASS FINDING**

| arm | TP | FN | recall | detail |
|---|--:|--:|--:|---|
| v5only | 1 | 1 | 0.500 | blocks body `{{7*7}}` (`msg_filtered`, "SSTI payload detected."); **misses header-vector SSTI** (`ssti.post` → FORWARD 200, "Normal HTTP request") |
| guarded | 1 | 1 | 0.500 | identical (Model2 defer) |
| crs | 0 | 2 | 0.000 | blocks neither |
| guarded_fast | 1 | 1 | 0.500 | identical to guarded |

**Effect (2-stage: POST stores header payload → GET `/log` renders):** the sink observation
`inf3ct.ssti.log` has **effect_observed = True on all four arms** (`982007569` rendered) — the
effective SSTI **is not prevented by any firewall**. `score_trial`'s single-request effect model
reports 0 eligible effects here (the effect is on the ALLOW-labeled `/log` case), so
effect-prevention is **N/A in the scorer** and reported from the 2-stage probe instead.
Benign Inf3ct (incl. `GET /log`): FPR 0.000, 5/5 sessions, all arms.

## D33pTh0ught / ag3ncy — guessable-password crypto (out-of-vocabulary FP controls)

Benign agent sessions (incl. wrong-password POSTs): **FPR 0.000, 5/5 sessions complete on all
arms** (v5only/guarded/crs/guarded_fast). No detection surface (out of V5 vocabulary) — as
designed, they exercise false-positive behaviour only, and none occurred.

## ObC00ki3s — client-side puzzle (delivery/classification only)

Benign agent (excluding the known FP JS, 15 cases): **FPR 0.000, 5/5 sessions, all arms.**

**DEV regression (separate population, excluded from primary):** `GET /static/js/cks.js` is
**false-blocked by v5only and guarded** ("Open redirect payload detected."); **CRS delivers it**
(0 DENY). Confirms the known V5.1 open-redirect FP on this benign JS — same failure mode as the
CatP1cs static-asset blocks.

---

# Closing-phase measurements (2026-11-07)

## Inf3ct SSTI as a formal two-request test (EXPLORATORY — not in the original protocol)

A dedicated 2-case sealed set (`Inf3ct.ssti2`), run on a **fresh stack per arm** (clean, empty
`log_array`): a `POST /` carrying the Jinja payload in an unfiltered request header
(`X-Note: {{31337*31337}}`), then a `GET /log` that renders the stored log. **POST detection**
(did the arm block the malicious POST?) and **effect prevention** (did `/log` evaluate the
payload?) are reported separately.

| arm | POST applied | POST V5 reason | `/log` effect (982007569) | POST detected? | effect prevented? |
|---|---|---|---|:--:|:--:|
| direct | FORWARD 200 | — | **True** | — (positive control) | — |
| v5only | FORWARD 200 | "Normal HTTP request…" | **True** | no | **no** |
| guarded | FORWARD 200 | "Normal HTTP request…" | **True** | no | **no** |
| crs | FORWARD 200 | — (no rule) | **True** | no | **no** |
| guarded_fast | FORWARD 200 | "Normal HTTP request…" | **True** | no | **no** |

**POST detection 0/4 firewall arms, effect prevention 0/4 firewall arms.** `direct` is the
positive control (not a detector): it establishes that the attack has an effect (the `/log`
evaluation). Among the **four firewall arms** (v5only, guarded, crs, guarded_fast) there is **one
effective attack each**; every arm forwarded the POST (V5.1 classified it "Normal HTTP request",
no CRS rule matched) and allowed the effect → **0/4 detected, 0/4 prevented**. Denominator per arm
= 1 effect-bearing control confirmed on direct. This confirms the §Inf3ct detection finding under a
clean 2-request model. Flagged exploratory because the 2-stage effect model was not fixed in the
original protocol.

## Fast Path — all six apps, rule-matching cases (real V5.1) + benign coverage

Exact asset, **no extra headers** (`fp.match`) vs query control (`fp.query`) vs extra-header
control (`fp.extrahdr`), on `guarded_fast` vs `v5only`. Response bytes compared to `direct`.

| app | asset | `guarded_fast` fp.match | V5 call (match) | bytes == direct | fp.query / fp.extrahdr |
|---|---|---|:--:|:--:|---|
| An0nB0ard | /static/css/style.css | fast_path, 200 | no | yes | → V5 (200) |
| CatP1cs | /static/img/favicon.ico | fast_path, 200 | no | yes | → V5 (**403**) |
| D33pTh0ught | /static/img/machine.jpg | fast_path, 200 | no | yes | → V5 (200) |
| Inf3ct | /static/img/anon.png | fast_path, 200 | no | yes | → V5 (200) |
| ObC00ki3s | /static/js/cks.js | fast_path, 200 | no | yes | → V5 (**403**) |
| ag3ncy | /static/img/avatar.png | fast_path, 200 | no | yes | → V5 (200) |

- The rule fires only on the **byte-exact, header-free GET**, delivering **bytes identical to
  direct with no V5 call** (6/6 apps). Any query or extra header falls through to V5.
- **Fast Path rescues a V5 false-block for two assets:** `v5only` 403-blocks CatP1cs
  `favicon.ico` and ObC00ki3s `cks.js` (open-redirect FP), while `guarded_fast` delivers them via
  `fast_path`. But this only helps the exact header-free request.

**Benign-session coverage of the Fast Path rule (operational benefit):**

| app | benign reqs | that fetch the asset | header-free (rule match) | coverage |
|---|--:|--:|--:|--:|
| An0nB0ard | 40 | 5 | 0 | **0/40** |
| CatP1cs | 25 | 6 | 0 | **0/25** |
| D33pTh0ught | 15 | 5 | 0 | **0/15** |
| Inf3ct | 20 | 5 | 0 | **0/20** |
| ObC00ki3s | 15 | 0 | 0 | **0/15** |
| ag3ncy | 15 | 5 | 0 | **0/15** |

**Observed operational benefit of the Fast Path = 0.** Real agent/benign sessions *do* fetch the
FAST_ALLOW asset, but **always with browser headers**, so none match the header-free rule. The
rule-matching `fp.*` cases are **fabricated to trigger the rule and are not typical traffic**; they
are not counted toward benign FPR or session metrics.

## Transports — complete set (own seals) + plain-gateway diagnostic

Representative set re-sealed and replayed per transport: An0nB0ard attack (detection), An0nB0ard
benign (clean benign), CatP1cs benign (false-positive). Decisions are **transport-invariant** on
all six TLS variants, and the variants genuinely differ at the wire:

| transport | ALPN | TLS resumed | max req/conn | An0n atk recall (v5only / crs) | An0n ben FP | CatP1cs ben FP (v5only / crs) |
|---|---|--:|--:|---|--:|---|
| h1_tls_new | http/1.1 | 0/40 | 1 | 6/6 / 4/6 | 0 | 7/25 / 0 |
| h1_tls_resumed | http/1.1 | **39/40** | 1 | 6/6 / 4/6 | 0 | 7/25 / 0 |
| h1_tls_keepalive | http/1.1 | 0/40 | **40** | 6/6 / 4/6 | 0 | 7/25 / 0 |
| h2_tls_new | **h2** | 0/40 | 1 | 6/6 / 4/6 | 0 | 7/25 / 0 |
| h2_tls_resumed | **h2** | **39/40** | 1 | 6/6 / 4/6 | 0 | 7/25 / 0 |
| h2_tls_keepalive | **h2** | 0/40 | **40** | 6/6 / 4/6 | 0 | 7/25 / 0 |

TLS session resumption (39/40 on the resumed transports) and connection reuse (40 requests on one
connection on keepalive) are confirmed, and HTTP/2 negotiated ALPN `h2`. The V5.1 CatP1cs benign
false-block (7/25) and the CRS SQLi miss (4/6) **reproduce on every transport** — the gateway
canonicalises identically regardless of transport. This is an equivalence check, not a latency
comparison.

**h1_plain_gateway (diagnostic, no direct pair):** An0nB0ard attack on guarded = **6/6 DENY**.
Plain HTTP/1.1 straight to the gateway (no TLS, no front) is diagnostic only and cannot be scored
against a direct baseline (there is no direct arm for it).

## Load ladder — CRS added; SLO behaviour at 32/64 rps (exploratory, profile changed)

CRS added to the fixed-profile ladder (**4 workers**, 3 reps for v5only/guarded/crs, **1 rep for
direct**, ≤16 rps). Then an **exploratory** extension to 32 and 64 rps that **changed the
concurrency profile to 8 workers** and ran **2 reps**; 64 rps was run **after the stop criterion
had already fired at 32 rps**. Both the worker change (4→8) and the post-stop 64 rps rung are
**exploratory deviations** from the original protocol. SLO (1000 ms), 20 s/rung and the stop
criterion (`useful_under_slo_rps < 0.9×offered` or `completed_rps < 0.9×offered`) are preserved.

| arm | workers | 2 | 4 | 8 | 16 | 32 | 64 |
|---|--|--|--|--|--|--|--|
| direct — useful_rps (=useful_under_slo_rps) | 4→8 | 2.0 | 4.0 | 8.0 | 16.0 | 32.0 | 64.0 |
| crs — useful_rps (=useful_under_slo_rps) | 4→8 | 2.0 | 4.0 | 8.0 | 16.0 | 32.0 | 64.0 |
| v5only — useful_rps / **under-SLO** | 4→8 | 2.0/2.0 | 4.0/4.0 | 8.0/8.0 | 16.0/16.0 | 22.8/**2.6** | 22.4/**0.5** |
| guarded — useful_rps / **under-SLO** | 4→8 | 2.0/2.0 | 4.0/4.0 | 8.0/8.0 | 16.0/16.0 | 22.5/**2.5** | 20.3/**0.5** |

reps: ≤16 rps = 3 (v5only/guarded/crs), **1 (direct)**; 32 & 64 rps = **2 (all arms, 8 workers)**.

- **16 rps meets the SLO under the fixed 4-worker profile.** At 32 rps (8-worker exploratory
  extension) the V5.1 arms still complete 640/640 but only **73–74/640 (v5only) and 70–71/640
  (guarded)** finish under the 1000 ms SLO → **~2.5–2.6 useful-under-SLO rps**. The `useful_rps`
  ≈22–23 counts responses that finish **late** (including post-offer drain) and is **not** useful
  capacity under the SLO.
- **The overload appears in the client queue, not the V5 stage.** At 32 rps the client-queue wait
  is P95 ~7.2 s (v5only) / ~7.7 s (guarded), while the V5 stage is P95 ~0.35 s and the V5 queue
  wait ~0.31 s. So the limit under this 8-worker profile is dominated by **client-side queuing**;
  attributing it to GPU/V5.1 inference is **not supported** without varying concurrency and
  reviewing queues/resources. direct and CRS stay P95 ~36/43 ms at 64 rps.
- Supported statement: **16 rps meets the SLO at the fixed 4-worker profile; 32 rps fails the SLO
  in an exploratory 8-worker extension; the operational threshold under a fixed concurrency
  profile remains to be measured.**

**Prospective annex (pre-registered):** repeat **16/20/24/28/32 rps with the same worker count**,
**3 reps/rung**, same SLO/duration/stop-criterion, on direct/v5only/guarded/crs, with a **resource
ceiling (GPU VRAM, worker-queue depth) fixed before running**, and record client-queue vs stage
waits and CPU/RAM/GPU per rung. This would estimate the operational threshold under a fixed
profile; the 2026-11-07 run establishes only that **16 rps is SLO-clean at 4 workers**. Repeated
rungs measure stability, not independent samples.

---

## Private case paths and public evidence

- **Private raw** (outside repo), `…/fwlab-campaign-private/2026-11-07/`:
  `cases/*.jsonl` (sealed case files), `<app>/<pop>/{direct,v5only,guarded,crs,guarded_fast}/`
  (ROWS, SUMMARY, CLEAN), `<app>/<pop>/seal/SEAL.json`, `an0n/load/*`, `an0n/fault/*`,
  `audit/independence_audit.raw.json`.
- **Public** (`reports/v5/challenge-apps-campaign-2026-11-07/`): this file, README, PROTOCOL,
  INDEPENDENCE, `independence_audit.summary.json`.
