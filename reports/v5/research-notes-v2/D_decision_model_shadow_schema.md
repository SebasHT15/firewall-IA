# D — Decision Model: shadow routing-data logging schema and baselines (design v1)

**DESIGN ONLY: not a decision, not a result.** Nothing here was implemented, run or measured, and
no runtime, configuration or data file was changed. This note designs the data the future Decision
Model (DM) will need, and the baselines it will have to beat. Every policy choice below is an
**owner decision that has not been taken**. Claims I could not check against a primary source are
marked **UNVERIFIED**.

| | |
|---|---|
| Date | 2026-10-06 |
| Branch / base | `research/v5-benign-coverage-audit`, base `5602045` (read-only) |
| Read | `reports/v5/research-notes-v1/README.md` §C · `DECISIONS.md` D29, D30, D37, D40–D55 · `data_plane/data_plane.py` · `data_plane/hybrid_contracts.py` · `data_plane/request_features.py` · `control_plane/{classifier_api,inference_core}.py` (response and timing fields) · `config.yaml` |
| Target pipeline | REQUEST → Fast Path (D29, FAST ALLOW only) → Hybrid Analyzer (evidence) → **DM: BLOCK vs DEFER_TO_V5** → V5 (ALLOW / BLOCK) → enforcement (D34) |
| Terminology | "V5" is the next **model** (D45). The DM is a Hybrid Architecture stage, never "V5". Today the verdict model is **V4**; every field named `v5_*` is the verdict model's field, and `verdict_model_role` says which model it was |

---

## 0. Design premises (from the repository, not new decisions)

1. **The DM's only learnable part is the rejector** (notes v1 §C). It has two actions: light BLOCK
   or DEFER. It never ALLOWs. With a perfect V5, Chow's rule on `P(attack | x)` is optimal, so the DM
   is useful only where V5's errors depend on `x` in ways the score does not summarize, or where the
   score is unreliable in identifiable regions (coverage, conflict) (Chow 1970; Jitkrittum et al.
   2023).
2. **Two labels per example.** `y` is adjudicated ground truth, the safety target. `v` is the V5
   verdict, used **only** to value deferral. A DM trained on `v` learns V5's false positives and its
   misses.
3. **Prevalence-free operation (D42).** The objective is to maximize light-BLOCK coverage of attacks
   under a cap on `P(light BLOCK | benign)`. Both are class-conditional rates, so neither depends on
   the traffic mix. All shadow rates are deployment- and period-specific observations.
4. **Shadow mode first (D43).** Nothing logged here changes classification, routing or enforcement.
   A logger failure is caught and ignored like an extractor failure (D43), and it never yields a
   403 or 503.
5. **Open owner decisions that gate any active DM:**
   - D29 forbids a heuristic fast BLOCK, and D43 left open whether any Hybrid stage may BLOCK without
     the model;
   - D44 says which headers may be read;
   - the costs or the cap;
   - V5, the Analyzer, the evidence schema and the fast path must all be frozen.
6. **Current logging policy** (`data_plane.py:244-247`): the query and body are never logged. The
   decision line does log `pretty_host:port` and the path without the query. The control plane logs
   `raw[:200]` of an **invalid** model output (`classifier_api.py:149-150`), which can quote the
   request. Both are acceptable in the lab, but they would violate §2 on real traffic (see §9,
   observations).

## 1. Record architecture: four stores, joined only by a random `event_id`

| Store | Content | Coverage | Privacy | Access |
|---|---|---|---|---|
| **R — routing event** | structured, numeric/enumerated record (§3) | **100% of requests** reaching the gateway (inclusion probability 1) | P0–P2 | research role; no join with any other identity source |
| **V — raw-text vault** | the D1 text after credential redaction (§4) | **sampled** only (§5), π logged | P3 | named adjudicators + replay job; every access logged |
| **A — adjudication** | blind two-pass labels (§6) | sampled subset of V | P1 | adjudicators write; research reads |
| **M — dataset manifest** | data-role assignment, group components, leakage flags (§7) | per frozen routing dataset | P0–P2 | builder only; immutable once frozen (D32/D39 style) |

- `event_id` is a random UUIDv4 created at request arrival. It is **not derived from content**, so
  on its own it links nothing across requests.
- Records are append-only. A correction is a new record with `supersedes_event_id`; a frozen file is
  never edited (D39).
- `R` is cheap enough to keep for every request, so the structured denominator is complete and the
  only sampling is for raw text and labels. This removes selection bias for every quantity that does
  not need `y`.

**Privacy classes**

| Class | Definition | Examples |
|---|---|---|
| P0 | configuration and provenance, no request information | versions, hashes, enums of policy |
| P1 | derived description of the request content or a model output (lengths, counts, probabilities) | RequestFeatures v2, Analyzer signals, V5 decision |
| P2 | pseudonymous identifiers: keyed HMAC of content or client | `g_canon`, `g_client` |
| P3 | raw or near-raw request content | vault item |
| P4 | secrets | HMAC keys, vault keys. **Never** in any record; only key **ids** are stored |

P2 is **pseudonymous, not anonymous.** A key holder can re-link it. NIST SP 800-188 treats
pseudonymisation as a de-identification technique with residual re-identification risk, and GDPR
Art. 4(5) defines pseudonymised data as still personal data. Treat R as personal data on real
traffic.

## 2. What is never stored (in R, A or M)

| Never stored | Why |
|---|---|
| Raw path, query string or values, body, header values, cookies, `Authorization`, fragments | attacker-controlled and may carry credentials or PII (current policy, `data_plane.py:244`) |
| Parameter names and JSON keys in clear | keys can carry PII (e-mail-as-key, IDs); only counts plus a keyed hash of the name set |
| **Any `Host`- or `User-Agent`-derived field**, including hashes, lengths and presence flags | D44 forbids indirect re-introduction into any Hybrid model input. R is the DM's training set, so the exclusion applies to the record. The deployment slice comes from the configured `deployment_id`, never from `Host` |
| Client IP, port, TLS fingerprint in clear | identity; only `g_client` (§3.1) |
| V5 free-text reason or raw generated text | it can echo the request (an invalid output is exactly that case). Store the D47-normalized reason **category** and token counts only |
| Generated token ids | the same echo risk |
| Exception messages | they can quote the request (D43 policy: type plus code location only) |
| Exact timestamps finer than 1 minute in R | timing correlation re-identifies; ordering comes from `seq_in_epoch` |
| Unsalted / unkeyed hashes of low-entropy identifiers | a SHA-256 of an IPv4 address can be inverted by enumeration; only keyed HMAC |
| Anything from External Test v1 | D40 / D53: never development data for a Hybrid component |

## 3. Routing-event schema `routing-shadow/v1` (store R)

Column key:
- **Req**: R = required, C = conditional (required when the producing component ran), O = optional.
- **DM-in**: whether the DM may read the field as an input. Only fields available **before** the V5
  call and allowed by D44 may be inputs. Every other field is a label, an outcome or provenance.
  Ingest validation must reject a model configuration that names a non-input field.

### 3.1 Identity, time, grouping keys

| Field | Type | Source | Req | Privacy | DM-in | Notes |
|---|---|---|---|---|---|---|
| `schema_version` | str `routing-shadow/v1` | logger | R | P0 | no | §8 |
| `event_id` | UUIDv4 str | gateway, at arrival | R | P0 | no | random, the join key to V / A |
| `epoch_id` | str | config | R | P0 | no | one epoch = one frozen set of all component versions plus one content-key period |
| `seq_in_epoch` | int64 | gateway, monotonic | R | P0 | no | total order without fine timestamps |
| `event_minute_utc` | ISO-8601, truncated to minute | gateway | R | P1 | no | temporal splits only |
| `g_canon` | hex128 | HMAC-SHA-256(`k_content`, canonical request) | R | P2 | no | canonical = `method path?query \n content_type \n body` after decoding and canonicalization, headers excluded (as D51) |
| `g_payload` | list[hex128] (≤ 16) | HMAC(`k_content`, each decoded value ≥ 8 chars) | R | P2 | no | links payload reuse across endpoints; short values are skipped to avoid giant components |
| `g_endpoint` | hex128 | HMAC(`k_content`, method + templated path + sorted param-name set + content-type) | R | P2 | no | for slicing and unseen-endpoint splits, **not** for grouping (it would make giant groups) |
| `g_featvec` | hex64 | SHA-256 of the 34 RequestFeatures v2 values | R | P1 | no | D54 feature-vector relation |
| `g_client` | hex128 | HMAC(`k_client[epoch]`, peer IP prefix /24 IPv4 or /48 IPv6 + `deployment_id`) | R | P2 | no | session/campaign grouping, flood caps. **Never an input** |
| `g_client_day` | hex128 | HMAC(`k_client`, `g_client` + UTC date) | R | P2 | no | the grouping relation (one scanner-day or one user-day = one group) |
| `hmac_key_ids` | map str→str | key service | R | P0 | no | e.g. `{"content":"kc-2026-10","client":"kk-2026-10"}`; never the keys |

**Anonymization method (decided in this design):**
- **Primitive:** HMAC-SHA-256 (RFC 2104 / FIPS 198-1), truncated to 128 bits. Collisions are
  negligible at these volumes.
- **Domain separation:** separate keys per purpose (`k_content`, `k_client`, `k_sample`), plus a
  label prefix in the message.
- **Key storage:** keys live in a secrets store that only the logging service can use. They are
  never in the repository, the configuration or the logs.
- **Rotation (NIST SP 800-57 cryptoperiod logic):**
  - `k_client` rotates every **30 days** and is destroyed when the last R records using it expire.
    Client linkage beyond one period is then impossible by construction.
  - `k_content` is stable for the life of **one routing-dataset generation** (≤ 12 months), because
    leakage checks need content linkage across time (§7). A rotation starts a new `epoch_id`. A
    temporal split never straddles a `k_content` rotation; otherwise the cross-split leakage check
    is impossible.
  - The privileged builder computes `g_canon` / `g_payload` over the V5 and Analyzer training sets
    with the same `k_content`, producing hash blocklists (§7). This is the only way a pseudonym is
    compared with an outside set.
- **What hashing does not protect:** numeric features (lengths, counts) plus minute and endpoint can
  still fingerprint a request. This residual risk is accepted and documented, not denied.

### 3.2 Provenance, versions and hashes

| Field | Type | Source | Req | Privacy | DM-in |
|---|---|---|---|---|---|
| `source` | enum `lab_synthetic \| docker_lab \| paired_dev \| vault_replay \| real_deployment` | config | R | P0 | no |
| `deployment_id` | str (configured; never from `Host`) | config | R | P0 | no (slice only) |
| `privacy_regime` | enum `lab \| real` | config | R | P0 | no |
| `gateway_commit` | git sha | build | R | P0 | no |
| `config_sha256` | hex | gateway | R | P0 | no |
| `feature_schema_version` | str `request-features/v2` | extractor | R | P0 | no |
| `analyzer_version` / `analyzer_artifact_sha256` / `calibrator_id` | str / hex / str | Analyzer | C | P0 | no |
| `deterministic_engine_version` / `_rules_sha256` | str / hex (null today) | engine A | C | P0 | no |
| `coverage_gate_version` / `_config_sha256` | str / hex | gate | R | P0 | no |
| `fast_path_policy_id` / `_sha256` | str / hex | fast path (D29, not implemented) | C | P0 | no |
| `dm_policy_id` / `dm_artifact_sha256` | str / hex | DM shadow | C | P0 | no |
| `baseline_policy_sha256` | map B0..B3 → hex (thresholds included) | DM shadow | R | P0 | no |
| `verdict_model_role` | enum `V4 \| V5` | config | R | P0 | no |
| `verdict_base_model` / `verdict_adapter_sha256` / `inference_config_sha256` | str / hex / hex (decoding mode, max_new_tokens, greedy) | control plane | R | P0 | no |
| `prompt_template_sha256` / `parse_rule_version` | hex / str | `inference_core` | R | P0 | no |
| `sampling_design_version` / `redaction_policy_version` | str | logger | R | P0 | no |
| `label_taxonomy_version` | str (D47 vocabulary) | config | R | P0 | no |

### 3.3 Request description and Analyzer evidence (pre-V5; candidate DM inputs)

| Field | Type | Source | Req | Privacy | DM-in |
|---|---|---|---|---|---|
| `features` | object: the 34 RequestFeatures v2 fields, exactly as `request_features.py` defines them | extractor | R | P1 | yes |
| `features_status` | enum `ok \| error:<ExcType>` | extractor | R | P0 | yes (gate) |
| `param_name_set_hash` | hex128, HMAC(`k_content`) | extractor | O | P2 | no |
| `analyzer_status` | enum `ok \| error \| skipped` | Analyzer | R | P0 | yes (gate) |
| `analyzer_attack` | float [0,1], calibrated, the D50 `attack` | Analyzer | C | P1 | yes |
| `analyzer_attack_raw` | float, the uncalibrated model score | Analyzer | C | P1 | yes |
| `analyzer_category` | map of the 8 D47 ids → float, sum 1 (or null) | Analyzer | C | P1 | yes (context only, D46) |
| `unc_margin05` | float, \|attack − 0.5\| | derived | C | P1 | yes |
| `cat_top1`, `cat_margin12`, `cat_entropy` | float | derived (D50: no global confidence) | C | P1 | yes |

**"Confidence" is not a stored score (D50).** It is always one of the derived quantities above.

### 3.4 Deterministic, coverage/OOD and conflict signals (pre-V5)

| Field | Type | Source | Req | Privacy | DM-in |
|---|---|---|---|---|---|
| `det_indicators` | list of {`family` (D47 id), `sink` enum `path_seg\|query_val\|form_val\|json_leaf\|multipart\|xml`, `decode_layer` int, `rule_id`} | engine A (future; null today) | C | P1 | yes |
| `det_strong_indicator` | bool: any indicator of class "strong" in a natural sink | engine A | C | P1 | yes |
| `parse_status` | enum list: `ok, body_unparsed, json_invalid, json_too_deep, duplicate_keys, mixed_encoding, …` | parser | R | P1 | yes (gate) |
| `decode_depth` | int (reported separately, never fed to family detectors; notes v1 §B) | parser | C | P1 | yes (gate) |
| `cov_body_format_supported` | bool (`body_format ∈ {none, form, json}`) | gate | R | P1 | gate |
| `cov_length_in_range` | bool: every length ≤ the frozen p99.9 of Analyzer TRAIN | gate | R | P1 | gate |
| `cov_featvec_seen_in_analyzer_dev` | bool (`g_featvec` ∈ TRAIN ∪ VALIDATION of `hybrid_analyzer_v2`) | gate | R | P1 | gate |
| `cov_ngram_novelty` | float (Anagram-style Bloom novelty; future) | gate | O | P1 | gate |
| `cov_endpoint_seen_before` | int (count of `g_endpoint` in **prior** epochs only, never future) | gate | O | P1 | gate |
| `cov_auth_bearer_present` | bool, JWT blind spot (D48) | gate | **not logged until a D44 revision**: it reads `Authorization` | — | — |
| `coverage_ok` | bool = AND of the hard gates | gate | R | P1 | gate |
| `conflict_flags` | enum list: `analyzer_high_no_det` (attack ≥ t_hi ∧ no indicator), `det_strong_analyzer_low` (strong ∧ attack ≤ t_lo), `family_mismatch` (det family ≠ category top-1), `multi_family` | derived | R | P1 | yes |
| `conflict_any` | bool | derived | R | P1 | gate |

**Coverage signals are hard DEFER gates first, not learned features** (notes v1 §C).
- A DM may learn from them only if the non-redundancy test (§10, W5) shows that they add value.
- Gate thresholds are frozen on Analyzer or routing development data, never on ROUTING-TEST.

### 3.5 Decisions: actual, proposed and hypothetical

| Field | Type | Source | Req | Privacy | DM-in |
|---|---|---|---|---|---|
| `fast_path_eligible` / `fast_path_hypothetical` | bool / enum `FAST_ALLOW \| NO` | fast path, shadow | R | P0 | no |
| `dm_population` | bool: not fast-path-eligible (the DM's population, notes v1 §C) | derived | R | P0 | no |
| `dm_score` | float | DM shadow | C | P1 | no |
| `dm_proposed` | enum `BLOCK \| DEFER` | DM shadow | C | P0 | no |
| `baseline_decisions` | map {`B0`,`B1`,`B2`,`B3`,`B3c`} → `BLOCK \| DEFER` (§10) | DM shadow | R | P0 | no |
| `dm_mode` | enum `shadow \| active` | config | R | P0 | no |
| `explore_holdout` | bool: an active DM BLOCK was turned into DEFER by ε-exploration | DM | C (active) | P0 | no |
| `logging_propensity` | float: P(observed action \| x) under the logging policy | DM | C (active) | P0 | no |
| `enforced_decision` / `enforced_by` | enum `ALLOW \| BLOCK` / enum `V4 \| V5 \| DM \| fail_closed \| fast_path` | gateway | R | P0 | no |
| `http_status` / `forwarded` | int / bool (L2, D41) | gateway | R | P0 | no |

### 3.6 Verdict-model outcome (V5; V4 today); never an input

| Field | Type | Source | Req | Privacy |
|---|---|---|---|---|
| `v_status` | enum `ok \| invalid \| timeout \| unreachable \| http_503 \| http_500 \| http_422 \| bad_json \| not_called` (the `data_plane.py` failure classes) | gateway | R | P0 |
| `v_decision` | enum `ALLOW \| BLOCK` or null | control plane | C | P1 |
| `v_reason_category` | D47 id (normalized via the D47 mapping) or `jwt` or null; never free text | control plane | C | P1 |
| `v_source` | enum `live \| deferred_validation (D30) \| vault_replay` | logger | R | P0 |
| `v_decoding_mode` / `v_stop_reason` | enum `full \| verdict_prefix` / enum `eos \| prefix_match \| max_tokens` | control plane | R | P0 |
| `v_prompt_tokens` / `v_generated_tokens` | int | `inference_core` | C | P1 |
| `v_logp_first` | {`AL`(1964), `B`(29933)} → float: first-token log-probabilities of the two verdict tokens (tokenization per notes v1 §D) | control plane (new field) | O | P1 |
| `v_logit_margin` | float = logp(B) − logp(AL) | derived | O | P1 |

### 3.7 Latency components (observations, not benchmarks; D42)

`lat_render_ms`, `lat_features_ms`, `lat_analyzer_ms`, `lat_det_ms`, `lat_gate_ms`, `lat_dm_ms`,
`lat_classifier_roundtrip_ms` (equal to the decision line's "(classifier N ms)"), `lat_model_ms`
(`model_latency_ms`), `lat_prompt_build_ms`, `lat_tokenize_ms`, `lat_transfer_ms`,
`lat_generate_ms`, `lat_decode_ms`, `lat_gateway_total_ms`. All are floats measured with
`perf_counter`, P1, and required when the component ran. They also carry `device` and
`concurrency_at_arrival` (int). The D36 objective is measured only by its own instrument.

### 3.8 Sampling and labels pointers

| Field | Type | Source | Req | Privacy |
|---|---|---|---|---|
| `sampling_stratum` | str (§5) | sampler | R | P0 |
| `pi_vault` | float (0,1]: inclusion probability into V | sampler | R | P0 |
| `pi_adjudication` | float: π_vault × P(adjudicated \| in V) | sampler | R | P0 |
| `sample_u` | float: HMAC(`k_sample`, `event_id`) / 2^64 (makes the draw reproducible) | sampler | R | P0 |
| `in_vault` / `vault_ref` | bool / opaque id | vault | R / C | P0 / P2 |
| `redactions_applied` | list of enum (`cookie`, `authorization`, `credential_param`, `email`, `pan_luhn`, …) | vault | C | P0 |
| `y_constructed` | enum `attack \| benign` + `y_constructed_source` (generator, paired-dev protocol) | lab only | C | P1 |

## 4. When raw text may be stored (store V)

- **Only sampled records** (§5) and only the D1 text that `/classify` received (headers included),
  because replaying V5 needs the exact input (notes v1 §C: without a vault, V4-era logs cannot be
  replayed for V5).
- **Redaction before writing.** Values of `Cookie`, `Authorization`, `Proxy-Authorization`,
  `Set-Cookie`, and parameters named like `password|passwd|token|secret|api[_-]?key|session|otp`
  are replaced with **length-preserving placeholders**. E-mail addresses and Luhn-valid 13–19-digit
  numbers are masked in every part. `redactions_applied` records what was done.
  - A replay on redacted text is labelled `v_source=vault_replay` and `redacted=true`.
  - Redaction can remove attack evidence (for example, an injection in a cookie). Such records are
    flagged, not silently used.
  - In `privacy_regime=lab` (synthetic traffic, no PII) redaction may be disabled by configuration,
    and that is recorded.
- **Storage.** The vault is encrypted at rest with a per-item data key wrapped by a vault key
  (envelope encryption). It is separate from R and from the repository: never in git, never in
  `/tmp`, never in `reports/`. Access is role-bound (named adjudicators and the replay job), and
  every read is logged with who, when and which `event_id`.
- **Retention:**
  - un-adjudicated items: **90 days**;
  - adjudicated items promoted into a frozen routing dataset: the dataset's declared life, at most
    **24 months**, with owner approval;
  - deletion by destroying the item key (crypto-shredding).
  - R records: 180 days, or the dataset life if they are promoted.
  - These periods are proposals for the owner.
- **Never exported.** Adjudicators view items in place; reports quote no raw text (copy rule,
  D42-style aggregate reporting).

## 5. Sampling design (vault and adjudication)

- **R: no sampling** (π = 1).
- **V and A: stratified Poisson sampling** with a **keyed, reproducible Bernoulli draw**: include
  the record iff `sample_u < π_stratum × π_flood`.
  - The key prevents an attacker from steering what gets sampled.
  - `π` is fixed by `sampling_design_version` **before** the epoch.
- **Strata** use only quantities known at request time, plus the verdict:

| Stratum | Definition | Proposed π_vault | Rationale |
|---|---|---|---|
| S1 `dm_block_cand` | any of `dm_proposed`, B1, B2, B3 = BLOCK | 1.0 (lab) / 0.5 (real) | the cap is estimated here; every benign block matters |
| S2 `conflict_or_ood` | `conflict_any ∨ ¬coverage_ok` | 0.5 | V5-error-prone regions; non-redundancy evidence |
| S3 `v_block` | `v_decision=BLOCK`, not S1/S2 | 0.2 | V5 false positives (the FP-imitation risk) |
| S4 `v_invalid_error` | `v_status ≠ ok` | 1.0 | rare; fail-closed audit |
| S5 `high_score_allow` | `v=ALLOW ∧ analyzer_attack ≥ 0.5` | 0.5 | candidate V5 misses (where deferring is wrong) |
| S6 `rest` | everything else | 0.01 (real) | positivity floor: every region has π > 0 |

- **Flood cap.** Within one `g_client_day`, records after the K-th in a stratum get `π_flood = K/n_k`,
  where `n_k` is the arrival index. That probability is known when the record is drawn, so π stays
  exact. This stops one scanner from dominating the labels.
- **Positivity.** π_min > 0 in every stratum, so Horvitz–Thompson weights `1/π` exist everywhere
  (Horvitz & Thompson 1952).
- **Adjudication subsample.** A fixed fraction of V per stratum, logged into `pi_adjudication`.
- **Estimation.**
  - Any rate over labelled records uses Horvitz–Thompson / Hájek weights.
  - Uncertainty uses a **stratified group bootstrap** that resamples routing groups within strata.
  - Sample-size statements use the Kish effective n = (Σw)² / Σw², never the raw count.

## 6. Ground truth and adjudication (store A)

| Field | Type | Notes |
|---|---|---|
| `event_id`, `adjudication_protocol_version` | | |
| `adj_status` | enum `not_sampled \| queued \| pass1_partial \| pass1_agreed \| disputed \| resolved \| undeterminable` | |
| `pass1_labels` | 2 × {`adjudicator_pseudonym`, `label` ∈ {attack, benign, undeterminable}, `family` (D47), `evidence_location` (sink enum), `time`} | independent |
| `pass2_label` / `pass2_family` | resolution by a third adjudicator, only when pass 1 disagrees | |
| `y` / `y_family` / `y_source` | final; `y_source ∈ {adjudicated, constructed, confirmed_incident}` | `constructed` = lab generator label |
| `blinded_to` | set ⊇ {`v_decision`, `analyzer_attack`, `dm_proposed`, `baselines`} | **required** |
| `agreement_stats_ref` | per batch: Cohen's κ, % undeterminable | |

**Protocol (anti-imitation and anti-leakage):**
- Adjudicators see only the redacted text and a neutral rubric: "executable syntax of family f in a
  sink the backend interprets", with the D47 vocabulary.
- They **never** see V5's verdict or any model score. Otherwise `y` drifts toward `v` and the DM
  learns to imitate V5.
- Undeterminable stays undeterminable. It is excluded from `y`-based metrics and counted.
- External Test v1 cases are never adjudicated into routing data (D40 / D53).
- The paired development diagnostics (#57, #60) are consumed development data. They may seed rubric
  examples but are not routing test data.

## 7. Leakage prevention and data roles (store M)

- **Populations.**
  - The DM population is `dm_population = true`.
  - ROUTING-TRAIN / ROUTING-VAL / ROUTING-TEST are built **only from shadow epochs with frozen
    versions** (same `epoch_id` hashes).
  - `v`-dependent labels are never pooled across V5 versions. `y` labels and the structured evidence
    survive a V5 change, and `v` can be regenerated by vault replay.
- **Temporal split (TESSERACT).** TRAIN < VAL < TEST in time, with an **embargo** of at least
  1 day plus the longest grouping window between blocks.
  - A group that spans a boundary goes to the earlier block, and its later records are dropped from
    the later block and counted. This avoids temporal bias and "future" knowledge (Pendlebury et al.
    2019).
  - Coverage features that use history (`cov_endpoint_seen_before`) use **only prior epochs**.
- **Group split (D54 analogue).** `routing_group` = connected components over "same `g_canon` OR
  shared `g_payload` OR same `g_featvec` OR same `g_client_day`". A group is never split.
  - The builder reports the largest component. If it exceeds 5% of rows (the risk is the
    feature-vector relation on real benign GETs), the owner decides whether to drop that relation;
    this is recorded in M.
  - Lab data adds the generator group (`_gid`, D54).
- **Separation from other models.** M carries, per record:
  - `in_v5_dev`: `g_canon` or `g_payload` ∈ blocklist from V5 TRAIN ∪ VALIDATION ∪ INTERNAL TEST;
  - `in_analyzer_dev`: ∈ `hybrid_analyzer_v2` TRAIN ∪ VALIDATION;
  - `in_analyzer_internal_test`: ∈ V4 eval.
  
  Flagged records are **excluded** from ROUTING-TEST and **reported** in TRAIN / VAL. **One record,
  one role:** a record promoted by D30 deferred validation into a V5 training candidate pool is
  removed from routing pools, and the reverse holds too. M holds that registry.
- **Test discipline (D37 / D54).** ROUTING-TEST is read **once**, after the DM, gates, thresholds and
  baselines are frozen and hashed. If its individual errors guide any change, it becomes development
  data, and the next claim needs a new TEST block.
- **Feature leakage.** Only fields marked DM-in = yes may be inputs. `v_*`, `y*`, `adj_*`,
  `enforced_*`, `http_status`, `forwarded`, all latencies after the DM, `g_*` and `deployment_id`
  never are.

## 8. Schema versioning

- `routing-shadow/vMAJOR.MINOR`:
  - adding an **optional** field → MINOR;
  - adding a required field, or removing or redefining one → MAJOR.
  
  The JSON Schema file is versioned, and its SHA-256 is in every dataset manifest.
- Ingest **rejects** unknown fields, missing required fields, out-of-range probabilities and
  partial category sets, mirroring `hybrid_contracts.py`. Data is never coerced.
- No dataset mixes MAJOR versions. Every dependent version (feature schema, Analyzer, gates,
  verdict model) is pinned per `epoch_id`, and a change starts a new epoch.

## 9. Derivable labels

Notation: `g` = DM action (1 = BLOCK); costs `c_FP` (benign blocked), `c_FN` (attack delivered),
`c_V5` (deferral compute) are **declared before training** (owner).

| Label | Definition | Available when |
|---|---|---|
| `y` | adjudicated / constructed ground truth | A or lab |
| `v`, `v_valid` | V5 decision; `v_status = ok` | always in shadow (V5 runs on 100%) |
| `v_correct` | 1[(v=BLOCK) = (y=attack)] | y ∧ v_valid |
| `block_correct` | 1[y = attack]; the light BLOCK is right | y |
| `v5_miss` | 1[y=attack ∧ v=ALLOW]; deferral would deliver an attack | y ∧ v |
| `v5_fp` | 1[y=benign ∧ v=BLOCK]; the FP-imitation risk | y ∧ v |
| `incremental_harm` | 1[y=benign ∧ v=ALLOW]; a DM BLOCK adds a benign block V5 would not | y ∧ v |
| `loss_block` | c_FP · 1[y=benign] | y |
| `loss_defer` | c_V5 + c_FN · 1[y=attack ∧ v≠BLOCK] + c_FP · 1[y=benign ∧ v=BLOCK]. Invalid or failed V5 counts as fail-closed BLOCK (D34) | y ∧ v_status |
| `defer_value` | loss_block − loss_defer; > 0 means deferring is better | y ∧ v |
| `r_star` | 1[defer_value ≤ 0]; the oracle BLOCK decision | y ∧ v |
| `compute_saved_ms` | lat_classifier_roundtrip_ms if g = BLOCK | always |

- **Not derivable:** an operational attack prevalence beyond "this deployment, this period, under
  this sampling design" (D42).
- **Shadow vs active.** In shadow mode `v` is observed for every record, which is full information.
  When the DM is active, `v` is missing for DM-BLOCKed records. The ε-holdout (`explore_holdout`,
  `logging_propensity`) then supports inverse-propensity and doubly-robust off-policy estimates
  (Swaminathan & Joachims 2015; Dudík et al. 2011). Exploration only ever turns BLOCK into DEFER,
  which costs compute, not safety.

## 10. Baselines (exact definitions)

All baselines act on `dm_population`, output BLOCK or DEFER, and are **frozen with hashed
thresholds** before ROUTING-TEST. Let `p = analyzer_attack`.

| Id | Rule |
|---|---|
| **B0** no DM | always DEFER. Coverage 0; the system risk equals V5's risk |
| **B1** deterministic | BLOCK iff `det_strong_indicator ∧ coverage_ok ∧ ¬conflict_any`. Needs engine A; with no engine A, B1 is undefined and reported as such |
| **B2** Chow threshold | BLOCK iff `p ≥ t₂`, with **t₂ = the smallest threshold on ROUTING-VAL whose group-level one-sided 95% Clopper–Pearson upper bound of β (below) is ≤ α**. With a perfect V5 and costs, Chow's form is BLOCK iff `(1−p)·c_FP < c_V5`, i.e. `p > 1 − c_V5/c_FP`. The cap form is used instead because it does not need a deployment prior: a monotone prior shift changes `p` but not the ranking, so the cap-selected threshold is prevalence-free |
| **B3** Chow + coverage gate | BLOCK iff `coverage_ok ∧ p ≥ t₃`, where t₃ is re-selected by the same rule on the gated population |
| **B3c** | B3 ∧ ¬conflict_any |
| *B_imit* (negative control) | the same model class as the DM, trained on `v` instead of `y`. It shows the cost of imitation and is not a target |
| *Oracle* (upper bound) | `r_star` |

## 11. Evaluation

**Metrics.** Use HT-weighted estimates with stratified group-bootstrap 95% CIs.

| Quantity | Definition | Notes |
|---|---|---|
| attack coverage τ | P(g=1 \| y=attack) | primary benefit |
| benign-block rate β | P(g=1 \| y=benign) | **cap, against `y`**. Blocking a benign that V5 also blocks still counts, so the DM gets no credit for imitating a V5 false positive |
| incremental benign blocks β_inc | P(g=1 ∧ v=ALLOW \| y=benign) | secondary |
| DM-alone risk–coverage curve | selective risk P(y=benign \| g=1) vs coverage P(g=1), swept over the score (El-Yaniv & Wiener 2010; Geifman & El-Yaniv 2017) | prevalence-dependent, so it is labelled with the test's class mix (D42) |
| **AURC** | the area under that curve (Geifman et al. 2019) | |
| **system deferral curve** | system loss of (DM + V5) vs the V5-call rate | the right curve for learning to defer, because DEFER hands the request to V5 rather than abstaining (Narasimhan et al. 2022). Its area is reported as **system-AURC** |
| class-conditional curve | τ vs β (prevalence-free) | the operating point is read here |

**Pre-registered win criteria (template; the numbers are owner placeholders).** The DM is adopted
only if **all** hold. Otherwise the best feasible baseline among B1/B3/B3c is adopted, or B0.

- **W1 cap.** On ROUTING-TEST, β upper bound (one-sided 95% Clopper–Pearson on Kish n_eff of
  independent benign groups) ≤ α, with α declared, for example 1%.
- **W2 benefit.** τ(DM) − max(τ(B1), τ(B3), τ(B3c)), each at its own W1-feasible point: the lower
  bound of the paired stratified group-bootstrap 95% CI must be > Δ_min, for example 0.05 absolute.
- **W3 system non-inferiority.** P(attack delivered \| y=attack) for DM+V5 ≤ the same for B3+V5 + δ
  (CI upper bound).
- **W4.** The system-AURC difference DM − B3 has a CI entirely below 0.
- **W5 non-redundancy (Jitkrittum et al. 2023).** On ROUTING-VAL, within deciles of calibrated `p`,
  the DM's other inputs predict `defer_value`. The test is pre-declared, for example a
  likelihood-ratio test with p < 0.01. If they do not, Chow (B2/B3) suffices and no DM is trained.
- **W6 temporal stability.** W1 and W2 hold in each of ≥ 2 successive TEST time blocks, not only on
  average (TESSERACT).
- **W7 sample adequacy.** The minimum independent groups (below) are met **before** reading TEST.
  Enough V5-error groups exist for W5; the events-per-parameter logic follows Riley et al. 2020
  (cited from notes v1, not re-verified here).
- **W8 auditability.** Every DM BLOCK is explained by logged evidence fields. The model is exported
  and hashed.

**Sample size** (one-sided 95% Clopper–Pearson; computed with scipy `beta.ppf`, 2026-10-06):

| Cap α | 0 errors | 1 error | 3 errors | 5 errors |
|---|---|---|---|---|
| 1% | n ≥ 299 | ≥ 473 | ≥ 773 | ≥ 1,050 |
| 0.1% | n ≥ 3,000 | ≥ 4,750 | ≥ 7,760 | ≥ 10,520 |

- Here n means **independent benign routing groups, Kish-effective**, not rows. A scanner flood is
  one group.
- The rule of three (3/n for zero events; Hanley & Lippman-Hand 1983) matches the 0-error column.
- Reaching n benign groups **in the BLOCK region** is what matters, because the cap's numerator
  lives there. That is why stratum S1 is sampled at π close to 1.
- **Value bound.** τ is bounded by the share of attacks among non-fast-path traffic. The DM's
  compute saving is ≈ prevalence × τ × V5 cost. Its main value is resilience under scanner floods,
  not average latency (notes v1 §C).

## 12. Observations (not changes)

1. `classifier_api.py:149-150` logs `raw[:200]` of invalid model outputs. On real traffic that can
   quote request content. Under §2 the routing record stores only `v_status=invalid` and token
   counts.
2. The decision line logs `pretty_host:port` and the path without the query
   (`data_plane.py:246`). The path can contain identifiers. This is fine for lab operational logs,
   but the routing record keeps neither.
3. `hybrid_contracts.DecisionOutput` has `ALLOW/BLOCK/UNCERTAIN` and a `confidence` field. The
   designed DM is BLOCK/DEFER, and D50 rejects invented confidences, so the contract will need a
   decision before a DM is built.
4. `v_logp_first` does not exist in `/classify` today. It would be a new, versioned response field.

## 13. Sources

| Ref | Year | Link | Claim used |
|---|---|---|---|
| Chow, "On optimum recognition error and reject tradeoff", IEEE T-IT 16(1):41–46 | 1970 | doi:10.1109/TIT.1970.1054406 (Crossref-checked) | optimal reject = threshold on posterior; error–reject trade-off |
| El-Yaniv & Wiener, JMLR 11:1605–1641 | 2010 | https://jmlr.org/papers/v11/el-yaniv10a.html | risk–coverage trade-off |
| Geifman & El-Yaniv, "Selective Classification for Deep Neural Networks", NeurIPS | 2017 | https://arxiv.org/abs/1705.08500 | thresholded selective classifier with a risk guarantee |
| Geifman, Uziel & El-Yaniv, ICLR | 2019 | https://arxiv.org/abs/1805.08206 | AURC as a summary of risk–coverage |
| Mozannar & Sontag, "Consistent Estimators for Learning to Defer to an Expert", ICML | 2020 | https://arxiv.org/abs/2006.01862 | classifier + rejector with an expert; consistent surrogate |
| Narasimhan, Jitkrittum, Menon, Rawat & Kumar, "Post-hoc estimators for learning to defer to an expert", NeurIPS | 2022 | https://proceedings.neurips.cc/paper_files/paper/2022/hash/bc8f76d9caadd48f77025b1c889d2e2d-Abstract-Conference.html | post-hoc deferral: defer when base error probability exceeds expert cost |
| Jitkrittum et al., "When Does Confidence-Based Cascade Deferral Suffice?", NeurIPS | 2023 | https://arxiv.org/abs/2307.02764 | confidence deferral fails with specialist experts, label noise, shift → W5 |
| Pendlebury et al., "TESSERACT", USENIX Security | 2019 | https://www.usenix.org/conference/usenixsecurity19/presentation/pendlebury | spatial / temporal bias; time-consistent splits |
| Arp et al., "Dos and Don'ts of Machine Learning in Computer Security", USENIX Security | 2022 | https://www.usenix.org/conference/usenixsecurity22/presentation/arp | sampling bias, data snooping, label inaccuracy, base-rate pitfalls |
| Horvitz & Thompson, JASA 47(260):663–685 | 1952 | doi:10.1080/01621459.1952.10483446 | unbiased estimation under unequal inclusion probabilities |
| Swaminathan & Joachims, JMLR 16:1731–1755 | 2015 | https://jmlr.org/papers/v16/swaminathan15a.html | propensity-weighted learning from logged actions |
| Dudík, Langford & Li, ICML | 2011 | https://arxiv.org/abs/1103.4601 | doubly robust off-policy evaluation |
| Clopper & Pearson, Biometrika 26:404–413 | 1934 | doi:10.1093/biomet/26.4.404 (Crossref-checked) | exact binomial bounds |
| Hanley & Lippman-Hand, JAMA 249(13):1743–1745 | 1983 | (DOI not checked) | rule of three |
| Angelopoulos et al., "Conformal Risk Control", ICLR | 2024 | https://arxiv.org/abs/2208.02814 | risk-control guarantee is exchangeability-bound; weak under lab→deployment shift |
| NIST SP 800-122 (McCallister, Grance, Scarfone) | 2010 | doi:10.6028/NIST.SP.800-122 | context-based PII confidentiality levels and safeguards |
| NIST SP 800-188 (Garfinkel et al.) | 2023 | doi:10.6028/NIST.SP.800-188 | de-identification techniques and governance; limits of traditional de-identification |
| NIST SP 800-57 Pt 1 | — | https://csrc.nist.gov/pubs/sp/800/57/pt1 | cryptoperiods limit exposure → key rotation (revision not pinned: **UNVERIFIED** which revision is current) |
| RFC 2104 / FIPS 198-1 | 1997 / 2008 | https://www.rfc-editor.org/rfc/rfc2104 | HMAC construction (years from memory: **UNVERIFIED**) |
| Regulation (EU) 2016/679 (GDPR) Art. 4(5) | 2016 | https://eur-lex.europa.eu/eli/reg/2016/679/oj | pseudonymised data remains personal data (not re-checked: **UNVERIFIED** wording) |
| Riley et al., BMJ | 2020 | (as cited in notes v1) | sample size for prediction models (**not re-verified**) |

NIST SP 800-107 Rev. 1 (HMAC truncation) has been proposed for withdrawal (CSRC news, 2022). The
128-bit truncation here is justified only by collision probability, not by that document.
