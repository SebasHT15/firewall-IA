# V5 / Hybrid research notes v1 (2026-10-06)

**RESEARCH NOTES, not decisions, not results.** These are condensed findings of four read-only
research subagents run alongside `benign-coverage-audit-v1`. No dataset was downloaded or
integrated, no model was trained or run, and no file outside this note was changed by them.
Claims that could not be verified online are marked **UNVERIFIED**, and any decision they suggest
is an owner decision that has **not** been taken.

## A. External data sources (priority: realistic benign traffic)

The Phase 2A survey (`reports/hybrid/phase2a-analyzer-design/`) was re-evaluated:

| Source | Change |
|---|---|
| SR-BH 2020 | downgraded. X-WAD (Bitussi & Doriguzzi-Corin, arXiv 2608.27172, 2026) reports ≈ 13.8% mislabeled rows; its "Normal" side is contaminated, and it is WordPress, mostly GET |
| ECML/PKDD 2007 | evaluation only (values randomized) |
| CRS regression tests, GoTestWAF | small fixtures; evaluation only |
| CSIC 2010, TORPEDA, Kaggle re-packs, CIC-IDS2017 | remain REJECT |

New candidates, ranked for benign realism:

1. **open-appsec WAF Comparison Project — Legitimate Requests** —
   [repo](https://github.com/openappsec/waf-comparison-project) ·
   [docs](https://docs.openappsec.io/references/waf-comparison-project).
   - **Status: STRONG CANDIDATE, conditional.**
   - Apache-2.0 per its README.
   - About 1.04 M full requests (method, URL, headers, body) from recorded human browsing of 692
     real sites. The zip is about 1.2 GB / 7.3 GB uncompressed (sizes measured from the ZIP
     directory only).
   - **Content UNVERIFIED** (not inspected): likely cookies/tokens/PII from sign-up flows and
     many third-party beacons/assets.
   - **Blocker:** a privacy audit and filtering (first-party, non-asset, credentials stripped)
     before any use. It is a public FPR benchmark, so training on it removes its value as an
     independent evaluation.
2. **Real API specifications as generator input**.
   - **Status: STRONG CANDIDATE.**
   - Sources:
     - [GitHub REST description](https://github.com/github/rest-api-description) (MIT);
     - [Stripe OpenAPI](https://github.com/stripe/openapi) (MIT);
     - [APIs.guru](https://github.com/APIs-guru/openapi-directory) (CC0 for contributed specs;
       fetched specs are under "fair use", so check per spec; skewed towards Azure/Google);
     - [octokit/webhooks payload examples](https://github.com/octokit/webhooks) (MIT; deprecated
       in favour of octokit/openapi-webhooks).
   - They cover exactly the measured multi-key / nested / numeric JSON gap. No leakage with V4.
3. **Natural Questions** (Kwiatkowski et al., TACL 2019; CC BY-SA 3.0) as a real free-text value
   corpus for search and note fields.
   - **Status: POSSIBLE.**
   - The share-alike obligation must be assessed.
   - MS MARCO is research-only.
4. **Hard-negative evaluation**: CRS false-positive stages, GoTestWAF false-pos, Vulnbank benign
   ([PositiveTechnologies](https://github.com/PositiveTechnologies/seq2seq-web-attack-detection),
   MIT; single application; generation method UNVERIFIED). **Evaluation only.**
5. **Web Fuzzing Dataset** (Sahin, Zhang & Arcuri, arXiv 2509.01612, 2025, Apache-2.0): 36
   open-source REST apps that could serve as targets for capturing benign traffic.
   - **Status: POSSIBLE.**
   - The fuzzer traffic itself is not realistic benign.

**Attack side, rejected for training:** the mgm WAF Payload Collection / openappsec malicious set
re-packages PayloadsAllTheThings (direct overlap with V4) and is GPL-3.0. The Zenodo CSRF set
(doi:10.5281/zenodo.20555856, 2026) is POSSIBLE for evaluation; its content and method are
UNVERIFIED.

**Gap no public dataset fills.** Labelled, permissively licensed, PII-free benign REST/JSON
traffic from real API clients; hard negatives at scale (apostrophe names, `#` addresses, prose
with SQL homonyms, webhook URLs, encoded paths); paired benign/attack on the same schema.
**A schema-driven generator (2) with real values (3) is unavoidable; (1) is an optional realism
anchor.**

## B. Analyzer v3 — candidate designs (none chosen)

**Diagnosis.** v2 fails by representation, not capacity:
- raw-encoding counts;
- no lexical view;
- the same data, labels and objective as V4;
- header-blind;
- an endpoint-driven category head.

Complementarity needs another view of the input (decoded values per field, bounded semantic
headers), another inductive bias (family grammars/lexers) and **another objective** ("does this
value contain executable syntax of family f?", per value, not "would V4-clean say BLOCK?").

**Shared deterministic base:**
- A backend-faithful parser: query, form, JSON leaves, multipart, minimal XML, cookies. Parse
  anomalies count as evidence; WAFFLED (Akhavani et al., ACSAC 2025, arXiv 2503.10846) showed
  1,207 WAF bypasses via parsing discrepancies.
- Bounded multi-layer decoding in the style of ModSecurity transformations. **Decode depth is
  reported as separate evidence and never fed to the family detectors.**
- Metamorphic acceptance tests with the held-out D15 transforms.

| Design | ML | Strengths | Risks |
|---|---|---|---|
| **A — deterministic evidence engine** (libinjection SQLi/XSS, BSD-3; normalized traversal; shell metachar in context; URL parse for SSRF/redirect incl. decimal/hex IPs; SSTI delimiters) | none | interpretable, encoding-invariant, best embedded portability, mechanism different from the LLM | recall on novel syntax; rule false positives; D9 says no CRS now, so a CRS-*inspired* evidence set needs an explicit decision; CSIC labels are keyword rules (circular evaluation) |
| **B — A + small per-value lexical model** (token-class and char-class n-grams, feature hashing 2^12–2^14; L1-logistic or small GBDT per family; no path, no learned parameter names, no raw-encoding features) | small | recall on variants; calibratable; precedent ModSec-Learn (Montaruli et al., DCAI 2024) and ModSec-AdvLearn (Floris et al., IEEE TIFS 2025, doi:10.1109/TIFS.2025.3583234) | re-learning generator artifacts if positives come from PayloadsAllTheThings with V4's renderer; benign values are the bottleneck; adversarial mutation (WAF-A-MoLE, Demetrio et al., SAC 2020) |
| **C — benign profile / anomaly** (per-attribute models, Kruegel & Vigna CCS 2003; Anagram n-gram Bloom filters, RAID 2006; PAYL, RAID 2004) | unsupervised | most complementary to the LLM; best OOD signal | needs weeks of real benign traffic per deployment (not available); profile poisoning; drift |

**Ranking:** B built in stages (A first, then the learned layer only if it beats A on
pre-registered criteria) > A alone > C. The cheap part of C (n-gram Bloom novelty, length
profiles) is worth adding as a coverage indicator.

**Deciding evidence (development data, then External v2):**
- error diversity vs V4 (double-fault / Q statistic, Kuncheva & Whitaker 2003);
- paired separation;
- metamorphic invariance;
- behaviour on hard benign;
- risk-coverage utility for the decision stage;
- latency and memory on target hardware.

**Answers:**
- **Category head:** drop it. Replace it with multi-label per-family evidence.
- **Training data:** use a **different objective and data** from V5, with positives grouped by
  decoded canonical payload and sources other than PayloadsAllTheThings where licences allow
  (licences UNVERIFIED).
- **Header indicators** (JWT structure / `alg`, Fetch-Metadata, smuggling framing per RFC 9112)
  each need a new decision revising D44. Origin must be compared with the *configured deployment
  origin*, never with `Host`.
- **Embedded export:** Treelite C99 export for HGB is documented. m2cgen HGB support and
  Isolation Forest export are UNVERIFIED.

## C. Decision Model — selective BLOCK / learning to defer

- **With BLOCK-or-DEFER only, the learnable part is the rejector.** If V5 were perfect, the
  optimal rule is Chow's threshold on P(attack | x) (Chow 1970). The DM is non-redundant only if:
  - V5's errors depend on x in ways P(attack) does not summarize; or
  - P(attack) is unreliable in identifiable regions (coverage, conflict).
  
  Jitkrittum et al. (NeurIPS 2023) characterize when confidence-based deferral fails.
- **Post-hoc / plug-in**, not end-to-end L2D surrogates (Narasimhan et al. 2022; Mozannar et al.
  2023).
- **Two labels per routing example:**
  - adjudicated ground truth `y`, the safety target;
  - V5 verdict `v`, used only for the value of deferring.
  
  Training on `v` imitates V5's false positives.
- **Operational form:** maximize light-BLOCK coverage of attacks subject to a cap on
  P(light BLOCK | benign). This is prevalence-free (D42; Axelsson 2000).
- **Coverage/OOD signals act first as hard DEFER gates, not learned features.**
- **Baselines the DM must beat:**
  - **B0:** no DM;
  - **B1:** deterministic policy (strong family indicator in a natural sink ∧ in coverage ∧ no
    conflict);
  - **B2:** Chow threshold;
  - **B3:** B2 plus the coverage gate.
- **ML only if all of these are pre-registered and met on ROUTING-VAL:**
  - a non-redundancy test conditioned on the calibrated score;
  - enough independent error groups (Riley et al., BMJ 2020);
  - a paired group-bootstrap gain over B1/B3;
  - material value;
  - auditability.
- **Value is bounded by attack prevalence.** Light BLOCK only saves V5 calls on attacks; its main
  value is resilience to scanner floods.
- **Sample sizes with zero errors** (rule of three): a benign cap of 1% needs ≥ 300 independent
  benign groups; 0.1% needs ≥ 3,000. Conformal risk control (Angelopoulos et al., ICLR 2024)
  applies formally but gives only test-specific guarantees under the shift between the lab and
  future traffic.
- **Routing sets:**
  - ROUTING-TRAIN / VAL / TEST, disjoint from V5's and the Analyzer's sets;
  - grouped like D54;
  - temporal split for shadow data (Pendlebury et al., USENIX Security 2019);
  - population = requests **not** eligible for the fast path.
- **Prerequisites before training:** frozen V5, Analyzer, evidence schema and fast-path policy;
  owner decisions on D29/D43 (any model-free BLOCK) and D44 (headers); declared costs or cap.
- **Shadow logging to start now:** structured JSONL per request with:
  - identity and provenance;
  - all versions and hashes;
  - HMAC grouping keys;
  - the full evidence vector;
  - fast-path eligibility and hypothetical decision;
  - B1–B3 hypothetical decisions;
  - verdict with first-token log-probs and generated tokens;
  - latencies;
  - enforcement (L1/L2/L3);
  - sampling stratum and **inclusion probability**;
  - a pointer to an access-controlled raw-text vault (sample only);
  - a separate blind, two-pass adjudication record.
  
  Without the raw-text vault, V4-era logs cannot be replayed for V5 targets.
- **Feedback bias once active:** keep a small random holdout ε where a DM BLOCK becomes DEFER,
  with its propensity logged. Deferring costs compute, not safety.

## D. Verdict-only decoding for V4 — design (not executed)

- **Correction to an earlier claim in this conversation.** Inside the real prompt the verdict
  tokenizes as `AL`(1964) `LOW` / `B`(29933) `LOCK`, not `▁ALL` / `▁B`. Checking only the first
  token (or the first two) does **not** preserve decisions by construction. Examples:
  - `ALLOW BLOCK | x` parses as BLOCK today;
  - `ALLOWED | x` and `ALLOW |` are invalid today.
- **Recommended:** greedy generation with a stopping criterion that stops once the decoded text
  matches `^\s*(ALLOW|BLOCK)\b\s*\|\s*\S`. That prefix fixes `parse_prediction`'s result
  whatever follows.
  - Canonical outputs stop at 4 tokens.
  - Any other prefix continues to EOS and is parsed exactly as today.
  - **Decision and invalid parity are preserved by construction.**
  - `parse_prediction` / `EXTRACT_RE` are untouched.
- **Measured offline from `baseline-local-v1` samples:**
  - ALLOW: 9,579 cases, always 13 generated tokens, P50 251.0 ms / P95 271.8 ms. ALLOW is the
    slow path.
  - BLOCK: 9,039 cases, 9–13 tokens, P50 192.9 / P95 250.6 ms.
  - Every ALLOW reason in predictions, train and eval is the same constant sentence.
- **Fail-closed today:** the control plane returns 200 with `status: invalid`; the data plane
  turns that into 503 (`data_plane.py:163-166, 207-208`). Unchanged by the design.
- **Changes:**
  - `inference_core`: `decoding="full"|"verdict_prefix"`, default `full`; `stop_reason`
    replaces `stopped_on_eos`.
  - Benchmark: new experiment identities (`v4-full-local-v2`, `v4-verdict-prefix-local-v1`;
    `baseline-local-v1` stays immutable).
  - Paired ABBA in one process, then interleaved formal runs.
  - **Parity criterion:** 100% identical decisions on the V4 eval split (latency workload only,
    labelled as such) and on development sets. Any mismatch is blocking.
  - The ALLOW reason is not generated; the BLOCK reason is generated asynchronously with a
    re-check.
  - Evaluation (D19) stays `full`.
  - A new DECISIONS entry is needed (draft wording in the subagent report; not written).
- **Hypothesis, not a result.** About 66% fewer forward passes; P95 pipeline perhaps around
  100–120 ms on this GPU. This extrapolates beyond the observed 9–13 token range.
- **On llama.cpp / CPU, prefill may dominate**, so measure `prompt_ms` and `predicted_ms`
  separately, reuse the fixed-prefix KV cache, and **do not use GBNF grammars** in parity mode
  (they can turn invalids into decisions).

## Sources

The subagents' reports list full URLs. Key references, as cited by them:
- Chow 1970 (doi:10.1109/TIT.1970.1054406)
- Geifman & El-Yaniv 2017
- Mozannar & Sontag 2020
- Narasimhan et al. 2022
- Jitkrittum et al. 2023
- Angelopoulos et al. 2024
- Axelsson 2000
- Arp et al. 2022
- Sommer & Paxson 2010
- Kruegel & Vigna 2003
- Wang et al. 2006 (Anagram)
- Montaruli et al. 2024
- Floris et al. 2025
- Akhavani et al. 2025
- RFC 8725
- RFC 9112
- Kwiatkowski et al. 2019

**UNVERIFIED as noted:**
- Wolpert 1992 venue;
- Clopper–Pearson 1934;
- m2cgen HGB support;
- Isolation Forest C export;
- CRS/GoTestWAF licences;
- the open-appsec content;
- whether mitmproxy de-chunks bodies before `render_request`.
