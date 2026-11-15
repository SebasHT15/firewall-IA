# Fast Path — contract and shadow-only implementation (PROPOSED)

**Status:** PROPOSED; no decision record exists yet. Implementation integrated for shadow-only evaluation.
Shadow only: the Fast Path observes and never changes what V4 decides or what is enforced. It adds no ALLOW path.
Integrated on `feat/v5-data-readiness`; the original development worktree is retained locally for recovery.

Target pipeline (corrected): validated canonical request → **Fast Path (FAST_ALLOW | CONTINUE)** → Analyzer C1 (+ optional
C2, evidence only) → Model 2 (BLOCK | DEFER) → V5 (ALLOW | BLOCK). ALLOW can come only from the Fast Path or from V5.

## 1. What was inspected before defining eligibility

- `data_plane/canonical_request.py` (`canonical-request/v1`): the canonical text carries **method, target and
  `Content-Type` only**; every other header is invisible to it and to the models (D44/D57), but **V4 reads them** (D1
  text). Its R1 (wire framing) is **explicitly not verified** there: "R1 stays UNVERIFIED as a project control until the
  wire-level tests at integration". Its `Limits` values (max decoded body, token budget B, bytes/token) are **PENDING**
  (spec §11.2) and have no defaults. It is **not integrated**: a test (`test_gateway_and_v4_untouched_by_contract`)
  forbids the gateway from importing it (D56).
- `data_plane/data_plane.py`: V4 decides every request, fail-closed (D4/D25/D34). The feature extractor (D43),
  Fast Path observation and isolated Analyzer observation run after the V4 verdict. Both new shadow modes ship off.
- D57: "A policy that depends on application context (…) must state that context explicitly"; mitmproxy's built-in header
  validation is third-party behaviour the project neither pins nor tests, so it is not a project control.
- D29/D30: any fast ALLOW must be allow-only, never BLOCK, and be measured against the model (D30 deferred validation).

## 2. Contract

```
evaluate(FastPathInput, Policy | None) -> FastPathDecision
FastPathDecision.decision ∈ {FAST_ALLOW, CONTINUE}        # no BLOCK exists
FastPathDecision.enforced is always False                 # shadow-only; True is rejected at construction
FAST_ALLOW carries a rule id and no reasons; CONTINUE carries ≥ 1 reason from a closed list (30 codes)
```
- **CONTINUE whenever eligibility cannot be established.** `safe_evaluate` converts any error, wrong type or malformed
  input into `CONTINUE(EVALUATION_ERROR)`. No path returns FAST_ALLOW by default.
- **No score, weight or threshold** exists in the module (a test scans its public names).
- **Absence of suspicious features is not evidence.** FAST_ALLOW needs positive, closed-world evidence: the request must
  match, completely, a rule of an **owner-supplied policy** that declares the application context. No policy or no
  full match ⇒ CONTINUE.

### Evaluation order (protocol validation first)
1. **Prerequisites** (all unmet ones are reported together; rules are not consulted until none is unmet):
   policy present; framing evidence `VERIFIED`; a `canonical-request/v1` result present and `ACCEPT`.
2. **Exclusions drawn from the canonical result:** any canonical signal; target form ≠ origin-form; any content
   coding other than identity; any Transfer-Encoding; size not `WITHIN_BUDGET`; the canonical result must describe *this*
   request (method and target compared).
3. **Policy rule match** (first rule that matches the whole request ⇒ FAST_ALLOW; none ⇒ `NO_RULE_MATCHED`).

### Conservative eligibility conditions (v1; every one must hold)
| Area | Condition |
|---|---|
| Methods | `GET` or `HEAD` only (a policy naming any other method is rejected) |
| Body | none (`BODY_PRESENT` otherwise) |
| Target | origin-form; ASCII printable only; no `%`; no `#`; no `//` start; exact segment match (no dot-segment can match) |
| Path | each segment is a literal or a grammar: `enum` (exact strings) or `uint` (≤ 9 digits, no leading zero) |
| Query | every parameter declared; none repeated; exactly one `=`; no empty pair; required ones present; value matches its grammar |
| Headers | **every** header name must be listed with a closed value grammar; repeats and unlisted names (Cookie, Referer, X-Forwarded-For, User-Agent, Content-Length…) ⇒ ineligible. `Transfer-Encoding`, `Content-Encoding`, `Upgrade`, `Expect`, `TE`, `Trailer`, `Proxy-Authorization` cannot be listed |
| Version | listed in the policy (`HTTP/1.1` default) |
| Canonical | `ACCEPT`, no signals, identity coding, no TE, within budget, matches the request |
| Framing | `VERIFIED` by a project-owned wire-level control |

Deliberately **not** offered: alphabet classes ("alphanumeric", "looks like a token"), regexes, JSON/form bodies,
percent-decoding, a score. A value made of letters and digits can still be a command name, a SSRF host or a NoSQL operator
fragment; only an owner-declared closed set or a bounded integer is accepted as positive evidence.

### Policy (`fast-path-policy/v1`, JSON)
Fields: `schema`, `policy_id`, `status` (`PROPOSED` | `APPROVED` with `approval.{approved_by,date,decision_ref}`, the D66
pattern), `canonical_contract` (must equal `canonical-request/v1`), `http_versions`, `rules[]`
(`id`, `methods`, `path[]`, `query{}`, `required_query[]`, `headers{}`). Unknown keys, unknown grammar types, empty or
out-of-alphabet enum values, `max_digits` outside 1..9 are rejected; nothing is partially applied. The policy is
hashed (SHA-256 over canonical JSON) and the hash is logged. **No deployable policy is shipped**;
`tests/fixtures/fast_path_policy_example.json` is a test example only (`policy_id` says so).

## 3. Shadow implementation (`data_plane/fast_path.py`, `data_plane/data_plane.py`, `config.yaml`)

- Stdlib only (D33). **It does not import `canonical_request`**: the three constants it reads are repeated and a test
  compares them with the contract module, so the D56 isolation test still holds.
- Gateway hook runs **after the V4 verdict**, next to the feature extractor: own function, own logger
  (`firewall.data_plane.fastpath`), returns nothing, never raises. V4 is always asked once, with the same bytes.
- Switches (both optional; absent ⇒ off): `data_plane.shadow_fast_path: false`, `data_plane.fast_path_policy_file: null`.
  Shipped **off**. A wrong-typed switch raises like the other settings; an unreadable/invalid policy only logs
  `POLICY_INVALID` (an experimental component never stops the gateway).
- Log line (codes and ids only; no path, query, header value or body):
  `FAST PATH (shadow) FAST_ALLOW (hypothetical; V4 decision unchanged) rule=… policy=id/hash8 v4=ALLOW|BLOCK` or
  `FAST PATH (shadow) CONTINUE reasons=… policy=hash8 v4=…`. `v4=` is context for later analysis, **not a label**.
- **In today's gateway the Fast Path is always ineligible.** `GatewayEvidence` supplies `canonical = None` and
  `framing = UNAVAILABLE`, so every request logs `CONTINUE reasons=…FRAMING_UNAVAILABLE,CANONICAL_UNAVAILABLE` (plus
  `POLICY_UNAVAILABLE` without a policy). That is the intended initial outcome, not a bug.

## 4. Tests actually run

Python 3.12.15 (`.venv-dataplane`, from the main checkout, read-only use) unless stated.

| Suite | Tests | Result |
|---|---:|---|
| `tests/test_fast_path.py` (eligible, prerequisites, exclusions, malformed/ambiguous, decision contract, policy validation, independence from the contract module) | 43 | OK (also OK on system Python 3.14.4) |
| `tests/test_data_plane_fast_path.py` (V4 preserved with the switch on/off, V4 BLOCK / classifier failures stay fail-closed under a hypothetical FAST_ALLOW, 4 decisions × 7 requests identical outcome and classifier input, hook failure ignored, order after verdict, no content in logs, config) | 17 | OK |
| existing `test_data_plane.py` | 36 | OK (1 skipped, as before) |
| existing `test_canonical_request*.py` (incl. the D56 isolation test) | 199 | OK (2 skipped) |
| existing `test_request_features.py` (includes the `hybrid_contracts` tests) | 44 | OK |

Mutation check (scratch copy): 16 mutations of `fast_path.py` (framing gate removed, canonical optional, body/percent/header/
signal/size/target-form checks removed, mismatch ignored, exceptions escaping, `enforced` allowed, POST permitted…) and 5 of
`data_plane.py` (classifier skipped when the switch is on, hook exceptions escaping, hook before the verdict, hook result
overriding V4, request content logged): **all killed, 0 survivors**.
Not run: pytest (not installed here); the full repository suite; any real mitmdump process or live traffic.

## 5. Readiness and remaining dependencies

**Shadow plumbing: ready for owner review. Enforcement: not ready and not authorized.** To make the Fast Path *eligible*
in the gateway (so that it can log a hypothetical FAST_ALLOW on real traffic):
1. **Framing evidence.** A project-owned, pinned and tested wire-level control that checks canonical R1 (CL/TE conflicts,
   duplicate/obsolete forms, bare CR/LF…) for each request and reports `VERIFIED`. The residual framing checks inside
   `canonicalize()` are not enough (the wire form is gone after parsing); mitmproxy's own validation does not count (D57).
2. **Canonical integration.** A mitmproxy-flow → `RequestParts` adapter (received header order and case; HTTP/2 `:path`)
   and a ratified `Limits` (max decoded body, B, bytes/token — all PENDING, §11.2). The gateway may import the contract only
   after the integration decision (D56).
3. **A policy of record.** The application context cannot be invented: someone must declare, per deployment, the
   endpoints, parameter grammars and header values. Without it the Fast Path never says FAST_ALLOW.
4. **Evaluation corpus.** Independently labelled requests including adversarial near-neighbours of each rule (V4 or Analyzer
   agreement alone is not ground truth; D37 data-use rules apply; External v1 is not used).
Before any enforcement: a decision entry, an approved policy, D30-style deferred validation, and the evaluation of §6.

## 6. How a hypothetical FAST_ALLOW is judged (no V4-only ground truth)
- Unit: a FAST_ALLOW on a request whose **independent reference label** is attack (constructive generator provenance,
  paired twin design, audited labels under D67/r4 with their disclosed limits) is a **Fast Path miss**. `v4=BLOCK` beside
  a FAST_ALLOW is a **trigger for adjudication**, not a verdict; `v4=ALLOW` is not evidence of correctness.
- Report: count of FAST_ALLOW, misses with numerator/denominator/set name (D42), coverage (share of reference-benign
  traffic it would skip), per rule; no rate is described as operational.
- The owner decides the tolerated miss level before the evaluation; this document proposes none (0 misses is the natural
  starting position for an allow-only bypass).

## 7. Owner decisions
1. Accept the closed-world, policy-based eligibility model (no score) as the Fast Path basis, and `GET`/`HEAD`/no-body as v1 scope.
2. Who authors and approves a policy, for which application, and where it lives (not in this repository by default).
3. Whether header values may be attested as irrelevant by the owner (v1: every header must be listed with a grammar).
4. The framing-control design (item 1 of §5) and whether `Transfer-Encoding: chunked` GET bodies are ever in scope (v1: no).
5. Ratification of canonical `Limits` and the gateway integration of `canonical-request/v1` (D56 follow-up).
6. The tolerated Fast Path miss level and the evaluation corpus, before any enforcement discussion.
7. Whether the shadow switch may be turned on in the lab (it logs only; it will report `CONTINUE` until 1–2 exist).
