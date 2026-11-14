# sec-challenges applications behind the local stack

**Status (2026-11-14):** the [13 November architecture campaign](../reports/v5/architecture-campaign-2026-11-13/RESULTS.md)
evaluated `fastv5` and `fastv5_guard` with real V5.1, without Model 2, against direct/V5-only/CRS controls.
The earlier [7 November campaign](../reports/v5/challenge-apps-campaign-2026-11-07/RESULTS.md)
and [integration preparation](../reports/v5/challenge-apps-premeasurement-2026-11-05/INFORME.md)
remain separate dated evidence. Traffic is programmed/agent-generated, not human or organic.
The separate [14 November flag-acquisition campaign](#flag-acquisition-campaign-2026-11-14) (h1 only)
is documented below and is not pooled with the architecture metrics.

## Current candidate (2026-11-13)

| Arm | Runtime | Purpose |
| --- | --- | --- |
| `direct` | front to app | Effect-positive and benign delivery control; not a detector |
| `v5only` | `V5_ONLY`, V5.1 | Model-only reference |
| `fastv5` | `FAST_PATH_V5`, Model 2 absent | Public-resource Fast Path ablation |
| `fastv5_guard` | `FAST_PATH_V5`, Model 2 absent | Candidate; adds `request-header-sink-guard/v2` only for Inf3ct |
| `crs` | ModSecurity + CRS 4.25.2 PL1 | Conventional comparator |

The current manifest is [manifest.EXPERIMENTAL.json](../reports/v5/fastv5-2026-11-11/manifest.EXPERIMENTAL.json).
`config` generates public-v3 policy and pins the complete app/image/manifest identities.
The candidate arms enable Fast Path automatically; the default audit rate is 0, as in the final campaign.
The historical `guarded` and `guarded_fast` arms below retain their original Model 2 behavior.

After [building the pinned app/front/CRS images](#reproducible-commands), configure a new run:

```bash
.venv-dataplane/bin/python scripts/local_stack/challenges/challenge_stack.py config --app Inf3ct --arm fastv5_guard --out /tmp/inf3ct.fastv5-guard.json
```

This writes a new config and adjacent policy/guard files and refuses existing output files.
Use a fresh private work directory outside the repository. A CPU smoke can start the configured arm
with `--v5 double`; this verifies mechanism only. Real-model evaluation needs the pinned adapter,
profile, and the documented exclusive GPU hand-off:

```bash
.venv-dataplane/bin/python scripts/local_stack/challenges/challenge_stack.py up --app Inf3ct --arm fastv5_guard --config /tmp/inf3ct.fastv5-guard.json --work <new-private-directory> --v5 real
```

Use `status`, `down` and `check-clean` with that same `--work` directory, as documented below.
Do not start a stack while Claude owns Docker, ports or GPU for the flag campaign.

Primary results: 789/985 benign V5 calls avoided at rate 0; 169/172 complete benign sessions;
63/65 eligible attack effects prevented. These are scoped effect results, not six flag-retrieval results.
The three benign FP and two stored-HTML-header effects remain in the report.

## Flag-acquisition campaign (2026-11-14)

A separate campaign measured, over `h1_tls_new` only, whether each app's flag can be obtained over
HTTP and whether the architecture prevents it. Report:
[`reports/v5/flag-acquisition-2026-11-14/run-1/`](../reports/v5/flag-acquisition-2026-11-14/run-1/RESULTS.md)
(PROTOCOL, RESULTS, METRICS.json, metrics_table.csv, EVIDENCE_INDEX.json, HANDOFF_CODEX.md,
CLEANUP_GPU.json). It is **not** merged into the 13 November architecture metrics or denominators.
Raw cases/runs are private, outside Git; the evidence index carries their SHA-256.

Method: draft each sequence against `direct`, confirm the full flag/credential string over HTTP
(oracle `body_contains`), `trial.py seal` the unchanged cases + direct rows, then replay through
`v5only`, `fastv5`, `fastv5_guard` and `crs` with real V5.1, three repetitions per sequence, clean
state (per-arm stack reseed; Inf3ct's rolling log flushed with benign setup POSTs). Sequences are
constructed from the source-audited mechanism, never from a candidate verdict.

| App | Flag objective | Method | Direct | Candidate `fastv5_guard` | Prevention | Stage |
| --- | --- | --- | --- | --- | --- | --- |
| An0nB0ard | credential disclosure; separate admin flag | SQLi read; independent login with fixed credential | 3/3 each | 0/3 credential; 3/3 login flag | credential only | V5 (SQLi); login allowed |
| CatP1cs | `/flag.txt` (placeholder) | path traversal via `/show?img=` | 3/3 | 0/3 | yes | V5 (traversal) |
| Inf3ct | `/flag.txt` (placeholder) | header SSTI → `GET /log` | 3/3 | 0/3 | yes | `request_guard` (not V5) |
| D33pTh0ught | real AES-GCM flag | legitimate `answer=42` | 3/3 | 3/3 allowed | legitimate — correctly allowed | application |
| ObC00ki3s | client-side flag | n/a (browser only) | n/a | n/a | n/a — no HTTP acquisition | — |
| ag3ncy | real AES-GCM flag | legitimate password (unknown) | n/a | n/a | n/a (not retrieved) | — |

Prevention of three exploit primitives (denominator 9 = 3 primitives × 3 reps): `fastv5_guard` **9/9**;
`v5only`, `fastv5` and `crs` **6/9** each — none stops the header SSTI (it lives in a header, outside
`canonical-request/v1`, and CRS fired no rule). Scorer taxonomy: CatP1cs/An0nB0ard =
`effect_prevented_by_firewall` 3/3; Inf3ct = `PREVENTED_AT_ATTACK` (candidate) vs `PERSISTED` (others).
The candidate's total separates into **6/6 flag retrievals prevented** (CatP1cs/Inf3ct) and
**3/3 credential disclosures prevented** (An0nB0ard). The fixed-credential An0nB0ard login
returns the flag on all arms; a dynamic extraction-to-login chain was not measured. See
[audit corrections](../reports/v5/flag-acquisition-2026-11-14/run-1/AUDIT_CORRECTIONS.md).

Distinctions carried into this campaign:
- The three exploit apps ship the **same placeholder flag**; the result is about the full-string
  retrieval *mechanism*, not three distinct secrets. 9/9 is three repeated sequences — not nine
  independent techniques, not six exploited apps.
- An0nB0ard's **SQLi credential disclosure** (scored exploit, blocked on every firewall arm) is
  separate from the benign admin login with that credential (allowed on every arm); a login with an
  already-seeded credential is not the exploit.
- D33pTh0ught `answer=42` is a **legitimate** retrieval, correctly allowed on every arm.
- ObC00ki3s has no server-side flag; ag3ncy's admin branch is unmeasured (password undetermined).
- The deterministic header guard, not the model, prevents the header SSTI. Effect-prevention (13 Nov)
  and flag-prevention (14 Nov) are distinct measurements with distinct denominators.
- No Model 2 anywhere (`model2_present:false`); audit sampling rate 0; 30/30 runs `clean:true`; GPU released.

## Earlier integration and guarded arms

Package: [`scripts/local_stack/challenges/`](../scripts/local_stack/challenges/). It reuses the leaf
helpers of [`scripts/local_stack/stack.py`](../scripts/local_stack/stack.py); the shared stack also
supports the separately pinned lab Fast Path policy. The fwlab-notes application is unchanged. See
also [`docs/local_stack.md`](local_stack.md).

## Applications repository (pinned in the evidence)

| | |
|---|---|
| Root | `/home/sebas/Documents/Codex/2026-11-02/sec-challenges` (override with `--apps-root` / `$FWLAB_APPS_ROOT`) |
| Branch / commit | `master` / `be8e4e8f1c6aa12a17430146d569870d96d43dd5` |
| Folder | `Web/` (capital **W**) |

Every `up` records the live commit and whether it matches the pin in `<work>/challenge-identity.json`
and in each smoke result. `up`/`build` **refuse** a different commit unless `--allow-commit-drift` is
given (the drift is then recorded). **The applications and their vulnerabilities are kept byte-for-byte
intact**: the package only builds an image from each application's own tree and runs it; it never edits a
file under the applications repository.

## Architecture and arms

```
client ──TLS 1.2/1.3, HTTP/1.1 or HTTP/2──> front: nginx 1.25-alpine (Docker, host loopback :8443)
            one HTTP/1.1 message per request, loopback, plaintext
   arm direct   : front ───────────────────────────────────────────> challenge app
   arm v5only   : front ─> gateway (mitmdump + cascade, V5_ONLY) ─guard─> challenge app
   arm guarded  : front ─> gateway (CASCADE_ACTIVE, Model 2 GUARDED_ENFORCE) ─guard─> challenge app
   arm guarded_fast: guarded + one exact app-bound static Fast Path rule (separate variant)
   arm crs      : front ─> ModSecurity + OWASP CRS ──────────────────> challenge app
                                                   challenge app: Docker, --internal network, NO route out
                                                   (+ MySQL 5.7 sidecar on the same internal net for An0nB0ard)
```

All five variants share the **same** TLS/HTTP-2 front (same image, ciphers, ALPN, body re-framing and header
normalisation) and the **same** application image, so only the layer between the front and the
application changes. The direct arm uses a front variant that proxies straight to the application
([`challenges/front/nginx-direct.conf.template`](../scripts/local_stack/challenges/front/nginx-direct.conf.template));
the cascade and CRS variants reuse the stack's own front and gateway/CRS machinery.

| Arm | `--arm` | firewall | mode | Model 2 | manifest |
|---|---|---|---|---|---|
| application directa | `direct` | none | — | — | — |
| V5.1 solo | `v5only` | cascade | `V5_ONLY` | not enforced | `reports/v5/model2-guarded-2026-11-05/manifest.EXPERIMENTAL.json` |
| V5.1 + Model 2 | `guarded` | cascade | `CASCADE_ACTIVE` | `GUARDED_ENFORCE` (`policy.LAB_EXPERIMENTAL.json`, threshold 0.9, guard `c1-selective-abstention/v1`) | same manifest |
| ModSecurity + CRS | `crs` | crs | — | — | CRS 4.25.2, paranoia 1, anomaly 5/4 |

`v5only` and `guarded` pin the **same** V5.1+Model 2 manifest and differ only by mode, so they are the
exact V5-only / V5+Model 2 contrast. The manifest and the GUARDED_ENFORCE policy are the ones Codex
prepared for the fwlab-notes arms; nothing here selects a model, a threshold or a Fast Path policy, and
nothing is tuned on any final set.

### Optional lab Fast Path on the guarded arm

`config --arm guarded --fast-path` adds a **fifth experimental variant** of the guarded arm. It writes
an app-bound `fast-path-policy/v1` next to the stack config and pins its digest and application contract.
Each policy can `FAST_ALLOW` exactly one `GET` for one static resource at the pinned application commit,
with an exact `Host`, no query, no body and no extra headers. Every other request continues to Model 2
and V5.1. The app and asset must match the pinned source; the front remains the same. `gateway-framing/v1`
supplies per-request egress-bound framing evidence in this lab configuration. This is an active bypass,
not merely a shadow observation, so it must be evaluated as its own arm before any paper claim.

| App | Exact Fast Path resource |
|---|---|
| An0nB0ard | `/static/css/style.css` |
| CatP1cs | `/static/img/favicon.ico` |
| D33pTh0ught | `/static/img/machine.jpg` |
| Inf3ct | `/static/img/anon.png` |
| ObC00ki3s | `/static/js/cks.js` |
| ag3ncy | `/static/img/avatar.png` |

The six app × guarded Fast Path smokes with the V5 double passed. For each app, the exact asset was
delivered with `deciding_stage=fast_path`, `model2=null`, `v5=null`; the same target with `?x=1`
continued to V5. The evidence is in `reports/v5/fastpath-six-apps-2026-11-05/`. Audit sampling is zero
in these integration smokes so a background audit cannot be mistaken for a required V5 decision. A
measurement run must state its audit rate and report audit cost separately. No performance or detection
claim follows from these smokes.

**Integration and attribution use the V5 DOUBLE** (`--v5 double`, default): the double BLOCKs any request
containing the literal word `evil` and ALLOWs everything else, which is enough to prove the pipeline and
the layer attribution. **Quality is never measured with the double**: a real V5.1 needs `--v5 real` and
the documented GPU hand-off (`GPU_STATUS.json`), and belongs to the measurement phase.

## Route and flow map

Internal port = the port the application binds inside its container (reached only via the internal
network / the gateway). Six applications, all Flask dev servers.

| App | Port | DB | Sessions | Vuln class | Effect observable? |
|---|---|---|---|---|---|
| **An0nB0ard** | 1337 | MySQL 5.7 | none issued | SQL injection (string-concatenated queries) | yes — admin page/flag, changed bodies |
| **CatP1cs** | 1337 | — | none | path traversal / local file read (blocklist bypass) | yes — file bytes in the response |
| **D33pTh0ught** | 3030 | — | none | guessable password → AES-GCM flag decryption | yes — flag in the response |
| **Inf3ct** | 1337 | — | none (in-memory log) | server-side template injection (char-filtered) | yes — evaluated template in `/log` |
| **ObC00ki3s** | 5000 | — | client-side cookies only | client-side JS puzzle | **no** — delivery/classification only |
| **ag3ncy** | 5000 | — | none | guessable password → AES-GCM flag decryption | yes — admin page/flag vs error page |

Routes (authoritative source: [`challenges/adapters.py`](../scripts/local_stack/challenges/adapters.py)):

**An0nB0ard** — `GET /` login form · `GET /register` · `POST /login` (username+password; **SQLi** in
`get_password`, admin → flag) · `GET /messages` list posts · `POST /new` create user · `POST /addentry`
(**SQLi** insert) · `GET|POST /post?id=` (**SQLi** in `get_entry`) · `GET /static/css/*`.
*State:* MySQL `members`/`posts`, re-seeded from `members.sql` on every `up` (ephemeral tmpfs).

**CatP1cs** — `GET /` gallery · `POST /` message form (random token id, nothing stored) ·
`GET /show?img=` `send_file('static/img/'+img)`, **traversal** if the substring blocklist
`['./','..','etc','passwd','flag']` (checked against `request.full_path`) is bypassed · `GET /static/img/*`.

**D33pTh0ught** — `GET /` question form · `POST /` `answer` → `PBKDF2(answer)` decrypts the flag if
correct (hint: *the answer to Life…*) · `GET /static/img/*`.

**Inf3ct** — `GET /` message form · `POST /` `msg` filtered (`bad_chars "{'_#&;}"` stripped) and stored
in an in-memory 5-slot log · `GET /log` renders the recent log via `render_template_string` → **SSTI**
sink · `GET /static/img/*`. *State:* in-memory `log_array`, resets on restart.

**ObC00ki3s** — `GET /` index that loads the puzzle JS · `GET /static/js/cks.js` · `GET
/static/js/asking.js` · `GET /static/img/*`. All logic is **client-side**; the server has no exploit
surface, only static delivery.

**ag3ncy** — `GET /` landing · `POST /auth` `password` → decrypts the flag if correct (hint: *may the
force be with you*), renders admin page/flag vs error page · `GET /static/img/*`.

## Reproducible commands

```bash
PY=.venv-dataplane/bin/python
```

Build the images (own Dockerfile where shipped; adapter Dockerfile for D33pTh0ught/ObC00ki3s/ag3ncy that
only installs the pinned requirements and runs the unmodified entry file) and pull the MySQL sidecar:

```bash
$PY scripts/local_stack/challenges/challenge_stack.py build
```

Write a stack config for one application and arm (pins the application image id + the arm's mode/manifest):

```bash
$PY scripts/local_stack/challenges/challenge_stack.py config --app An0nB0ard --arm guarded --out /tmp/an0n.guarded.json
```

For the app-bound experimental Fast Path variant:

```bash
$PY scripts/local_stack/challenges/challenge_stack.py config --app An0nB0ard --arm guarded --fast-path --out /tmp/an0n.fast-path.json
```

Bring it up / inspect / tear down / verify clean (`<work>` MUST be outside the repository):

```bash
$PY scripts/local_stack/challenges/challenge_stack.py up --app An0nB0ard --arm guarded --config /tmp/an0n.guarded.json --work <private dir> --v5 double
```

```bash
$PY scripts/local_stack/challenges/challenge_stack.py status      --work <private dir>
```

```bash
$PY scripts/local_stack/challenges/challenge_stack.py down        --work <private dir>
```

```bash
$PY scripts/local_stack/challenges/challenge_stack.py check-clean  --work <private dir>
```

One-command minimal functional smoke (config → up → benign/reception/attribution checks → down →
check-clean), which writes `smoke-<app>-<arm>.json`:

```bash
$PY scripts/local_stack/challenges/smoke.py --app CatP1cs --arm v5only --v5 double --work <private dir> --evidence <evidence dir>
```

## Isolation

Identical to the fwlab-notes application container. Each application runs on a dedicated `--internal`
Docker network with **no default route** (`up` refuses if the container has one), non-root
(`--user 1000:1000`), read-only root filesystem, every capability dropped, `no-new-privileges`, pids and
memory limits, and a small writable tmpfs. The MySQL 5.7 sidecar is the one exception: its official
entrypoint needs a writable root and a few capabilities (CHOWN/SETUID/SETGID/DAC_OVERRIDE/FOWNER), so it
keeps those, but it is confined to the same internal network with no route out and stores data on an
ephemeral tmpfs, so every run re-seeds from `members.sql`. The gateway reaches only the application; the
application reaches only its own sidecar.

## Attribution of a rejection (challenge apps)

Same three-independent-logs principle as the fwlab-notes stack, with one difference: the challenge
applications emit **no structured application log** (they are stock CTF apps). Reception is therefore
taken from the front access log and the application container's console, not from an application oracle.

| Layer | Evidence |
|---|---|
| front | front access log: nginx answered itself, no `upstream_*` (e.g. 400 on a dot-segment path, 413 over 64 KiB request) |
| firewall (cascade) | gateway decision record `applied: DENY`, no delivery, firewall body; a block on the double is `v5.decision=BLOCK` |
| firewall (CRS) | ModSecurity audit entry (JSON, `RelevantOnly`), `is_interrupted`, with rule ids |
| gateway protocol | mitmproxy refused before the cascade (e.g. CL+TE), no decision record |
| application reception | front access log `upstream_status` set (the app answered) **and** a werkzeug request line in the app container console |

This coarser reception signal (status + access log + container console, no per-request application
oracle) is a **limit** carried into every per-application report.

## Known limits and integration findings

- **Large-response asymmetry resolved for the challenge apps.** The original 64 KiB cascade gateway
  limit produced 502 on ordinary assets while direct and CRS returned 200. Before constructing the
  measurement corpus, the challenge stack fixed `gateway.body_size_limit` to **16 MiB** for both cascade
  arms. The front's request-body cap remains **64 KiB**, and the V5.1 manifest's decoded-body cap remains
  19,920 bytes. A new 24-run matrix at this fixed setting passed; all 16 large-response checks returned
  200 with complete bodies, including CatP1cs `blackcat.gif` (8,106,213 bytes). The earlier 64 KiB
  matrix remains historical evidence of the defect. See
  [`MATRIX.md`](../reports/v5/challenge-apps-premeasurement-2026-11-05/MATRIX.md).
- **64 KiB request cap / `max_decoded_body` 19920.** The front caps request bodies at 64 KiB (413) and the
  manifest caps the decoded body the model sees at 19920 bytes. Benign corpora must fit, or the confound
  must be recorded.
- **ObC00ki3s is client-side only.** The server offers no exploit surface, so for this application only
  *delivery* and *classification* are measurable server-side, never an exploit effect.
- **Two applications are outside the V5 threat vocabulary.** D33pTh0ught and ag3ncy are guessable-password
  crypto challenges, and ObC00ki3s is a client-side puzzle. The V5.1 vocabulary covers SQLi, XSS, path
  traversal, file inclusion, command/SSTI/SSRF/open-redirect/NoSQL/CRLF/XPath injection — so these three
  are expected to pass as benign by design. They exercise **false-positive** behaviour and out-of-scope
  traffic, not detection. SQLi (An0nB0ard), path traversal (CatP1cs) and SSTI (Inf3ct) map onto the
  vocabulary and are the detection-relevant applications.
- **Dev servers.** All six run the Flask development server; absolute latency is not representative (same
  caveat as fwlab-notes).
- **An0nB0ard has no server sessions.** `blog.py` imports `flask.session` but sets no secret key and
  never writes a session; no application issues a server-side auth cookie. Sessions to measure are
  client-side only (ObC00ki3s) — a documented fact, not a gap to fix.

## Attack-effect observability

| App | Observable exploit effect? | What can be measured |
|---|---|---|
| An0nB0ard | **Yes** | SQLi auth-bypass renders the admin page with the (fake) flag; UNION/boolean SQLi changes the body → effect + delivery + classification |
| CatP1cs | **Yes** | a successful traversal returns the target file's bytes → effect (bounded by the 16 MiB gateway response cap) + delivery + classification |
| D33pTh0ught | **Yes** | correct answer renders the decrypted flag → effect + delivery + classification |
| Inf3ct | **Yes** | SSTI output appears in `/log` (textual oracle, no browser execution) → effect + delivery + classification |
| ObC00ki3s | **No (server-side)** | delivery + classification only; the exploit is entirely in the browser |
| ag3ncy | **Yes** | correct password renders the admin page/flag, wrong → error page → effect + delivery + classification |

## Capture, seal and measurement

The governing metric specification is
`/home/sebas/Documents/Codex/2026-11-02/firewall-ia-cierre-pc-paper/outputs/METRICAS_CASCADA_PAPER_2026-11-04.md`.
The trial seal records its SHA-256. A raw case file is private JSONL **outside this repository**. Each
row has opaque `case_id`, `group_id`, `session_id`, app, method, target, label (`ALLOW`, `BLOCK`, or
`UNKNOWN`), independent `label_basis`, family, optional headers/body, and an effect oracle. Agent-run
benign sessions use `label_basis=agent_task`, opaque `generator_id` and `task_id`, and a separate
`L2_AGENT_LAB` seal. They must never be described as human or organic traffic. Public
trial rows contain hashes, closed decision fields and numbers; private stack logs remain under `--work`.
The static-asset `ObC00ki3s` example in the premeasurement report is a two-request *tool dry run*, not
an FPR estimate.

For each app and transport, the order is:

1. Author cases independently, with benign tasks and attack-effect cases grouped by component/session.
   Keep final-test apps, templates and sessions out of training and model selection. No request is
   labeled from a firewall verdict. A status-only oracle is acceptable for a benign delivery check,
   but attack eligibility requires a positive direct effect oracle.
2. Run `trial.py run --arm direct` with that case file and a private `--work` directory. Review direct
   oracles and label basis. Freeze the unchanged file and direct rows with `trial.py seal`. The seal
   records all five configurations, the app commit, the 16 MiB/64 KiB limits, the transport and the
   metric specification hash. A seal is per transport because the paired quality comparison must use
   identical requests and transport.
3. Replay the sealed cases with `trial.py run` for `v5only`, `guarded`, `crs`, and separately
   `guarded_fast`. Real V5.1 arms use `--v5 real --handoff-gpu`; the hand-off is released even on
   failure. The `--integration-double` option is diagnostic only and cannot be scored as quality.
4. Run `score_trial.py` on the direct and real-arm outputs. It requires exact case/label/group/session/
   transport pairs and clean teardown. It also reports Model2 AUROC, average precision, Brier,
   ten-bin ECE and a fixed diagnostic threshold curve where labels permit them. The client records
   TCP connect and TLS handshake time separately for new/resumed sessions. Invalid model
   results are reported separately and penalized by
   true class in the primary matrix; fail-closed denials are never silently called detector TPs.
   Attack effect prevention requires a positive direct control and a firewall denial with no app
   receipt. Sessions with missing or failed oracles are incomplete, not successful.
5. Run `load_trial.py` with read-only, benign, direct-positive case IDs, a predeclared offered rate,
   duration, workers, warmup and SLO. It reports offered/completed/useful rps, P50/P95/P99, client
   queue, gateway/V5 stage waits, queue snapshots and CPU/RAM/GPU samples. Repetitions and arm order
   must be fixed before the campaign. `--restart-front-at-seconds` injects a front restart during
   offered load and records the time/requests to five consecutive useful responses under the SLO.
   Repeated load requests are **not independent quality labels**.
6. Run `fault_trial.py` for app, front, gateway, V5 and Model2 child failures, each in a fresh stack;
   it records impaired status/receipt and time/attempts to clean service after an explicit pinned
   restart. The existing `scripts/local_stack/failure_check.py` separately covers V5 error, malformed
   answer and timeout with the laboratory V5 double. Autonomous recovery and saturation require their
   own declared experiments; a manual restart is labeled as such.

Example (run from the Firewall-IA repository root; paths are deliberately private and unique):

```bash
PY=.venv-dataplane/bin/python
$PY scripts/local_stack/challenges/trial.py run --app ObC00ki3s --arm direct \
  --cases /private/cases.jsonl --transport h1_tls_new \
  --out /new/direct-evidence --work /private/direct-work
$PY scripts/local_stack/challenges/trial.py seal --app ObC00ki3s \
  --cases /private/cases.jsonl --direct-rows /new/direct-evidence/ROWS.jsonl \
  --population L2_SCRIPTED_LAB --out /new/seal
$PY scripts/local_stack/challenges/trial.py run --app ObC00ki3s --arm guarded \
  --cases /private/cases.jsonl --seal /new/seal/SEAL.json \
  --transport h1_tls_new --v5 real --handoff-gpu \
  --out /new/guarded-evidence --work /private/guarded-work
```

The `--out` and `--work` paths must not exist before a run. The app images must already be built.
Formal campaigns should put raw cases, stack logs, labels and reviewer notes in a protected private
area with an agreed retention period; the two-request dry run used only controlled local lab data.

## Campaign prerequisites and interpretation

- Construct the independent six-app case population and predeclare attack effects, legitimate task
  completion, grouping, exclusions, SLO, load ladder, repetitions and analysis plan. The current
  two-request example is too small and not independent enough for a paper claim.
- `An0nB0ard`, `CatP1cs` and `Inf3ct` are detection-relevant for SQLi, traversal and SSTI. The two
  password puzzles and browser-only `ObC00ki3s` mainly stress false positives and out-of-scope input.
- The main causal contrast is `guarded` versus `v5only` with identical V5.1 and cases. Fast Path is
  a separate active policy arm. The policy is `PROPOSED`, so promotion needs its own risk/benefit result.
- These six apps are L2 laboratory applications. Scripted requests are **not traffic from real users**.
  Browser tasks run by Claude are **agent-generated laboratory traffic**, even when the browsing
  resembles a person's path. Human tasks need actual participants. Organic population R requires a separately authorized app or
  logs, a privacy/retention plan and a shadow-first collector; no R metric can be inferred here.
- The Flask development servers and limited lab app behavior constrain performance generalization.
