# Flag-acquisition campaign — PROTOCOL

**Post-run audit note:** this original protocol is preserved. Its description of An0nB0ard
as a coupled extraction-to-login chain is qualified by [AUDIT_CORRECTIONS.md](AUDIT_CORRECTIONS.md).
The actual sealed login uses a fixed credential and a separate session. The audit does not
retroactively change the protocol or the measured cases.

- **Campaign:** `flag-acquisition-2026-11-14` / `run-1`
- **Objective:** For each of the six isolated lab web apps, (1) identify the real flag
  and the condition that yields it, (2) obtain the flag over HTTP against the firewall-less
  (`direct`) arm when possible, keeping checkable evidence, and (3) replay the same sealed
  sequences through each firewall arm to determine whether, why and in how many runs the
  architecture prevented the acquisition.
- **Owner of this campaign:** Claude (sole owner of Docker / GPU / ports for its duration).
  No staging, commit, push, PR or merge is done here — Codex consolidates the repo.
- **Separation of concerns:** This campaign is kept apart from the 2026‑11‑07 and
  2026‑11‑13 evidence. Its cases are **new** (`fa.*` ids); nothing here is folded back
  into those campaigns' metrics.

## Pinned identity verified before using resources

| Item | Value |
|---|---|
| Apps pin | `sec-challenges@be8e4e8f1c6aa12a17430146d569870d96d43dd5` (verified `rev-parse HEAD`) |
| Candidate | `fastv5-public-v3-headerguard-v2-20261111` (FAST_PATH_V5, V5.1 real, **no Model2**) |
| Manifest | `reports/v5/fastv5-2026-11-11/manifest.EXPERIMENTAL.json`, `model2: null` (verified) |
| GPU at start | RTX 4090 Laptop, idle (≈0.4 GiB used); released after every run (verified clean) |
| Docker/ports at start | no challenge containers; 1337/3030/5000/8443 free |
| Harness | committed `scripts/local_stack/challenges/{trial,score_trial,challenge_stack}.py` (source-hashed in each seal) |

The runtime, weights, decoder, representation, policies and frozen sources were **not**
changed to improve results. Protected sets were not used; nothing was trained.

## Arms (RUNTIME_CONTRACT.md)

| Arm | Meaning |
|---|---|
| `direct` | baseline, no firewall — the acquisition control |
| `v5only` | gateway with V5.1 only (reference) |
| `fastv5` | public‑v3 static Fast Path + V5.1, no Model2, no sink guard (Fast Path ablation) |
| `fastv5_guard` | **candidate** — `fastv5` + `request-header-sink-guard/v2` (active only on Inf3ct) |
| `crs` | ModSecurity + OWASP CRS comparator |

`fastv5_guard` is the primary candidate. On the five non‑Inf3ct apps it is equivalent to
`fastv5` by contract; it is nonetheless run on every app for a complete candidate record.
All firewall arms use **real V5.1** under the owner‑authorized temporary GPU hand‑off;
`direct` does not use the model.

## Protocol (per app)

1. Draft the sequences against `direct`, confirm the full flag/credential is returned
   over HTTP (oracle hit), **seal** the unchanged cases + direct rows
   (`trial.py seal`, source + config + apps‑commit pinned).
2. Replay the sealed cases through each firewall arm with real V5.1 (`trial.py run`).
3. **Three repetitions** per sequence and arm, clean state. Reps measure stability of the
   same technique — they are not new independent techniques or samples.
4. Requests are byte‑identical across arms (same sealed `cases_sha256`); only session‑level
   values that must differ are documented.
5. Sequences are constructed from the **direct‑arm mechanism** (source‑audited), never
   adapted from any candidate verdict.
6. Score with `score_trial.py`, which never counts operational fail‑closed, the V5 double,
   unlabeled cases or direct controls as detector results, and separates:
   `PREVENTED_AT_ATTACK` · `DELIVERY_BLOCKED_AT_OBSERVATION` · `PERSISTED` ·
   `ABSENT_OTHER_CAUSE` · `UNKNOWN`. A deterministic guard block (`request_guard`) is
   **not** attributed to V5.

Transport: `h1_tls_new` (primary). Clean state is proven per run: `trial.py` reseeds each
stack on `up` and runs `check-clean` on `down` (recorded in `CLEAN.json`); for Inf3ct the
rolling 5‑entry log is flushed with five benign `setup` POSTs before each attack rep.

## Exploration budget (fixed before starting)

- Exploit construction reuses the **source‑audited** mechanism for each vulnerability
  (no open‑ended fuzzing): one primary flag‑acquisition sequence per exploitable app,
  three reps, five arms.
- **ag3ncy** correct password: bounded **offline** dictionary attempt only (themed
  Star‑Wars/Marvel + common‑password list, a few hundred candidates; PBKDF2‑480k ⇒
  ≈20 guesses/s). If not found within that budget, the flag is recorded as **not
  retrieved** (documented limit) — no indefinite search, no brute force against the app.
- No success is invented; a 500, a disconnect or an absent flag without an identified
  cause is **not** scored as a detector hit.

## Phase 1 — flag audit (from full source read at the pin)

| App | Flag / objective | Provenance | Condition to obtain | Exploit vs legitimate | HTTP‑acquirable |
|---|---|---|---|---|---|
| **An0nB0ard** | `Flag{T3st1ng_f4k3_fl4g}` (admin page) | **placeholder fixture** (`FLAG` env = decoy); admin password `password123` is the DB seed | SQLi **UNION** read of `members.password` via `GET /post?id=` discloses the admin credential over HTTP; a **benign** admin login with that credential returns the flag | **Exploitation** (credential disclosure) + benign login | Yes |
| **CatP1cs** | `Flag{T3st1ng_f4k3_fl4g}` (`/flag.txt`) | **placeholder fixture** (`flag.txt` copied to container `/`) | **Path traversal** via `GET /show?img=` with percent‑encoding that evades the raw‑query blacklist, reading `/flag.txt` | **Exploitation** (traversal) | Yes |
| **D33pTh0ught** | `flag{Nob0dy_KNow5_Th3_6U1d3_t0_7h3_G4l4xy_an1M0r3}` | **real** (AES‑GCM blob, decrypts only with the answer) | `POST /` `answer=42` (PBKDF2→AES‑GCM decrypt) | **Legitimate** (correct riddle answer) — firewall should permit | Yes |
| **Inf3ct** | `Flag{T3st1ng_f4k3_fl4g}` (`/flag.txt`) | **placeholder fixture** (`flag.txt` copied to container `/`) | **Header SSTI**: `{{…}}` in any header value of a `POST /` is stored verbatim and rendered by `render_template_string` at `GET /log`; a Jinja file‑read returns `/flag.txt` | **Exploitation** (2‑step, header‑borne) | Yes |
| **ObC00ki3s** | client‑side flag (JS `requestOne()` → `atob`) | computed in the browser; **the server never sees or validates it** | set cookie `question=May I have a cookie, please?`, call `requestOne()`, read the console | **Client‑side only** — no server role | **No** (no HTTP response ever contains it) |
| **ag3ncy** | encrypted; value unknown | **real** (AES‑GCM blob) | `POST /auth` with the **correct password** (not in the repo) | **Legitimate** (correct password) | Yes, but password undetermined within budget |

Notes carried from the app contracts and confirmed here:

- The three "exploit" apps ship the **same placeholder** `Flag{T3st1ng_f4k3_fl4g}`. What the
  exploit demonstrates is the **mechanism** of retrieval over HTTP (arbitrary file read /
  credential exfiltration / stored‑template RCE reading a file), not a unique secret. The
  **full** flag string is retrieved and oracle‑checked, not merely the token `Flag{`.
- For An0nB0ard the admin password is **exfiltrated via the UNION read over HTTP**, not taken
  from source; the subsequent login is syntactically benign (a step of effect, not of
  detection). Prevention is attributed at the **extraction**, which is the only exploit step.
- D33p `answer=42` and a correct ag3ncy password are **legitimate interactions**: retrieving
  the flag through them may be correctly **permitted** by the firewall and is not a miss.
- ObC00ki3s has **no HTTP‑evaluable flag acquisition**: loading `cks.js`/`asking.js` is benign
  static traffic and does not by itself credit the flag.

## Sealed sequences and oracles (`effect_oracle` = full‑string `body_contains`)

| App | Sequence (roles) | Oracle (response body contains) | Scored as |
|---|---|---|---|
| CatP1cs | `GET /` (benign) · `GET /show?img=%2e%2e/%2e%2e/%2e%2e/fl%61g.txt` (attack) ×3 | `Flag{T3st1ng_f4k3_fl4g}` | single‑request exploit |
| Inf3ct | 5× benign `POST /` (setup) · `POST /` + `X-Note: {{ get_flashed_messages.__globals__.__builtins__.open('/flag.txt').read() }}` (attack) · `GET /log` (observe) ×3 | observe contains `Flag{T3st1ng_f4k3_fl4g}` | attack→observe sequence |
| An0nB0ard | `GET /messages` (benign) · `GET /post?id=zz' UNION SELECT 1,password FROM members-- -` (attack) · `POST /login admin_test:password123` (benign) ×3 | attack contains `password123`; benign login contains `Flag{…}` | single‑request exploit (extraction) + benign login |
| D33pTh0ught | `GET /` (benign) · `POST / answer=42` (benign) ×3 | `flag{Nob0dy_…}` | legitimate (expected ALLOW) |
| ag3ncy | `GET /` · `POST /auth password=usetheforce` (benign, invalid) ×3 | — (no flag; benign branch only) | legitimate benign surface |
| ObC00ki3s | `GET /`, `GET /static/js/cks.js`, `GET /static/js/asking.js`, `GET cks.js`+cookie | — (no server flag) | benign static traffic (FP check) |

Success criterion for "prevention attributed": the matching `direct` control obtained the
flag/credential (effect positive), the firewall run is evaluable (not an infra error / unknown
oracle / broken transport), and the stage that stopped it is identified
(`v5`, `request_guard`, `crs`, or application/benign).
