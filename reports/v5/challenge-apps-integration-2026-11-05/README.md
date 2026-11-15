# sec-challenges applications — stack integration (2026-11-05)

Integration of the six `sec-challenges/Web/` applications into the Firewall-IA local stack, with
**minimal functional smoke only**. No experimental traffic set, attack campaign, load/latency run or
paper number is produced here — those are the later measurement phase. Design and command reference:
[`docs/challenge_apps.md`](../../../docs/challenge_apps.md). Package:
[`scripts/local_stack/challenges/`](../../../scripts/local_stack/challenges/).

## Applications repository pin

`/home/sebas/Documents/Codex/2026-11-02/sec-challenges` — branch `master`, commit
**`be8e4e8f1c6aa12a17430146d569870d96d43dd5`**, folder `Web/`. Every run recorded a live commit equal to
this pin (`commit_matches_pin: true`). The applications and their vulnerabilities are byte-for-byte
intact; the package only builds and runs them.

## Image ids built (2026-11-05)

| App | Image | Image id | Base / Dockerfile |
|---|---|---|---|
| An0nB0ard | `fwlab-challenge/an0nb0ard:lab` | `sha256:4700125b…1da42a` | application's own Dockerfile (python:3.9-slim) + MySQL 5.7 `sha256:4bc6bc96…2aad73bb` |
| CatP1cs | `fwlab-challenge/catp1cs:lab` | `sha256:da7f29db…ce28f67` | application's own Dockerfile (python:3-alpine) |
| D33pTh0ught | `fwlab-challenge/d33pth0ught:lab` | `sha256:7533d6f6…b682654` | adapter Dockerfile (python:3.12-slim) |
| Inf3ct | `fwlab-challenge/inf3ct:lab` | `sha256:83028adb…cc5d5ba6` | application's own Dockerfile (python:3-alpine) |
| ObC00ki3s | `fwlab-challenge/obc00ki3s:lab` | `sha256:c4a8f1aa…de476a63` | adapter Dockerfile (python:3.12-slim) |
| ag3ncy | `fwlab-challenge/ag3ncy:lab` | `sha256:1bde7655…ec28fc50` | adapter Dockerfile (python:3.12-slim) |

## Smoke matrix run this phase (V5 DOUBLE, CPU) — full 6 × 4

**24/24 runs pass** (6 applications × `direct`, `v5only`, `guarded`, `crs`). apps commit matches the pin
in every run. Full per-run breakdown, failure causes (none) and the large-response table:
[`MATRIX.md`](MATRIX.md).

| App | direct | v5only | guarded | crs |
|---|---|---|---|---|
| An0nB0ard | ✅ | ✅ | ✅ (MySQL + Model 2) | ✅ (CRS 403) |
| CatP1cs | ✅ | ✅ | ✅ | ✅ (CRS 403) |
| D33pTh0ught | ✅ | ✅ | ✅ | ✅ (CRS 403) |
| Inf3ct | ✅ | ✅ | ✅ | ✅ (CRS 403) |
| ObC00ki3s | ✅ | ✅ | ✅ | ✅ (CRS 403) |
| ag3ncy | ✅ | ✅ | ✅ | ✅ (CRS 403) |

Each run checks: startup, benign flows + reception, the no-server-session fact, **state reset**, block
attribution for that arm, large-response handling (where an asset > 64 KiB exists), teardown and
`check-clean`.

- **With `--v5 double` the only cascade block is the double's rule** (BLOCK on the literal word `evil`):
  integration and attribution, **not** detection quality.
- **guarded arm** (all six): the full `CASCADE_ACTIVE` path — Model 2 GUARDED_ENFORCE
  (`model2-v51-selective-guard-lab-20261105`, threshold 0.9) returned **DEFER**, V5 double returned
  **BLOCK** → `applied: DENY`, application not reached.
- **crs arm** (all six): the per-app mechanism probe (SQLi / traversal / XSS) was **blocked by ModSecurity
  (403, `is_interrupted`)** and never reached the application.
- **direct arm** (all six): no blocking layer; the request reaches the application (baseline).
- **Cross-restart state reset proved** for the two stateful apps
  ([`evidence/_state-reset-proof/`](evidence/_state-reset-proof/)): a unique marker written to An0nB0ard
  (`/addentry` → `/messages`) and Inf3ct (`/` → `/log`) is **gone after a `down`/`up`** (MySQL re-seeded
  from `members.sql` on tmpfs; Inf3ct's in-memory log reset with the container).

## Per-application reports

- [An0nB0ard.md](An0nB0ard.md) — SQL injection, MySQL sidecar
- [CatP1cs.md](CatP1cs.md) — path traversal / local file read
- [D33pTh0ught.md](D33pTh0ught.md) — guessable-password crypto
- [Inf3ct.md](Inf3ct.md) — server-side template injection
- [ObC00ki3s.md](ObC00ki3s.md) — client-side puzzle (delivery/classification only)
- [ag3ncy.md](ag3ncy.md) — guessable-password crypto

## Evidence layout

`evidence/<app>-<arm>/` holds, per run: `smoke-<app>-<arm>.json` (every check + raw attribution),
`<app>.<arm>.stack.json` (the exact pinned stack config), and `challenge-identity.json` (apps commit,
image ids, manifest id/sha, front/gateway/CRS identity).

## Key integration findings / limits

1. **64 KiB response cap on the cascade arms only** (`v5only`/`guarded`, `gateway-framing/v1`, both
   directions): responses over 64 KiB are refused with 502 (CatP1cs `alba.jpg` 76 KB / `blackcat.gif`
   8 MB; raising `gateway.body_size_limit` to 16m → 200). **CRS and direct have no such cap and serve the
   asset in full** — an arm asymmetry. Recorded per run in `MATRIX.md`; the limit was kept, never tuned.
2. **No structured application log** in the stock CTF apps → reception is attributed from the front access
   log `upstream_status` plus the application container console, not a per-request oracle.
3. **ObC00ki3s is client-side only** → delivery/classification measurable server-side, never an effect.
4. **D33pTh0ught, ag3ncy, ObC00ki3s are outside the V5 threat vocabulary** → expected to pass as benign;
   they are false-positive / out-of-scope stressors, not detection targets.
5. **An0nB0ard issues no server session**; its DB state is ephemeral (tmpfs, re-seeded from `members.sql`
   each `up`). **Inf3ct** keeps an in-memory 5-slot log that resets per container.
