# ag3ncy — integration report

**Vulnerability class:** guessable password → AES-GCM flag decryption (weak secret). **Port:** 5000.
**Needs:** nothing (Flask + cryptography + bcrypt). Source: `Web/ag3ncy/` @ `be8e4e8` (intact). Image
`fwlab-challenge/ag3ncy:lab` (`sha256:1bde7655…ec28fc50`), built from the **adapter** Dockerfile
(python:3.12-slim) — the application ships none; the adapter only installs `requirements.txt` and runs
the unmodified `agency.py`.

## Start

Single Flask app on 5000. `GET /` → 200 readiness.

## Routes / flows

| Method | Path | Note |
|---|---|---|
| GET | `/` | landing page (`index.html`, 586 B) |
| POST | `/auth` | `password`; decrypts the flag if correct (hint: *may the force be with you*); renders admin page/flag vs error page |
| GET | `/static/img/*` | `avatar.png` (14 KB, under the cap) |

**Sessions:** none. **State:** none (flag ciphertext is a module constant).

## What works (smoke, V5 double)

**All four arms pass** (direct, v5only, guarded, crs — see [`MATRIX.md`](MATRIX.md)); the CRS arm blocked
the XSS mechanism probe (403, `is_interrupted`). Highlights below.

- Startup, isolated, benign `GET /` → 200 with reception.
- **direct arm:** `GET /?q=evil` reaches the application (no blocking layer) → the baseline `front → app`
  path (shared TLS front, no gateway, no WAF) is confirmed.
- **v5only arm:** `GET /?q=evil` → `applied: DENY`, app not reached; benign forwarded.
- Teardown + `check-clean` clean on both.

## Attack-effect observability

**Observable.** The correct password renders the admin page with the flag; a wrong one renders the error
page. So effect + delivery + classification are measurable. **But this is a crypto/guessing challenge,
outside the V5 threat vocabulary:** the exploit traffic is an ordinary small POST, so it primarily
exercises false-positive behaviour and out-of-scope traffic, not detection.

## Limits

- Out-of-vocabulary for V5.1 → expected to pass as benign; treat as an FP / out-of-scope stressor.
- No structured app log; reception from the front access log + container console.
- Adapter Dockerfile pins the base image (python:3.12-slim); the application code is unchanged.

## Reproducible commands

```bash
PY=.venv-dataplane/bin/python
$PY scripts/local_stack/challenges/challenge_stack.py build --app ag3ncy
$PY scripts/local_stack/challenges/smoke.py --app ag3ncy --arm direct --v5 double --work <private dir> --evidence <evidence dir>
$PY scripts/local_stack/challenges/smoke.py --app ag3ncy --arm v5only --v5 double --work <private dir> --evidence <evidence dir>
```

## Evidence

`evidence/ag3ncy-v5only/` and `evidence/ag3ncy-direct/`: `smoke-*.json`, `*.stack.json`,
`challenge-identity.json`.
