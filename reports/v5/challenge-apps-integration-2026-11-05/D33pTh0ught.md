# D33pTh0ught — integration report

**Vulnerability class:** guessable password → AES-GCM flag decryption (weak secret). **Port:** 3030.
**Needs:** nothing (Flask + cryptography + bcrypt). Source: `Web/D33pTh0ught/` @ `be8e4e8` (intact).
Image `fwlab-challenge/d33pth0ught:lab` (`sha256:7533d6f6…b682654`), built from the **adapter** Dockerfile
(python:3.12-slim) — the application ships none; the adapter only installs `requirements.txt` and runs
the unmodified `D33p.py`.

## Start

Single Flask app binding **port 3030** (not 1337). `GET /` → 200 readiness.

## Routes / flows

| Method | Path | Note |
|---|---|---|
| GET | `/` | question form (`index.html`, 450 B) |
| POST | `/` | `answer`; `PBKDF2(answer)` derives the key and decrypts the flag if correct (hint: *the answer to Life…*) |
| GET | `/static/img/*` | `machine.jpg` (39 KB, under the cap) |

**Sessions:** none. **State:** none (flag ciphertext is a module constant).

## What works (smoke, V5 double)

**All four arms pass** (direct, v5only, guarded, crs — see [`MATRIX.md`](MATRIX.md)); the CRS arm blocked
the XSS mechanism probe (403, `is_interrupted`). Highlights: startup, isolated, benign `GET /` → 200 with
reception; cascade block
attribution on `/?q=evil` (DENY, app not reached); benign forwarded; teardown + check-clean clean.

## Attack-effect observability

**Observable.** The correct answer renders the decrypted flag into the response; a wrong answer renders
the plain form. So effect + delivery + classification are measurable. **But this is a crypto/guessing
challenge, outside the V5 threat vocabulary** (SQLi/XSS/traversal/SSTI/…): the exploit traffic looks like
an ordinary small POST, so this application primarily exercises **false-positive** behaviour and
out-of-scope traffic, not detection.

## Limits

- Out-of-vocabulary for V5.1 → expected to pass as benign; treat as an FP / out-of-scope stressor.
- No structured app log; reception from the front access log + container console.
- Adapter Dockerfile pins the base image (python:3.12-slim); the application code is unchanged.

## Reproducible commands

```bash
PY=.venv-dataplane/bin/python
$PY scripts/local_stack/challenges/challenge_stack.py build --app D33pTh0ught
$PY scripts/local_stack/challenges/smoke.py --app D33pTh0ught --arm v5only --v5 double --work <private dir> --evidence <evidence dir>
```

## Evidence

`evidence/D33pTh0ught-v5only/`: `smoke-*.json`, `*.stack.json`, `challenge-identity.json`.
