# Inf3ct — integration report

**Vulnerability class:** server-side template injection (character-filtered). **Port:** 1337. **Needs:**
nothing. Source: `Web/Inf3ct/` @ `be8e4e8` (intact). Image `fwlab-challenge/inf3ct:lab`
(`sha256:83028adb…cc5d5ba6`), built from the application's own Dockerfile (python:3-alpine); copies the
fake `flag.txt` to `/flag.txt`.

## Start

Single Flask app on 1337. `GET /` → 200 readiness.

## Routes / flows

| Method | Path | Note |
|---|---|---|
| GET | `/` | message form (`index.html`, 1.3 KB) |
| POST | `/` | `msg`; `bad_chars "{'_#&;}"` stripped, then stored in an in-memory 5-slot log |
| GET | `/log` | renders the recent log via `render_template_string` → **SSTI sink** |
| GET | `/static/img/*` | `anon.png` |

**Sessions:** none. **State:** in-memory `log_array` (last 5 requests); resets when the container
restarts (so a `down`/`up` resets it).

## What works (smoke, V5 double)

**All four arms pass** (direct, v5only, guarded, crs — see [`MATRIX.md`](MATRIX.md)); the CRS arm blocked
the XSS mechanism probe (403, `is_interrupted`), and the cross-restart state-reset proof confirms the
in-memory log resets on `up`. Highlights: startup, isolated, benign `GET /` → 200 and **`GET /log` → 200** (the SSTI
sink route serves cleanly with a benign log), both with reception; cascade block attribution on
`/?q=evil` (DENY, app not reached); benign forwarded; teardown + check-clean clean.

## Attack-effect observability

**Observable (textual).** A successful SSTI makes evaluated template output appear in the `/log`
response. The oracle is textual (the rendered string), not browser execution. Note the application's own
`bad_chars` filter strips `{ ' _ # & ; }`, so a working payload must avoid those — the challenge's
intended difficulty, left intact. Effect + delivery + classification are measurable.

## Limits

- The in-memory log is shared process state: an attack POST then a `/log` GET are **two** requests; the
  measurement must account for the two-step source→sink flow and reset the log (container restart)
  between cases for clean state.
- No structured app log; reception from the front access log + container console.

## Reproducible commands

```bash
PY=.venv-dataplane/bin/python
$PY scripts/local_stack/challenges/challenge_stack.py build --app Inf3ct
$PY scripts/local_stack/challenges/smoke.py --app Inf3ct --arm v5only --v5 double --work <private dir> --evidence <evidence dir>
```

## Evidence

`evidence/Inf3ct-v5only/`: `smoke-*.json`, `*.stack.json`, `challenge-identity.json`.
