# ObC00ki3s — integration report

**Vulnerability class:** client-side only (obfuscated JavaScript cookie puzzle). **Port:** 5000 (Flask
default; `server.py` calls `app.run(host='0.0.0.0')` with no port). **Needs:** nothing. Source:
`Web/ObC00ki3s/` @ `be8e4e8` (intact). Image `fwlab-challenge/obc00ki3s:lab`
(`sha256:c4a8f1aa…de476a63`), built from the **adapter** Dockerfile (python:3.12-slim) — the application
ships none; the adapter only installs Flask and runs the unmodified `server.py`.

## Start

Single Flask app on 5000. `GET /` → 200 readiness.

## Routes / flows

| Method | Path | Note |
|---|---|---|
| GET | `/` | `index.html` (777 B) that loads the puzzle JS |
| GET | `/static/js/cks.js` | obfuscated client logic (592 B) |
| GET | `/static/js/asking.js` | obfuscated client logic (2.3 KB) |
| GET | `/static/img/*` | `bunchofcookies.jpeg` (136 KB → exceeds the 64 KiB gateway cap) |

**Sessions:** cookies are set by the JavaScript in the **browser**; the server issues none. **State:**
none server-side.

## What works (smoke, V5 double)

**All four arms pass** (direct, v5only, guarded, crs — see [`MATRIX.md`](MATRIX.md)); the CRS arm blocked
the XSS mechanism probe (403, `is_interrupted`). Highlights: startup, isolated, benign `GET /` → 200 and `GET /static/js/cks.js` → 200
(both under the cap, reception confirmed); cascade block attribution on `/?q=evil` (DENY, app not
reached); benign forwarded; teardown + check-clean clean.

## Attack-effect observability

**Not observable server-side.** All challenge logic runs in the browser; the firewall only sees `GET /`
and static fetches. For this application **only delivery and classification are measurable** — never an
exploit effect. It is a client-side puzzle, outside the V5 threat vocabulary, so it serves as a
false-positive / out-of-scope stressor.

## Limits

- No server-observable exploit effect; measuring it would require a real browser client (out of scope for
  the stack's server-side attribution).
- `bunchofcookies.jpeg` (136 KB) exceeds the 64 KiB cascade cap → 502 on the cascade arms (v5only,
  guarded), served in full (200) by CRS and direct; benign browsing
  of the page itself (HTML + small JS) is under the cap.
- No structured app log; reception from the front access log + container console.

## Reproducible commands

```bash
PY=.venv-dataplane/bin/python
$PY scripts/local_stack/challenges/challenge_stack.py build --app ObC00ki3s
$PY scripts/local_stack/challenges/smoke.py --app ObC00ki3s --arm v5only --v5 double --work <private dir> --evidence <evidence dir>
```

## Evidence

`evidence/ObC00ki3s-v5only/`: `smoke-*.json`, `*.stack.json`, `challenge-identity.json`.
