# CatP1cs — integration report

**Vulnerability class:** path traversal / local file read (blocklist bypass). **Port:** 1337. **Needs:**
nothing. Source: `Web/CatP1cs/` @ `be8e4e8` (intact). Image `fwlab-challenge/catp1cs:lab`
(`sha256:da7f29db…ce28f67`), built from the application's own Dockerfile (python:3-alpine); it also
copies the fake `flag.txt` to `/flag.txt` inside the container.

## Start

Single Flask app on 1337; no companion services. `GET /` → 200 readiness.

## Routes / flows

| Method | Path | Note |
|---|---|---|
| GET | `/` | cat gallery (`index.html`, 4 KB) |
| POST | `/` | message form; returns a random token id, nothing stored |
| GET | `/show?img=` | `send_file('static/img/'+img)`; **path traversal** if the substring blocklist `['./','..','etc','passwd','flag']` (checked against `request.full_path`) is bypassed |
| GET | `/static/img/*` | cat images (`favicon.ico` 17 KB; `alba.jpg` 76 KB; `blackcat.gif` 8 MB) |

**Sessions:** none. **State:** none.

## What works (smoke, V5 double)

**All four arms pass** (direct, v5only, guarded, crs — see [`MATRIX.md`](MATRIX.md)). Highlights below.

- Startup, isolated, benign `GET /` → 200.
- Benign file serving: `GET /show?img=favicon.ico` → 200 (17 KB, under the gateway cap), reception
  confirmed.
- Cascade block attribution (v5only): `GET /?q=evil` → `applied: DENY`, app not reached; benign
  forwarded.
- **CRS arm:** the traversal mechanism request `GET /show?img=....//....//etc/passwd` → **403**, one
  ModSecurity audit entry (`is_interrupted`), application **not** reached — block correctly attributed to
  the CRS layer. (A known DEV mechanism request; it gives no CRS rate.)
- Teardown + `check-clean` clean.

## Attack-effect observability

**Observable.** A successful traversal returns the target file's **bytes** in the response body (e.g.
`/flag.txt`), so effect + delivery + classification are measurable — **bounded by the 64 KiB response
cap** on the cascade arms (v5only, guarded); CRS and direct serve the full file.

## Limits

- `alba.jpg` (76 KB) and `blackcat.gif` (8 MB) exceed the 64 KiB cascade cap → 502 on the **cascade arms
  (v5only, guarded)**, verified; the **CRS and direct arms serve them in full (200)**. A benign corpus for
  the cascade arms must use sub-64 KiB responses, or the body limit must be raised (decided before runs).
- No structured app log; reception from the front access log + container console.

## Reproducible commands

```bash
PY=.venv-dataplane/bin/python
$PY scripts/local_stack/challenges/challenge_stack.py build --app CatP1cs
$PY scripts/local_stack/challenges/smoke.py --app CatP1cs --arm v5only --v5 double --work <private dir> --evidence <evidence dir>
$PY scripts/local_stack/challenges/smoke.py --app CatP1cs --arm crs    --v5 double --work <private dir> --evidence <evidence dir>
```

## Evidence

`evidence/CatP1cs-v5only/` and `evidence/CatP1cs-crs/`: `smoke-*.json`, `*.stack.json`,
`challenge-identity.json`.
