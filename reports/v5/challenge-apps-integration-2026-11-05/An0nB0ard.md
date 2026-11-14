# An0nB0ard — integration report

**Vulnerability class:** SQL injection (string-concatenated queries). **Port:** 1337. **Needs:** MySQL 5.7
sidecar. Source: `Web/An0nB0ard/` @ `be8e4e8` (intact). Image `fwlab-challenge/an0nb0ard:lab`
(`sha256:4700125b…1da42a`), built from the application's own Dockerfile; MySQL `mysql:5.7`
(`sha256:4bc6bc96…2aad73bb`).

## Start

Its own `docker-compose.yml` runs a MySQL 5.7 service plus the Flask app on 1337. The stack reproduces
this with a MySQL sidecar on the same `--internal` network (reachable by container name via embedded
DNS), seeded from `members.sql`, data on an **ephemeral tmpfs** so every `up` starts clean. The app
image is the application's unmodified Dockerfile; the sidecar env/credentials are copied verbatim from
the application's compose file (`root`/`rootpassword`, DB `members`, fake `FLAG=Flag{T3st1ng_f4k3_fl4g}`).
Readiness: MySQL `mysqladmin ping`, then `GET /` → 200.

## Routes / flows

| Method | Path | Note |
|---|---|---|
| GET | `/` | login form (`sign.html`) — no DB touch |
| GET | `/register` | registration form |
| POST | `/login` | `username`+`password`; **SQLi** in `get_password` (string concat); admin → `admin.html` + flag |
| GET | `/messages` | list all posts (DB-backed) |
| POST | `/new` | create user |
| POST | `/addentry` | insert post (`id`+`entry`); **SQLi** (string concat) |
| GET\|POST | `/post?id=` | fetch post by id; **SQLi** in `get_entry` |
| GET | `/static/css/*` | bootstrap assets (bootstrap.min.css is 82 KB → exceeds the 64 KiB gateway cap) |

**Sessions:** none. `blog.py` imports `flask.session` but sets no secret key and never writes a session.
**State:** MySQL `members`/`posts`, re-seeded each run.

## What works (smoke, V5 double)

**All four arms pass** (direct, v5only, guarded, crs — see [`MATRIX.md`](MATRIX.md)). Highlights below;
the guarded arm exercises MySQL + Model 2 GUARDED_ENFORCE end to end, and the CRS arm blocked the SQLi
mechanism probe (`/post?id=1' OR '1'='1` → 403, `is_interrupted`, app not reached).

- Startup behind the shared TLS/HTTP-2 front, isolated internal network with no route out.
- Benign `GET /` → 200; **`GET /messages` → 200 with upstream 200 and a werkzeug console line → MySQL
  wiring confirmed** (the DB sidecar answered).
- Block attribution (guarded): `GET /?q=evil` → `applied: DENY`; the decision record shows Model 2
  (`model2-v51-selective-guard-lab-20261105`, threshold 0.9) **DEFER** (p_block 0.245) then V5 **BLOCK**;
  the application was **not** reached (`app_received: false`). Benign `/?q=hello` forwarded to the app.
- Teardown + `check-clean` clean (containers, network and the MySQL sidecar all removed).

## Attack-effect observability

**Observable.** A successful SQLi auth-bypass renders `admin.html` carrying the (fake) flag; UNION/boolean
SQLi changes the response body. So effect + delivery + classification are all measurable. The flag is the
fake learning value from the compose file, not a real secret.

## Limits

- Large static assets (`bootstrap.min.css`, 82 KB) exceed the 64 KiB cascade cap → 502 on the cascade
  arms; the benign HTML routes are well under it. Decide the body-limit policy before measuring.
- No structured app log; reception is attributed from the front access log + container console.
- No server session to measure.
- MySQL sidecar runs with a few capabilities its entrypoint needs (still no route out, ephemeral storage).

## Reproducible commands

```bash
PY=.venv-dataplane/bin/python
$PY scripts/local_stack/challenges/challenge_stack.py build --app An0nB0ard
$PY scripts/local_stack/challenges/smoke.py --app An0nB0ard --arm guarded --v5 double --work <private dir> --evidence <evidence dir>
```

Manual (any arm — `direct`, `v5only`, `guarded`, `crs`):

```bash
$PY scripts/local_stack/challenges/challenge_stack.py config --app An0nB0ard --arm guarded --out /tmp/an0n.guarded.json
$PY scripts/local_stack/challenges/challenge_stack.py up --app An0nB0ard --arm guarded --config /tmp/an0n.guarded.json --work <private dir> --v5 double
$PY scripts/local_stack/challenges/challenge_stack.py down --work <private dir>
$PY scripts/local_stack/challenges/challenge_stack.py check-clean --work <private dir>
```

## Evidence

`evidence/An0nB0ard-v5only/` and `evidence/An0nB0ard-guarded/`: `smoke-*.json`, `*.stack.json`,
`challenge-identity.json`.
