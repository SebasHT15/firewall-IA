# Local stack: TLS / HTTP/2 front, cascade gateway, independent application

**Status: lab package for the local demo and the final trials. Not a deployment approval.** Nothing in it
selects a model, a threshold or a Fast Path policy. Package: [`scripts/local_stack/`](../scripts/local_stack/).

```
client ──TLS 1.2/1.3, HTTP/1.1 or HTTP/2──> front: nginx 1.25.5 (Docker, host loopback :8443)
           one HTTP/1.1 message per request, loopback, plaintext
        ──> gateway: mitmdump + cascade_addon (:8080, admin :8090)   gateway-framing/v1, unchanged
              ├─ canonical workers, Model 2 worker (CPU)
              ├─ V5: double (default) | real service (GPU hand-off) | url:
              └─ egress guard (:8081) ──> fwlab-notes (Docker, --internal network, no route out)
```

Defaults: `V5_ONLY`, V5 **double**, Fast Path **disabled**, V4 **never started**. `V4_ONLY` and
`CASCADE_OBSERVE` are refused by this package; they stay with `scripts/gateway_ops/launch.py`.

## Start, stop, check

The work directory must be outside the repository: it holds the run seed, the lab CA key, the lab
passwords' derivation and logs that can carry request paths.

```bash
.venv-dataplane/bin/python scripts/local_stack/stack.py up --config scripts/local_stack/stack.example.json --work /home/sebas/Documents/Codex/2026-10-26/ta/work/local-stack/<new>
```

```bash
.venv-dataplane/bin/python scripts/local_stack/stack.py status --work <same dir>
```

```bash
.venv-dataplane/bin/python scripts/local_stack/stack.py down --work <same dir>
```

```bash
.venv-dataplane/bin/python scripts/local_stack/stack.py check-clean --work <same dir>
```

`up` refuses when a port is taken (it never stops the occupant), when an image differs from its pinned
ID, when the manifest's SHA-256 differs from the pin, or, for `--v5 real`, when `GPU_STATUS.json` does not
show the hand-off. Every component is written to `<work>/stack-state.json` as it starts (pid, process
group, kernel start time, command line; container/network names with a run label). `down` stops only
those and only while they still match, so a reused pid is never signalled; a failed `up` cleans itself
the same way. `check-clean` verifies no recorded process, group member, container, network or port is
left.

Options of `up`: `--v5 double|real|url:<url>`, `--upstream app|raw-sink` (raw-sink keeps exact bytes, for
transport checks), `--effect-routes` (mounts the deliberately vulnerable routes of the app; isolated
network only), `--log-targets` (app log keeps raw targets; synthetic traffic only).

Demo, narrated, stops everything at the end (`--keep-up` to leave it running):

```bash
.venv-dataplane/bin/python -B scripts/local_stack/demo.py --config scripts/local_stack/stack.example.json --work <new private dir>
```

## A delivered candidate

Codex delivers a `firewall-cascade-model-manifest/v2` (see `docs/cascade_candidate_handoff.md`). Pin it in
a new configuration; the mode is always explicit:

```bash
.venv-dataplane/bin/python scripts/local_stack/stack.py pin --config scripts/local_stack/stack.example.json --manifest <candidate manifest> --mode V5_ONLY --out <new config.json>
```

Then, with the GPU hand-off, `stack.py up --config <new config.json> --v5 real`. Nothing measured with
the double or with an earlier candidate carries over: reception, effect, load, queue and recovery are
repeated for the pinned candidate.

## Trust boundary

- TLS ends at the front. Front → gateway is plaintext HTTP/1.1 **on loopback**, and gateway → application
  is plaintext on an internal Docker bridge. Both are trusted only because they never leave this host;
  if either did, it would need its own protection (TLS or mTLS) and a new framing contract.
- The gateway still refuses inbound TLS and HTTP/2 itself (`scope_tls_inbound`, h2c gets no decision).
  It sees exactly what the front forwards, and that is what it decides on and what the egress guard
  delivers. `gateway-framing/v1` evidence covers the front → gateway → application hop, **not** the
  client → front hop: no framing evidence of the gateway is claimed for HTTP/2 or TLS.
- Anyone who can reach `127.0.0.1:8080` bypasses the front (not the firewall). That is how the `plain`
  reference path of the checks works, and it is why every port listens on loopback only.
- JWT and CSRF are decided by the **application**. `canonical-request/v1` carries neither cookies nor
  `Authorization`, so no credential ever reaches a model.

## What the front changes (measured, `transport_check.py`)

| Change | Effect on the gateway's input |
|---|---|
| Body re-framed with `Content-Length` (h1 chunked, h2 without length) | Same canonical text as the same body sent with a length |
| HTTP/2 header names lowercase; `cookie` crumbs joined with `"; "` | None on the canonical text (it carries only `Content-Type`) |
| Header names with `_` and invalid names dropped (nginx default) | None on the canonical text; the application never sees them |
| Absolute-form target turned into origin form | Plain gateway answers 501 (`scope_target_form`); through the front it is decided on the origin form |
| `Host`/`:authority` mismatch on HTTP/2 | Front answers 400 |
| CL + TE together | Front answers 400 (plain gateway: 400 from mitmproxy, no decision record) |
| Dot segments / encoded slashes escaping the root in the PATH | **Front answers 400 itself.** A refusal of the front is not a model decision and must be reported apart |
| Body over 64 KiB | Front 413 (plain: mitmproxy 413, no record). Over the manifest's `max_decoded_body`: gateway 413 on every path |
| Cancelled HTTP/2 stream mid-body | Never classified nor delivered (front logs 499) |

No header is added (`X-Forwarded-*`, `Via`, request ids). A request is never retried
(`proxy_next_upstream off`).

## Attribution of a rejection

Each answer is attributed from three independent logs, never from the status alone:

| Layer | Evidence |
|---|---|
| front | front access log: no `upstream_connect_time` (nginx answered itself; a 502 with the gateway down) |
| firewall | gateway decision record `applied: DENY`, nothing in the application log, firewall body |
| gateway protocol | mitmproxy refused before the cascade (e.g. CL+TE), no decision record |
| upstream unreachable | decision `FORWARD`, nothing in the application log, 502 |
| application | one line in the application log: `served`, or `app_rejected` with `control/reason` and the `X-Fwlab-Rejected` header |

## The application: fwlab-notes

[`notes_app/app.py`](../scripts/local_stack/notes_app/app.py): Flask 3.1.0 (image `firewall-ia/lab-app:lab`,
dev server — not representative for latency), standard library only besides Flask, nothing imported from
this repository. Server-side sessions (HttpOnly, SameSite=Lax, Secure behind TLS, rotated at login,
destroyed at logout), CSRF synchronizer token plus Origin/Referer check, JWT HS256 only with fixed `kid`,
`iss`, `aud`, `exp`, `nbf`, `iat`, `sub`, `jti` revocation and `scope`. Closed reason codes. Lab users and
passwords are derived from the run seed in the private work directory; nothing secret is in the repo.

Effect routes (`--effect-routes`): SQL injection (`/share/search`), traversal (`/files`), open redirect
(`/continue`), reflected XSS (`/share/preview`), each with an oracle in the application log
(`canary_in_response`, `external_location`, `unescaped_reflection`). The XSS oracle is textual; it does
not execute the document in a browser.

**Its routes have not been shown to any model.** If it is to serve as an application never seen in
model development, keep its route set and any population built for it out of training and selection.

## Checks (V5 double, CPU, Docker)

```bash
scripts/local_stack/run_checks.sh <new evidence dir> <new private work dir>
```

Unit tests alone, without Docker:

```bash
.venv-dataplane/bin/python -B -m unittest discover -s tests -p 'test_local_stack.py'
```

## ModSecurity + CRS comparator

`stack.py up --firewall crs` replaces the gateway with ModSecurity + OWASP CRS behind the **same** front and
in front of the **same** application, so both arms share TLS, HTTP/2 conversion and the application.

| Item | Value |
|---|---|
| Image | `owasp/modsecurity-crs:4.25.2-nginx-alpine-202610180210-lts`, pinned `sha256:57fd215e2894638a02d235f88510fa2a129d64740f0edb6798ca0e4aa2f02457` (38 MB compressed, pulled 2026-11-04 with the owner's approval) |
| Engine | ModSecurity v3.0.17, ModSecurity-nginx v1.0.4, nginx 1.30.6, CRS 4.25.2 |
| Rules | The image's CRS setup, unmodified: blocking paranoia 1, inbound anomaly threshold 5, outbound 4, `SecRuleEngine on`. Read back from the running container into the identity |
| Changed from the image | Listener on `127.0.0.1:<crs.port>` without TLS (`crs/default.conf.template`); no `/healthz` or `/metrics` answered by the WAF (`crs/location_common.conf.template`); image HEALTHCHECK off, because on the host network it would probe the stack's own TLS front |
| Kept from the image | Its proxy headers to the backend (`X-Real-IP`, `X-Forwarded-*`): the application sees them in this arm only |
| Attribution | Audit log (JSON, `RelevantOnly`, parts ABHZ) in the private work dir: a block is an `is_interrupted` entry with its rule ids and no application line |

Paranoia and thresholds live in the `crs` section of the configuration and are fixed **before** a run.
They are never tuned on results of the final set. Rule exclusions are not supported on purpose.

`crs_check.py` runs the app scenarios through this arm and records what CRS blocks. Those requests were
written here for the mechanism checks: they are known DEV and give no CRS rate.
