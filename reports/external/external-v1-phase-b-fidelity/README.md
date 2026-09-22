# External Test v1 — Phase B capture/replay fidelity evidence

**What was tested.** Before any External v1 case was built, the capture/replay chain was
checked for byte fidelity with no classifier in the path (protocol §4.2): real clients sent
requests through the capture-only proxy to `lab-app`; those captures were replayed by the
raw-socket replay client through the **same capture proxy**; and the two captured passes
were compared request by request by SHA-256 of the rendered text.

| Check | Result |
|---|---|
| `curl` — 8 captured, 8 replayed | **8 / 8 byte-exact** |
| Chromium / Playwright — 22 captured, predeclared first 12 replayed (10 not replayed by design) | **12 / 12 byte-exact** |

The capture proxy imports the data plane's `render_request()`, so this shows that byte-exact
replay of a captured request reproduces the same rendered text at a proxy using that
renderer. It is **not** a capture of what the enforcing data plane sent to `/classify`
during `external-v1-run-001`; that check was pre-registered (protocol §11) but not executed.
This evidence is supporting only (see the status note at the top of
[`../../../docs/external_test_v1_protocol.md`](../../../docs/external_test_v1_protocol.md)).

## Contents

| File | What it is | Kind |
|---|---|---|
| `raw/capture.jsonl` | `curl` run: 16 capture records — 8 original (from 2026-09-21T03:35:27Z) then 8 replayed (to 03:41:39Z) | original evidence, copied |
| `raw/replay_results.jsonl` | the replay client's 8 send records for the `curl` run (all HTTP 200, 0 errors) | original evidence, copied |
| `raw/browser_smoke.jsonl` | Chromium run: 34 capture records (tag `browser-smoke`) — 22 original then 12 replayed, 2026-09-21T04:01:07Z–04:01:08Z | original evidence, copied |
| `raw/browser_smoke_replay.jsonl` | the replay client's 12 send records for the Chromium run (11 × 200, 1 × 302, 0 errors) | original evidence, copied |
| `fidelity_check-curl.txt`, `fidelity_check-chromium.txt` | output of `scripts/external/fidelity_check.py` run on the copies above at stage close (2026-09-22) | derived re-verification |
| `SHA256SUMS` | SHA-256 of every file listed here | integrity |

## Provenance

- **Source:** `docker/.lab-logs/capture/` on the lab machine — machine-local and gitignored.
  The four `raw/` files were **copied, not regenerated**, on 2026-09-22; no traffic was
  re-sent. Each copy's SHA-256 was verified identical to its source file, and the sources
  were left unmodified.
- The original result was recorded in the message of commit `16da803` ("Verify curl
  capture/replay fidelity at 8/8 byte-exact", "Verify Chromium/Playwright fidelity at 12/12
  byte-exact").
- Only the lab's own hosts appear (`shop.fwlab.test`); the only cookie is the lab session
  cookie `fwlab_session`.

## Reproduce the check (read-only)

```bash
.venv-dataplane/bin/python scripts/external/fidelity_check.py --capture reports/external/external-v1-phase-b-fidelity/raw/capture.jsonl --split-after 8 --expect 8
```

```bash
.venv-dataplane/bin/python scripts/external/fidelity_check.py --capture reports/external/external-v1-phase-b-fidelity/raw/browser_smoke.jsonl --split-after 22 --expect 12
```

```bash
cd reports/external/external-v1-phase-b-fidelity && sha256sum -c SHA256SUMS
```

**Checker semantics** (`scripts/external/fidelity_check.py`, `tests/test_fidelity_check.py`):
SHA-256 comparison per request; with `--expect N`, exactly N must be selected on both sides
and all must match; a declared subset is reported as "not replayed by design", never as a
count mismatch; the originals are selected with `replay.py`'s own rule, so both sides
compare the same requests.
