# real-http-fp-v1 — diagnostic: false positives on benign HTTP requests

**Experiment type: DIAGNOSTIC.** The case mix was chosen to find and explain failures. It is
**not** the external test, **not** a representative benchmark, **not** an FPR estimate and
**not** training data. No proportion below is the model's false-positive rate, and none
extrapolates to real traffic.

Run 2026-09-18, 15:23–15:26 local time, V4 adapter `model-output-v4-clean`, branch
`feature/ml-evaluation` at `52f4fbc` (the working tree carries the uncommitted text-only changes
of the documentation pass: docs and docstrings, no functional code; list in `manifest.json`). It repeats the design of the 2026-09-17 diagnostic, whose raw data were
lost; this time every raw record is kept in this directory.

## What was run

Four visible foreground processes, each tee'd to its log (exact commands in `manifest.json`):

| Process | Log |
|---|---|
| `classifier_api:app` on 127.0.0.1:8000 (unchanged) | `classifier.log` |
| `mitmdump -s data_plane.py` on 127.0.0.1:8080 (unchanged), launched under `strace` to record the bytes it sent to `/classify` | `proxy.log`, `proxy_strace.log` |
| `python3.12 -m http.server 9000` serving `www/` | `server.log` |
| `run_experiment.py` | `client.log`, `results.jsonl` |

- **Cases:** `build_cases.py` pre-registered 175 cases (149 unique texts) in `cases.jsonl`
  before anything was sent. Every case is benign by construction, `expected_label = ALLOW`,
  and none was excluded as ambiguous. Each non-reference case changes **one** variable
  against the reference named in `pair_with`. The proxy subset (26 curl commands) was fixed
  in the same file, before any result. Case ids never appear in an HTTP request.
- **Direct:** 149 unique texts × 3 repetitions = 447 calls to `/classify`, after 3 warm-up
  calls that are excluded from every statistic.
- **Proxy:** 26 curl commands × 3 = 78 requests through mitmdump (curl 8.18.0), after 1
  excluded warm-up request. Each proxy call's `/classify` body was recovered from
  `proxy_strace.log` and POSTed again directly (78 re-sends).

## Results

**Determinism and validity.** 149 of 149 unique texts gave the same decision and reason on
all 3 repetitions. There were 0 invalid outputs in 447 direct calls.

**37 false positives among 149 constructed benign unique texts.** The BLOCK reasons were:

| Reason | Unique texts |
|---|---:|
| SSRF | 25 |
| File inclusion | 4 |
| HTTP parameter pollution | 3 |
| Open redirect | 3 |
| Request smuggling | 2 |

Decision per value, `A` = ALLOW and `B` = BLOCK:

| Group (fixed context) | Values → decision |
|---|---|
| HOST, curl via proxy (K1) | localhost A · 127.0.0.1 **B** · 127.0.0.2 **B** · [::1] **B** · 192.168.1.20 A · 10.0.0.15 A · app.fwlab.test A · shop.example.com A |
| HOST, curl direct (K2) | same pattern as K1: the three loopback values **B**, everything else A |
| HOST, browser (K3) and Python API (K4) | all 8 values A |
| EVALSWAP (10 eval ALLOW rows) | original A · localhost:9000 A · 127.0.0.1:9000 A, in 10 of 10 rows |
| PATH, K1 and K2, localhost | `/` **B** · `/favicon.ico` **B** · the other 5 paths A |
| PATH, K3 browser, localhost | all 7 paths A |
| PATH, K1, Host 127.0.0.1 | `/about.html` A · `/miembros/imagenes/zarauz.jpg` A · the other 5 **B** |
| PORT, K1, localhost | none, 80, 3000, 8000, 8080, 9000, 12345, 18080 A · 19000, 20000, 30000, 65000 **B** |
| PORT, K1, app.fwlab.test | the same ports up to 18080, plus 19000, A · 20000, 30000, 65000 **B** |
| HDR, K1, localhost | −User-Agent **B** · +Connection: close **B** · −Proxy-Connection A · −Accept A · +Cookie A |
| HDR, K2 and K3, localhost | every toggle A |
| HDR, K1 and K2, 127.0.0.1 | every toggle **B** except +Cookie, which gives A in both |
| UA value, K1, localhost | Chrome **B**; curl 8.18.0 / curl 8.5.0 / Wget / Firefox / python-requests / httpx / urllib A |
| UA value, K2, localhost | all 8 values A |
| UA value, K1, 127.0.0.1 | all 8 values **B** |
| UA × Proxy-Connection, localhost | UA on/PC on A · UA on/PC off A · **UA off/PC on B** · UA off/PC off A |

**A/B pair transitions.** Each case is compared with its reference.

| Family | ALLOW→BLOCK | ALLOW→ALLOW | BLOCK→ALLOW | BLOCK→BLOCK |
|---|---:|---:|---:|---:|
| HOST | 6 | 22 | 0 | 0 |
| PATH | 4 | 14 | 2 | 4 |
| PORT | 7 | 15 | 0 | 0 |
| HDR | 2 | 12 | 2 | 8 |
| UA | 1 | 13 | 0 | 7 |
| UA×PC | 1 | 2 | 0 | 3 |
| EVALSWAP | 0 | 20 | 0 | 0 |

**API vs proxy.**
- The captured proxy→`/classify` text was byte-identical to the pre-registered text in 78
  of 78 calls.
- The capture-to-call mapping is independently confirmed in 78 of 78 calls: the text length
  equals the "received request (N bytes)" the classifier logged for that call.
- Re-sent directly, the captured text gave the same decision in 78 of 78 calls and the same
  reason in 78 of 78.

**Proxy enforcement.** 48 of 48 model ALLOW decisions returned HTTP 200 and reached the
destination. 30 of 30 BLOCK decisions returned HTTP 403 and did not reach it. `server.log`
has 49 GET lines: the 48 ALLOW plus the excluded warm-up. There were 0 fail-closed 503s.

**Latency: observation only.** This is not a benchmark and D36 is not evaluated.
- Direct `model_latency_ms` (`generate()` only): n = 447 over repeated texts, P50 230.8 ms,
  P95 236.2 ms.
- The first warm-up call took 529.1 ms. It was a cold start and is reported separately.
- Proxy → classifier round trip: n = 78, P50 249 ms, P95 267 ms, with `strace` attached to
  the proxy.

## Interpretation

**CONFIRMED OBSERVATIONS** (in this run, reproducible 3 of 3)
- In 6 of 28 controlled HOST pairs, localhost → a loopback value (127.0.0.1, 127.0.0.2 or
  [::1]) changed ALLOW → BLOCK. All 6 are in the two curl header sets. The same change did
  not alter the decision in the browser or Python-API header sets, or in 10 of 10 eval ALLOW
  rows. Private IPs and ordinary hostnames never changed the decision.
- With a loopback Host, adding a Cookie changed BLOCK → ALLOW in both curl contexts. So did
  2 of 7 paths.
- In the curl contexts, the path `/` and `/favicon.ico` changed ALLOW → BLOCK. They did not
  in the browser context.
- In the curl-via-proxy context, the Host ports tested from 20000 up gave BLOCK for both
  hostnames. Port 19000 gave BLOCK for `localhost` and ALLOW for `app.fwlab.test`.
- Removing User-Agent, or adding `Connection: close`, changed ALLOW → BLOCK only when
  Proxy-Connection was present. Without it (the K2 context), neither change altered the
  decision.
- Accept presence and most User-Agent values changed nothing in the contexts tested. The
  exception is a Chrome UA in the curl-via-proxy context.
- The proxy path and the direct path give identical decisions and reasons for identical
  text, and the proxy enforces them correctly.

**SUPPORTED HYPOTHESES** (compatible with the evidence, not demonstrated)
- *Out-of-distribution inputs / coverage gap:* the feature values that flip decisions have
  no support in the V4 splits. The splits contain 0 loopback Hosts, 0 requests to `/` or
  `/index.html`, and only ports 8000 and 8080, per a direct count on
  `datasets/v4_clean/{train,eval}.jsonl`.
- *Spurious correlation / shortcut:* `127.0.0.1` appears only in BLOCK rows of V4 (58 train,
  12 eval), and SSRF is the reason for 25 of the 37 BLOCK texts. That is compatible with a
  learned loopback → SSRF association. It is **not** a simple rule: the browser and
  Python-API header sets, the eval rows, a Cookie and some paths all cancel it.
- *Joint-feature sensitivity:* decisions for minimal curl-like requests depend on several
  envelope features together (UA × Proxy-Connection, Connection: close × Proxy-Connection,
  Cookie, path). That is compatible with these requests lying in a sparsely covered region.
- *Overfitting* is neither supported nor excluded. This experiment does not measure a
  train/held-out gap.

**OPEN QUESTIONS**
- Why browser and Python-API header sets are unaffected by a loopback Host while curl-like
  ones are.
- Why the port at which BLOCK starts differs by hostname. No threshold is claimed.
- The `/favicon.ico` → file-inclusion and Chrome-UA → open-redirect decisions. Both are new
  relative to the 2026-09-17 summary, and each was seen in one context family.
- Whether any of this holds for other clients, methods with bodies, HTTPS or HTTP/2.
- The mechanism: which training rows, if any, produce these decisions.

## Limitations

- The composition is diagnostic, so BLOCK proportions are not rates. Only GET requests went
  through the proxy, all sent by one client (curl 8.18.0) over plain HTTP/1.1.
- The benign texts were built by hand from real clients' header sets. They are not captured
  user traffic.
- There is one model version (V4), one machine and greedy decoding. Repetition verifies
  determinism, not variance.
- The 10 eval rows come from the internal V4 split. They were used only as in-distribution
  contexts, not to guide any change.
- Latency was measured with `strace` attached to the proxy and is not a benchmark.
- The comparison with the 2026-09-17 run rests on a surviving summary that cannot be
  re-verified.

## Files

| File | Content |
|---|---|
| `manifest.json` | identity, versions, hashes, hardware, design, commands, limitations, log offsets at GO |
| `cases.jsonl` | 175 pre-registered cases: text, SHA-256, family, variable, pair, proxy curl spec |
| `results.jsonl` | one record per call: warm-up, direct, proxy, capture and re-send |
| `summary.json` | computed diagnostic statistics and the per-text outcome |
| `classifier.log`, `proxy.log`, `server.log`, `client.log` | tee'd output of the four processes |
| `proxy_strace.log` | raw `strace` of mitmdump, the source of the captured texts |
| `build_cases.py`, `run_experiment.py`, `www/` | code and destination content needed to reproduce the run |
