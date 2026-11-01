# Cascade gateway: operation

The cascade in the mitmproxy gateway. **Status: lab integration, not a deployment approval.** The
Model 2 threshold of the development fixture (0.9) is `LAB_EXPERIMENTAL`. There is no approved
operating point, no real application contract for the Fast Path, and D36 is not met.

Results and limits of this integration: [`reports/v5/hybrid/gateway-integration-v1/REPORTE.md`](../reports/v5/hybrid/gateway-integration-v1/REPORTE.md).

## What runs

```
client ──> mitmdump + cascade_addon.py ──> EgressGuard (loopback) ──> application
              │  scope gate
              │  delivery binding (serialize + strict parse)
              ├─ canonical workers (.venv-dataplane)     one canonicalize per request
              │  Fast Path
              ├─ Model 2 worker (.venv-analyzer)         BLOCK / DEFER only
              └─ V5 service (GPU, control plane)
```

| Mode | Who decides | Guard in the path | Failure of a cascade component |
|---|---|---|---|
| `V4_ONLY` | V4 | no | no cascade exists |
| `CASCADE_OBSERVE` | V4; the cascade is computed afterwards and recorded | no | the observation is lost, V4 is untouched |
| `V5_ONLY` | V5 | yes | deny |
| `CASCADE_ACTIVE` | Fast Path, Model 2, V5 | yes | Model 2 defers to V5; anything else denies |

`data_plane/data_plane.py` is not modified: `data_plane/cascade_addon.py` subclasses it, so the V4
path of every mode is that code. `mitmdump -s data_plane/data_plane.py` keeps being the plain V4
gateway. The chosen deployment is **reverse mode**, because the guard must be the upstream of
mitmproxy; a forward-proxy (`regular` mode) deployment is outside `gateway-framing/v1`.

## Before starting

```bash
.venv-dataplane/bin/python scripts/gateway_ops/make_dev_manifest.py --out reports/v5/hybrid/gateway-integration-v1/manifests/dev_fixture_baseline34.json
```

Refuses to overwrite. Skip it if the file exists. Then validate, offline, without a model or GPU:

```bash
.venv-dataplane/bin/python scripts/gateway_ops/launch.py --config config.cascade.example.yaml --check
```

Start the V4 service (needed by OBSERVE and by a return to V4) and, when the GPU is free, the V5
service:

```bash
/usr/bin/python3.12 -m uvicorn --app-dir control_plane classifier_api:app --host 127.0.0.1 --port 8000
```

```bash
/usr/bin/python3.12 -m uvicorn --app-dir control_plane v5_classifier_api:app --host 127.0.0.1 --port 8001
```

## Starting the gateway

```bash
.venv-dataplane/bin/python scripts/gateway_ops/launch.py --config config.cascade.example.yaml
```

`--print` shows the exact mitmdump command. The launcher passes the options of `gateway-framing/v1`
and removes proxy variables from the environment. In an authoritative mode, a configuration or
manifest that cannot be enabled stops mitmdump before it listens. In OBSERVE the problem is reported
and V4 serves.

Readiness and metrics are on a separate loopback port (`admin_port`):

```bash
curl -s http://127.0.0.1:8090/readyz
```

```bash
curl -s http://127.0.0.1:8090/status
```

```bash
curl -s http://127.0.0.1:8090/metrics
```

`/readyz` answers 503 with closed reasons in `cascade_problems`: a V5 service with another adapter,
recipe, fingerprint, vocabulary or B; an effective mitmproxy option outside the profile; no canonical
worker; the guard down; a Model 2 worker that never proved its identity. In an authoritative mode a
not-ready gateway answers 503 to every request. Each stage counts in `firewall_requests_total`,
`firewall_canonical_total`, `firewall_fast_path_total`, `firewall_model2_total`, `firewall_v5_total`,
`firewall_egress_total` and `firewall_stage_ms`.

Records go to `decision_log`, rotated and bounded. They carry closed codes, identifiers and numbers,
never a target, query, header value, body or canonical text.

## Returning to V4

Without a restart, in seconds, while V4's service is up:

```bash
touch reports/v5/hybrid/gateway-integration-v1/runtime/RETURN_TO_V4
```

V4 decides every request from that moment, and the guard forwards without enforcing. Remove the file
to give authority back:

```bash
rm reports/v5/hybrid/gateway-integration-v1/runtime/RETURN_TO_V4
```

Permanently: set `mode: V4_ONLY` and restart, or run the plain V4 gateway. In both cases mitmproxy
connects directly to the application.

**A return carries V4's capacity.** V4 has no admission control and keeps working on requests the
gateway gave up on, so above its capacity useful work falls to almost nothing and stays there for
minutes after the load ends. On the test machine that was about 4 r/s, far below `verified-suffix`:
see [`INFORME_CARGA.md`](../reports/v5/hybrid/gateway-integration-v1/load-run-1/INFORME_CARGA.md).

## Delivering a model candidate

A candidate is a `firewall-cascade-model-manifest/v2` JSON file. Nothing about it is hard-coded in the
gateway. The whole path, from new weights to a measured candidate, is in
[`cascade_candidate_handoff.md`](cascade_candidate_handoff.md). Reference: `CM.parse_manifest` in
[`data_plane/cascade_manifest.py`](../data_plane/cascade_manifest.py).

- `max_decoded_body` must be at least `max_bytes_per_token * token_budget_B`.
- `v5.*` must equal what the running service reports on `/health` and `/contract`.
- `v5.runtime` is required. `null` is the recipe's own runtime and refuses a service running any profile.
  A profile must bind this adapter and recipe in its own file, so a fast profile measured on earlier
  weights is refused. `firewall-cascade-model-manifest/v1` stays readable for existing fixtures.
- `artifact_sha256` is the SHA-256 of the file. `policy_sha256` is `Model2Policy.sha256`, the digest
  of the policy document, and the policy must be bound to that artifact and feature view.
- `status: APPROVED` needs `approval.approved_by/date/decision_ref`.
- `model2: null` is valid for `V5_ONLY` and `CASCADE_OBSERVE`, not for `CASCADE_ACTIVE`.
- The Model 2 worker accepts whatever `data_plane/model2_decider.py` can load, so a new feature view
  needs that module and `model2_policy.FEATURE_VIEWS` to know it.

Check a candidate:

```bash
.venv-dataplane/bin/python scripts/gateway_ops/launch.py --config <gateway.yaml> --check
```

## Fast Path audit

The audit shares V5 with the traffic waiting for a decision, so it has a budget in `fast_path.audit`:

| Key | Effect |
|---|---|
| `max_audits_per_second`, `burst` | Token bucket. Beyond it the audit is `RATE_LIMITED` |
| `yield_when_v5_inflight` | A queued audit starts only with fewer traffic calls than this in V5 |
| `max_queue_age_seconds` | Waited this long without room: `EXPIRED` |
| `queue_size`, `max_queue_bytes` | Bounded queue. Full: `SATURATED` |

V5 cannot be preempted: an audit that started delays later traffic by up to one inference, and the bucket
bounds how often. Sampling stays deterministic and traceable, but under a budget the audits actually run
are the first ones that fit, so read `discarded` before reading a rate of agreement.

`firewall_fast_path_audit_requested_total` always equals the sum of `_completed_total{verdict}`,
`_discarded_total{reason}`, `_failed_total{reason}` and what is in flight. `/status` gives the same
numbers in `fast_path_audit`, and queue depths in `queues`.

## Tests

CPU only. No GPU, no model service.

```bash
.venv-dataplane/bin/python -B -m unittest discover -s tests -p 'test_data_plane_cascade.py'
```

```bash
.venv-dataplane/bin/python -B -m unittest discover -s tests -p 'test_gateway_framing.py'
```

```bash
.venv-dataplane/bin/python -B -m unittest discover -s tests -p 'test_cascade_workers.py'
```

```bash
.venv-dataplane/bin/python -B -m unittest discover -s tests -p 'test_cascade_ops.py'
```

```bash
.venv-dataplane/bin/python -B -m unittest discover -s tests -p 'test_cascade_manifest.py'
```

```bash
.venv-dataplane/bin/python -B -m unittest discover -s tests -p 'test_load_lib.py'
```

```bash
.venv-dataplane/bin/python -B -m unittest discover -s tests -p 'test_cascade_candidate.py'
```

```bash
.venv-dataplane/bin/python -B -m unittest discover -s tests -p 'test_candidate_trials.py'
```

Live matrix: real mitmdump, canonical workers, guard and Model 2 on CPU, an independent sink process,
and V4/V5 **doubles**. It proves mechanisms, not detection:

```bash
.venv-dataplane/bin/python scripts/gateway_ops/live_check.py --out <new directory>
```

## Real models

Only with an explicit GPU hand-off, recorded in `GPU_STATUS.json`. `load_check.py` and
`candidate_walkthrough.py` refuse without it. Start V4 and V5 in visible terminals, with their logs in a private
directory: gateway and service logs can carry request paths, and `reports/**/*.log` is tracked.

Functional matrix: the four modes, the routes, the return to V4 and L1/L2/L3 with independent
reception, against real services:

```bash
scripts/gateway_ops/run_real.sh <label> <v5 log> <v4 log> <manifest.json>
```

With V4 and V5 both loaded on one GPU, no time from this run is a benchmark. The references of the
authored DEV cohort are constructed expectations, not confirmed attacks; JWT and CSRF need state; L3
delivery to an inert sink is not exploitation.

Isolated measurement by layers (inference, generation, queue, service, API client, V5 hop, gateway,
client). It starts its own V5 process per run, keeps V4 unloaded and refuses to start if another
compute process is on the GPU:

```bash
.venv-dataplane/bin/python scripts/gateway_ops/real_perf.py --out <new directory> --work <private directory> --manifest <manifest.json> --inputs <private inputs.jsonl> --benchmark-ids reports/v5/successor-2026-10-30/runtime/protocol.json
```

### Experimental V5 profiles

A profile needs its full hash and an explicit opt-in, and the manifest must name it. A manifest that
names no profile refuses a service running one, so a profile is never adopted silently.

```bash
.venv-dataplane/bin/python scripts/gateway_ops/make_dev_manifest.py --runtime-profile reports/v5/successor-2026-10-30/runtime/profiles/nf4.EXPERIMENTAL.json --out <manifest.json>
```

Start the service with `FIREWALL_V5_RUNTIME_PROFILE`, `FIREWALL_V5_RUNTIME_PROFILE_SHA256` and
`FIREWALL_V5_ALLOW_EXPERIMENTAL_RUNTIME=1`. BF16 stays experimental: it lowered P95 but lost some
detections, so it must not be promoted automatically.

### Load and recovery

Open-loop load against real services, on a reserved GPU. Finished runs are skipped, so a run can be
restarted. It stops if a compute process that is not ours appears on the GPU. A 503 is never counted as
useful work, a status only counts when its whole body arrived, and the saturation criteria are
descriptive, not an SLO.

```bash
scripts/gateway_ops/run_load.sh --phase ladder
```

Read the rates from the analysis, then run the other phases with them:

```bash
.venv-dataplane/bin/python scripts/gateway_ops/load_analyze.py --run <evidence directory> --out <new file>
```

```bash
scripts/gateway_ops/run_load.sh --phase failures --phase recovery --phase audit --phase soak --soak-rates reference=<R>,verified=<R> --phase soakhigh --soak-high-rate <R>
```

| Phase | Measures |
|---|---|
| `ladder` | Saturation per mode, overload and short recovery probes |
| `soak`, `soakhigh` | Sustained load, stages per route, resources, OBSERVE against V4 alone |
| `recovery` | Overload, probes until clean; return to V4 under load |
| `audit` | Fast Path response and audit losses at three sample rates |
| `failures` | V5, Model 2, canonical workers, guard, sink and gateway killed under load; return to V4 |

`--doubles --quick` is a dry run of the harness, without GPU. `EVIDENCE` and `WORK` override the output
directories; keep `WORK` outside the repository, since it holds logs with DEV data.
