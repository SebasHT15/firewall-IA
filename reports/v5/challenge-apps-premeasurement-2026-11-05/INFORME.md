# Six challenge applications: measurement readiness (2026-11-05)

## Decision

**Ready to start an L2 scripted laboratory campaign**, once its independent case population,
direct-effect oracles, grouping, load ladder, SLO, repetitions and analysis plan are fixed. The
stack and tools can capture, seal, replay and score those cases without V5 doubles. The six apps are
not organic user traffic; population R and human-task claims remain unavailable until actual
authorized users/data and a privacy/retention plan exist. No rate in this report is a paper result.

The metric contract is
`/home/sebas/Documents/Codex/2026-11-02/firewall-ia-cierre-pc-paper/outputs/METRICAS_CASCADA_PAPER_2026-11-04.md`
(SHA-256 `fb8ce839151d9bb842700c8ea4a1a591fe55d62ae5c680e1f3feaf6a3d58c4e8`). The app source is
`sec-challenges/Web` at `be8e4e8f1c6aa12a17430146d569870d96d43dd5`. C2 is outside this campaign.
V5.1 is the real semantic model; Model2 is the experimental `GUARDED_ENFORCE` policy. V5.2 is not a
candidate after its known FN regression.

## Architecture and resolved response cap

The common TLS/HTTP-2 front connects each app through direct, V5_ONLY, guarded cascade and CRS arms.
A fifth, separately analyzed guarded Fast Path variant allows one exact static asset per app and
sends all other requests onward to Model2/V5.1. The 64 KiB cascade response limit that gave normal
assets a 502 was raised **before corpus construction** to 16 MiB for these challenge apps. The
front's request cap remains 64 KiB and the V5.1 manifest's decoded-body cap remains 19,920 bytes.

At the fixed 16 MiB limit, the [24-run matrix](MATRIX.md) passed 24/24 with the V5 double. All 16
large-response checks returned complete 200s, including the 8,106,213-byte CatP1cs GIF. The six
guarded Fast Path double smokes passed 6/6, and the six app-bound Fast Path probes with **real V5.1**
passed 6/6. The earlier 64 KiB matrix is retained as evidence of the resolved defect. No capacity
or detection estimate follows from any smoke.

## Measurement tools now exercised

| Requirement from metric contract | Collector/evidence | Boundary |
|---|---|---|
| Per-request identity, label basis, transport, hashes, app receipt, effect oracle, layer, Model2/V5, timings | `trial.py`, `trial_client.py` and private stack logs | Raw cases outside repository; public rows have no URL/body/cookie/JWT/IP |
| Direct effect before firewall, frozen cases/config/code/app/metric specification | `trial.py run --arm direct` then `trial.py seal` | One seal per app and transport; source/config drift fails closed |
| TP/TN/FP/FN, invalids, FPR/recall, family/session/effect, V5 reason, Model2 rescues/damage, paired differences, cluster intervals, AUROC/AP/Brier/ECE diagnostics | `score_trial.py` | Requires real V5.1, identical cases/groups/transport and clean teardown; no score from double |
| HTTP/1.1 plain, TLS h1/h2 new, resumed and persistent; TCP/TLS setup times | `trial_client.py` | Plain gateway is diagnostic and has no direct-arm pair |
| Offered/completed/useful throughput, SLO, P50/P95/P99, client queue, gateway/V5 waits, queue snapshots, CPU/RAM/GPU | `load_trial.py` | Read-only benign direct-positive controls; repeated load traffic is not independent quality evidence |
| App, front, gateway, V5 and Model2 failure, attribution, app receipt and pinned-restart recovery | `fault_trial.py` | Measures explicit restart recovery; V5 invalid/error/timeout remain covered by `scripts/local_stack/failure_check.py` |
| CRS version/image/config, rule IDs and anomaly scores | sealed CRS config, runtime effective values, `trial.py` audit extraction | Direct and CRS keep the same front/app; CRS adds its documented forwarding headers |

The real V5.1 two-case tool dry run used one `GET /` and one ObC00ki3s static JS request. Direct and
CRS delivered both. V5_ONLY and guarded delivered `/`, but V5.1 blocked the benign JS with reason
`Open redirect payload detected.`; Model2 deferred. The separate Fast Path variant delivered the
exact JS with no V5 call. This confirms attribution and exposes a concrete benign regression to
include in the independent campaign. **Two authored requests are not an FPR estimate.** The final
source-pinned dry-run seal is `trial-dryrun-seal-v9/SEAL.json`; its paired real V5_ONLY and guarded
rows include canonical text length/hash, prompt/generated token information and closed V5 reason.

Transport dry runs delivered both requests with h1/h2 TLS new, TLS session resumption and persistent
connections. The second resumed request reported `tls_session_reused=true` for both h1 and h2; the
second persistent request reported two requests on one connection. Plain h1 to the gateway also
passed as a diagnostic. TCP connect and TLS handshake times are now separate per request; the
persistent second request records zero additional handshake time. These are transport checks, not
latency comparisons.

Two short **real V5.1** load wiring checks at 2 offered rps for 2 seconds completed 4/4 useful
requests in each of V5_ONLY and guarded. They sampled gateway/V5 waits, CPU/RAM and GPU. Their
duration and sample size are insufficient for throughput or saturation claims. A real V5 failure
gave firewall 503 with no app receipt; a Model2 child failure gave `Model2Unavailable` and the
request continued through V5 to a 200. Both returned to clean service after an explicit restart.
Double-only app, gateway and front failures produced respectively 502, 502 and a connection failure,
all without app receipt, and recovered after restart. Docker cleanup passed after each run and the
GPU status returned to `AVAILABLE`.

The under-traffic restart probe also ran with **real V5.1**: 24 offered requests over four seconds,
one front restart, 23 useful responses and one connection failure during the interruption. Five
consecutive useful responses under the illustrative 1,000 ms SLO were observed 0.88 seconds after
the front returned. The double probe showed the same 23/24 pattern. These short runs validate the
collector and recovery definition only; they are not capacity or reliability estimates.

A separate CatP1cs CRS audit probe reached the app in the direct arm (200) and was interrupted by
CRS (403) before app receipt. The public CRS row retained only rule IDs `930120`, `932160`, `949110`
and anomaly score 10; the raw request stayed in the private case/audit area. This probe has no
effect oracle and is **not** an effect-prevention observation.

## Conditions before paper measurement

1. Build an independent L2 case population per app, with legitimate task oracles and attack effect
   oracles established on the direct arm. Record component, template, session, family, time, label
   basis and adjudicator. Exclude final groups from training and model selection. An0nB0ard,
   CatP1cs and Inf3ct are detection-relevant; the password/browser challenges are chiefly benign
   and out-of-vocabulary controls.
2. Ratify the operational SLO, load ladder, repetitions (at least three per important point), arm
   order, exclusions, effect denominators and privacy/retention rules **before** opening final cases.
   Run the same request/transport in direct, V5_ONLY, guarded and CRS; analyze Fast Path separately.
3. Execute the sealed campaign with V5.1 real and temporary GPU hand-off; inspect negative results
   and missing labels. Do not tune Model2 threshold, V5, CRS or Fast Path on those final cases.
4. For human-task or organic claims, obtain actual participants or an authorized application/log
   source. Organic traffic starts in shadow with private capture rules and blind adjudication;
   unlabeled requests stay `UNKNOWN`. The six CTF apps and scripted replay cannot supply R by themselves.

The capture schema also supports a separate `L2_AGENT_LAB` population for browser sessions performed
by an agent such as Claude. Such rows require `label_basis=agent_task`, `generator_id` and `task_id`;
they remain laboratory traffic and are never labeled human or organic.

No Git commit or push was made in this preparation.
