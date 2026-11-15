"""
The reproducible walk through a delivered candidate, in the real gateway. Real mitmdump, canonical
workers, Model 2 on CPU, guard and an independent sink process, with V5 real or a double.

    .venv-dataplane/bin/python scripts/gateway_ops/candidate_walkthrough.py --manifest <v2 manifest> \
        --out <new directory> --work <private directory> [--inputs <private inputs.jsonl>] [--doubles]

Without `--doubles` it starts the V5 service of the manifest, so it needs the hand-off in GPU_STATUS.json
and refuses without it. V4 takes no part: the return to V4 is not exercised here.

THREE LAYERS, NEVER ADDED TOGETHER:

  mechanism        what the gateway does, whatever the model says: identity and readiness, each route,
                   Model 2 failure defers, every V5 failure denies, independent reception, recovery.
                   A pass here says the plumbing holds for this candidate. It says nothing of quality.
  classification   the candidate's decisions on the authored DEV cohort against authored references.
                   References are expectations, not confirmed attacks, and JWT/CSRF need state. It
                   needs the real model, so with doubles it is not computed.
  attack_effect    whether anything would have worked against an application. NOT MEASURED: the
                   destination is an inert sink, which proves delivery only.

A route fixture is a request the gateway routes a known way. Which decision V5 takes on it belongs to the
candidate, so a V5 route checks that the action follows the decision, whichever it was.
"""
import argparse
import collections
import json
import os
import signal
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path[:0] = [HERE, os.path.join(REPO, "data_plane")]

import candidate_check as CK      # noqa: E402
import cascade_manifest as CM     # noqa: E402
import fault_proxy as FP          # noqa: E402
import gpu_gate                   # noqa: E402
import live_check as LC           # noqa: E402
import live_stack as L            # noqa: E402
import load_check as LK           # noqa: E402
import real_check as R            # noqa: E402

UNUSED_V4 = "http://127.0.0.1:9"     # nothing listens: no route here may depend on V4
OVERRIDES = dict(v4_timeout=2.0, v5_timeout=3.0, deadline=6.0, worker_backoff=0.2)
READY_TIMEOUT = 30.0
ATTACK_EFFECT = {
    "status": "NOT_MEASURED",
    "why": "The destination is an inert sink. It records exact bytes and answers 200, so a delivered "
           "request proves delivery and never that an attack worked or failed.",
    "needs": "an authorized isolated application with an effect oracle per family; see "
             "docs/cascade_candidate_handoff.md"}


class V5Service:
    """The candidate's V5 service, real or double, as a process of this program."""

    def __init__(self, args):
        self.args = args
        self.port = L.free_port()
        self.url = f"http://127.0.0.1:{self.port}"
        self.proc = None

    def start(self):
        if self.args.doubles:
            argv = [L.PYTHON, os.path.join(HERE, "service_doubles.py"), "--role", "v5", "--port",
                    str(self.port), "--manifest", self.args.manifest]
            env = None
        else:
            argv = ["/usr/bin/python3.12", "-B", "-m", "uvicorn", "--app-dir",
                    os.path.join(REPO, "control_plane"), "v5_classifier_api:app", "--host", "127.0.0.1",
                    "--port", str(self.port)]
            env = {k: v for k, v in os.environ.items() if not k.startswith("FIREWALL_V5_")}
            env.update(LK.SERVICE_ENV)
            env.update(LK.v5_environment(self.args.manifest))
        with open(os.path.join(self.args.work, "v5.log"), "ab") as log:
            self.proc = subprocess.Popen(argv, cwd=REPO, stdout=log, stderr=subprocess.STDOUT, env=env,
                                         start_new_session=True)

    def wait(self, timeout=120.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            status, body = L.http_get(self.url + "/health", timeout=1.0)
            if status == 200 and json.loads(body).get("model_loaded"):
                return
            if self.proc.poll() is not None:
                raise RuntimeError("V5 service exited")
            time.sleep(0.1)
        raise TimeoutError("V5 service did not load")

    def kill(self):
        self.proc.send_signal(signal.SIGKILL)
        self.proc.wait()

    def stop(self):
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=20)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait(timeout=5)


class Calls:
    """V5 calls counted by the forwarder, independently of what the gateway records."""

    def __init__(self, proxy):
        self.proxy = proxy

    def v5_calls(self):
        return self.proxy.classify_calls

    def v4_calls(self):
        return 0

    def settle(self, delay=0.05):
        time.sleep(delay)


def action_follows_decision(stack, tail, checks, calls, group, name, raw):
    """The decision on a V5 route is the candidate's. The gateway must apply it, whichever it is."""
    before = calls.v5_calls()
    status, delivered, rows, _ = R.send_case(stack, tail, raw, wait_for=R.is_decision)
    decision = R.decision_of(rows) or {}
    answered = (decision.get("v5") or {}).get("decision")
    expected = {"ALLOW": (200, 1), "BLOCK": (403, 0)}.get(answered, (503, 0))
    checks.add(group, name, decision.get("deciding_stage") == "v5" and (status, delivered) == expected
               and calls.v5_calls() == before + 1, status=status, delivered=delivered, v5_decision=answered,
               stage=decision.get("deciding_stage"), reason=decision.get("reason"))
    return decision


def group_identity(args, checks, calls, proxy):
    """A service that is not the one in the manifest stops readiness, and nothing is delivered. The
    forwarder changes what the service reports, so the manifest and the real service stay as delivered."""
    group = "identity_readiness"
    manifest = CM.load_manifest(args.manifest)
    v5 = manifest.v5
    variants = (
        ("another adapter", "/health", {"adapter_sha256": "0" * 64}, "v5_adapter_mismatch"),
        ("another recipe", "/contract", {"recipe_sha256": "0" * 64}, "v5_recipe_sha256_mismatch"),
        ("another vocabulary", "/contract", {"vocabulary": list(v5.vocabulary)[:-1]},
         "v5_vocabulary_mismatch"),
        ("another budget", "/contract", {"token_budget_B": v5.token_budget_B - 1},
         "v5_token_budget_B_mismatch"),
        ("another label budget", "/contract", {"label_budget": v5.token_contract.label_budget - 1},
         "v5_label_budget_mismatch"),
        ("another template", "/contract", {"template_fingerprint": "0" * 64},
         "v5_template_fingerprint_mismatch"),
        ("another base revision", "/contract", {"base_revision": "0" * 40}, "v5_base_revision_mismatch"),
        ("another runtime", "/health", {"runtime_profile": {"sha256": "e" * 64, "status": "EXPERIMENTAL"}},
         "v5_runtime_profile_mismatch"))
    for name, path, fields, reason in variants:
        proxy.identity = {path: fields}
        try:
            readiness_refused(args, checks, group, f"{name}: not ready, fail-closed", reason)
        finally:
            proxy.identity = {}


def readiness_refused(args, checks, group, name, reason):
    stack = LC.make_stack(args, f"identity_{reason}", mode="CASCADE_ACTIVE", overrides=OVERRIDES)
    stack.start()
    try:
        detail = stack.wait_ready(want=False, timeout=15.0)
        deadline = time.monotonic() + 8.0
        while time.monotonic() < deadline and reason not in detail["cascade_problems"]:
            time.sleep(0.05)
            detail = json.loads(stack.admin("/readyz")[1])
        status = stack.send([LC.BENIGN], timeout=10.0)[0]
        checks.add(group, name, reason in detail["cascade_problems"] and status == 503
                   and not stack.sink_records(), status=status, problems=detail["cascade_problems"])
    finally:
        stack.stop()


def group_routes(args, checks, calls, proxy):
    group = "routes"
    stack = LC.make_stack(args, "routes", mode="CASCADE_ACTIVE", fast_path=True, overrides=OVERRIDES)
    tail = R.start(stack)
    try:
        detail = stack.wait_ready(timeout=READY_TIMEOUT, require_cascade=True)
        status = stack.status()
        manifest = CM.load_manifest(args.manifest)
        checks.add(group, "ready, and serving this manifest", not detail["cascade_problems"]
                   and status["manifest_id"] == manifest.manifest_id
                   and status["manifest_sha256"] == manifest.sha256, manifest_id=status["manifest_id"])
        checks.add(group, "reported as experimental, never approved",
                   status["manifest_status"] == "EXPERIMENTAL"
                   and status["model2_policy_status"] != "APPROVED")
        action_follows_decision(stack, tail, checks, calls, group, "V5 route: action follows the decision",
                                LC.BENIGN)
        action_follows_decision(stack, tail, checks, calls, group, "V5 route: another request", R.V5_BLOCKED)
        v = lambda *a, **k: R.verify_case(stack, tail, checks, group, *a, services=calls, **k)  # noqa: E731
        v("Model 2 route: early BLOCK, no V5 call", LC.TRAVERSAL, status=403, delivered=0, stage="model2",
          v5_delta=0)
        v("Fast Path fixture route: no synchronous V5 call", LC.HEALTHZ, status=200, delivered=1,
          stage="fast_path")
        audits = LC.wait_records(stack, lambda r: r.get("kind") == "fast_path_audit", 8.0)
        checks.add(group, "the audit of that permit has no retroactive effect",
                   audits and audits[-1]["status"] == "AUDITED" and audits[-1]["retroactive_effect"] == "none",
                   verdict=(audits or [{}])[-1].get("verdict"))
        v("canonical reject: protocol answer, no model", R.TWO_TYPES, status=400, delivered=0,
          stage="protocol", v5_delta=0)
        v("out of scope: HTTP/1.0", R.HTTP10, status=505, delivered=0, stage="framing", v5_delta=0)
        v("ambiguous framing stopped before the addon", R.DUP_CL, status=(400, 403, 501, 502), delivered=0,
          v5_delta=0, wait_for=None)
    finally:
        stack.stop()
        reception(checks, group, stack)


def reception(checks, group, stack):
    """Independent reception against what the gateway decided, for one stack."""
    decided = collections.Counter(r["wire_sha256"] for r in stack.records("decision")
                                  if r.get("applied") == "FORWARD" and r.get("wire_sha256"))
    received = collections.Counter(r["wire_sha256"] for r in stack.sink_records())
    checks.add(group, "independent reception equals the forwarded decisions", decided == received,
               decided=sum(decided.values()), received=sum(received.values()))


def group_model2_failure(args, checks, calls, proxy):
    """Model 2 only ever blocks early. When it fails the request goes on to V5, never to a denial."""
    group = "model2_failure_defers"
    stack = LC.make_stack(args, "model2_failure", mode="CASCADE_ACTIVE", overrides=OVERRIDES)
    tail = R.start(stack)
    try:
        stack.wait_ready(timeout=READY_TIMEOUT, require_cascade=True)
        LC._kill_model2(stack)
        decision = action_follows_decision(stack, tail, checks, calls, group, "worker killed: V5 decides",
                                           LC.TRAVERSAL)
        checks.add(group, "the failure is on record as non-OK",
                   (decision.get("model2") or {}).get("status") not in (None, "OK"),
                   model2=(decision.get("model2") or {}).get("status"))
        wait_model2(stack)
        pids = LC._model2_pids(stack)
        for pid in pids:
            os.kill(pid, signal.SIGSTOP)
        decision = action_follows_decision(stack, tail, checks, calls, group, "worker hung: V5 decides",
                                           LC.TRAVERSAL)
        for pid in pids:
            try:
                os.kill(pid, signal.SIGCONT)
            except ProcessLookupError:
                pass
        wait_model2(stack)
        R.verify_case(stack, tail, checks, group, "worker back: early BLOCK again", LC.TRAVERSAL,
                      status=403, delivered=0, stage="model2", services=calls, v5_delta=0)
    finally:
        stack.stop()
        reception(checks, group, stack)


def wait_model2(stack, timeout=20.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and stack.status()["model2_worker"]["state"] != "READY":
        time.sleep(0.05)


def group_v5_failure(args, checks, calls, proxy):
    """No V5 answer that is not an ok decision may let a request through."""
    group = "v5_failure_denies"
    proxy.hang_seconds = OVERRIDES["v5_timeout"] + 1.0
    stack = LC.make_stack(args, "v5_failure", mode="CASCADE_ACTIVE", overrides=OVERRIDES)
    tail = R.start(stack)
    try:
        stack.wait_ready(timeout=READY_TIMEOUT, require_cascade=True)
        for fault in tuple(FP.ANSWER_FAULTS) + FP.CONNECTION_FAULTS:
            proxy.fault = fault
            try:
                R.verify_case(stack, tail, checks, group, f"{fault}: denied, nothing delivered", LC.BENIGN,
                              status=503, delivered=0, stage="v5", services=calls, v5_delta=0)
            finally:
                proxy.fault = None
        action_follows_decision(stack, tail, checks, calls, group, "service healthy again: V5 decides",
                                LC.BENIGN)
    finally:
        stack.stop()
        reception(checks, group, stack)


def group_recovery(args, checks, calls, proxy, service):
    group = "recovery"
    stack = LC.make_stack(args, "recovery", mode="CASCADE_ACTIVE", overrides=OVERRIDES)
    tail = R.start(stack)
    try:
        stack.wait_ready(timeout=READY_TIMEOUT, require_cascade=True)
        service.kill()
        stack.wait_ready(want=False, timeout=15.0)
        status, delivered, _, _ = R.send_case(stack, tail, LC.BENIGN, wait_for=R.is_decision)
        checks.add(group, "V5 killed: not ready, fail-closed", status == 503 and delivered == 0, status=status)
        started = time.monotonic()
        service.start()
        service.wait()
        stack.wait_ready(timeout=READY_TIMEOUT, require_cascade=True)
        action_follows_decision(stack, tail, checks, calls, group, "V5 back: decisions resume", LC.BENIGN)
        checks.add(group, "time until the service was back in readiness", True,
                   seconds=round(time.monotonic() - started, 2))
        for pid in [p for p, row in LK.proc_table().items()
                    if row[0] == stack.gateway_proc.pid and b"cascade_canonical_worker" in row[3]]:
            os.kill(pid, signal.SIGKILL)
        # A pool learns of a dead worker from the next request or probe. That request may be denied.
        status = stack.send([LC.BENIGN], timeout=10.0)[0]
        checks.add(group, "canonical workers killed: a denial or a decision, nothing else",
                   status in (200, 403, 503), status=status)
        stack.wait_ready(timeout=READY_TIMEOUT, require_cascade=True)
        action_follows_decision(stack, tail, checks, calls, group, "canonical workers back: decisions resume",
                                LC.BENIGN)
        stack.gateway_proc.kill()
        stack.gateway_proc.wait()
        stack.start_gateway()
        stack.wait_port(stack.listen_port)
        stack.wait_ready(timeout=READY_TIMEOUT, require_cascade=True)
        action_follows_decision(stack, tail, checks, calls, group, "gateway restarted: decisions resume",
                                LC.BENIGN)
    finally:
        stack.stop()
        reception(checks, group, stack)


def group_privacy(args, checks, calls, proxy):
    group = "privacy"
    stack = LC.make_stack(args, "privacy", mode="CASCADE_ACTIVE", overrides=OVERRIDES)
    stack.start()
    try:
        stack.wait_ready(timeout=READY_TIMEOUT, require_cascade=True)
        for raw in LC.PRIVACY_REQUESTS:
            stack.send([raw], timeout=10.0)
        hits = LC._privacy_scan(stack)
        checks.add(group, "no sentinel of these requests in records or log", not hits, hits=hits)
    finally:
        stack.stop()


def classification(args, checks, calls):
    """The candidate's decisions on the authored DEV cohort. Agreement with an authored reference is not
    detection quality, and this population selects nothing."""
    with open(args.inputs, encoding="utf-8") as fh:
        rows = [json.loads(line) for line in fh]
    rows = [r for r in rows if r["cohort"] == "authored_paired_dev"][:args.limit or None]
    stack = LC.make_stack(args, "classification", mode="CASCADE_ACTIVE", overrides=OVERRIDES)
    tail = R.start(stack)
    output = []
    try:
        stack.wait_ready(timeout=READY_TIMEOUT, require_cascade=True)
        for row in rows:
            status, delivered, new, _ = R.send_case(stack, tail, row["wire"].encode("utf-8"),
                                                    wait_for=R.is_decision)
            record = R.decision_of(new) or {}
            levels = LC.l_levels(row["id"], row["label"], record, status, delivered == 1, R.reference_kind(row))
            levels.update(family=row.get("family"), http_status=status, reason=record.get("reason"),
                          observation=None, cascade_stage=None,
                          v5={k: (record.get("v5") or {}).get(k) for k in ("status", "decision",
                                                                           "invalid_reason")})
            output.append(levels)
    finally:
        stack.stop()
    summary = R.summarize(output)
    checks.add("classification", "every case answered", not summary["no_response"], cases=len(output))
    checks.add("classification", "L2 conformant on every case", summary["L2_conformant"] == len(output),
               conformant=summary["L2_conformant"], cases=len(output))
    with open(os.path.join(args.out, "classification_rows.jsonl"), "x", encoding="utf-8") as fh:
        for row in output:
            fh.write(json.dumps(row, sort_keys=True) + "\n")
    return {"status": "MEASURED_ON_DEV", "population": "authored_paired_dev", "summary": summary,
            "note": "References are authored expectations, not confirmed attacks. JWT and CSRF need "
                    "state. No threshold, candidate or set was selected from this."}


MECHANISM = (("identity_readiness", group_identity), ("routes", group_routes),
             ("model2_failure_defers", group_model2_failure), ("v5_failure_denies", group_v5_failure),
             ("privacy", group_privacy))


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, help="a v2 candidate manifest")
    parser.add_argument("--out", required=True)
    parser.add_argument("--work", required=True, help="private: holds logs")
    parser.add_argument("--inputs", help="private DEV inputs, for the classification layer")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--doubles", action="store_true", help="V5 double: no GPU, mechanism only")
    parser.add_argument("--group", action="append", help="only these mechanism groups")
    args = parser.parse_args(argv)
    if not args.doubles:
        problem = gpu_gate.refusal()
        if problem:
            print(f"REFUSED: {problem}", flush=True)
            return 4
    os.makedirs(args.out, exist_ok=True)
    os.makedirs(args.work, exist_ok=True)

    checks = LC.Checks()
    identity = argparse.Namespace(manifest=args.manifest, previous=[], gateway_config=None, v5_url=None)
    report, manifest = CK.check(identity)
    for row in report.checks:
        checks.add("delivery", row["check"], row["passed"],
                   **{k: v for k, v in row.items() if k not in ("check", "passed")})
    started = time.time()
    summary = {"status": "NOT_COMPUTED", "why": "the delivery was refused"}
    if not report.failed:
        service = V5Service(args)
        service.start()
        proxy = None
        try:
            service.wait()
            proxy = FP.FaultProxy(service.url)
            args.v5_url, args.v4_url = proxy.url, UNUSED_V4
            calls = Calls(proxy)
            for name, group in MECHANISM:
                if args.group and name not in args.group:
                    continue
                print(f"=== {name}", flush=True)
                try:
                    group(args, checks, calls, proxy)
                except Exception as exc:  # noqa: BLE001 — a group that dies is a failed check, not a skip
                    checks.add(name, "group completed", False, error=f"{type(exc).__name__}: {exc}")
            if not args.group or "recovery" in args.group:
                print("=== recovery", flush=True)
                try:
                    group_recovery(args, checks, calls, proxy, service)
                except Exception as exc:  # noqa: BLE001
                    checks.add("recovery", "group completed", False, error=f"{type(exc).__name__}: {exc}")
            if args.doubles:
                summary = {"status": "NOT_MEANINGFUL_WITH_DOUBLES",
                           "why": "the V5 double answers by a fixed rule"}
            elif args.inputs:
                print("=== classification", flush=True)
                summary = classification(args, checks, calls)
            else:
                summary = {"status": "NOT_RUN", "why": "no --inputs"}
        finally:
            if proxy is not None:
                proxy.close()
            service.stop()
    failed = [c for c in checks.rows if not c["passed"]]
    result = {
        "schema": "firewall-candidate-walkthrough/v1",
        "manifest_id": manifest.manifest_id if manifest else None,
        "manifest_sha256": manifest.sha256 if manifest else None,
        "v5": "double" if args.doubles else "real", "v4": "not used; the return to V4 is not exercised",
        "scope": "Reverse proxy, HTTP/1.1 cleartext, inert sink. Not a deployment, threshold, D70, P9/R3 "
                 "or Fast Path approval.",
        "started_utc": started, "duration_s": time.time() - started,
        "layers": {"mechanism": {"total": len(checks.rows), "failed": len(failed),
                                 "status": "PASSED" if not failed else "FAILED", "checks": checks.rows},
                   "classification": summary, "attack_effect": ATTACK_EFFECT}}
    with open(os.path.join(args.out, "walkthrough.json"), "x", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(f"TOTAL {len(checks.rows) - len(failed)}/{len(checks.rows)} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
