"""
Functional verification with REAL V4 and V5 services: the four modes, the routes, the return to V4
and L1/L2/L3 with independent reception. Reverse proxy, HTTP/1.1 cleartext only.

    .venv-dataplane/bin/python scripts/gateway_ops/real_check.py --out <evidence dir> --work <private dir> \
        --manifest <manifest.json> --v4-url http://127.0.0.1:8000 --v5-url http://127.0.0.1:8001 \
        --v4-log <service log> --v5-log <service log> --inputs <private inputs.jsonl> --label reference

The services are started separately, in visible terminals. This program starts and stops only its own
gateway, sink and workers.

WITH V4 AND V5 BOTH LOADED NO TIME HERE IS A BENCHMARK: they share one GPU. Use real_perf.py.

REFERENCES ARE NOT GROUND TRUTH. The population is the project's authored DEV cohort. Its BLOCK
references are constructed attempts, and JWT/CSRF cases need state to be concluded at all. L1 is
agreement with that reference. L3 says whether a request reached an inert sink, not whether anything
was exploited. The historical eval.jsonl cohort is not used: its references are weak.

PRIVACY. `--work` holds gateway logs, whose V4 path lines carry request paths, and must stay out of the
repository. `--out` gets closed codes, identifiers and booleans only.
"""
import argparse
import collections
import dataclasses
import json
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path[:0] = [HERE, os.path.join(REPO, "data_plane")]

import live_check as LC      # noqa: E402
import live_stack as L       # noqa: E402

CONTEXT_FAMILIES = ("jwt", "csrf")
BENIGN_FAMILIES = ("benign_twin", "benign_probe")
OUT_OF_VOCABULARY_FAMILIES = ("ssrf", "open_redirect", "jwt", "csrf", "other_attack")

HOST = b"Host: shop.local\r\n"
BENIGN = LC.BENIGN
# Authored here. The baseline34 lab policy defers it and the reference V5 blocks it, so it exercises the
# DEFER -> V5 BLOCK route. That is a route fixture, not a statement about either model.
V5_BLOCKED = b"GET /ping?host=127.0.0.1;cat+/etc/passwd HTTP/1.1\r\n" + HOST + b"\r\n"
TRAVERSAL = LC.TRAVERSAL
HEALTHZ = LC.HEALTHZ
TWO_TYPES = b"GET /a HTTP/1.1\r\n" + HOST + b"Content-Type: a/b\r\nContent-Type: c/d\r\n\r\n"
HTTP10 = b"GET /a HTTP/1.0\r\n" + HOST + b"\r\n"
DUP_CL = LC.POST_HEAD + b"Content-Length: 1\r\nContent-Length: 2\r\n\r\nab"
OVERRIDES = dict(v4_timeout=8.0, v5_timeout=8.0, deadline=20.0)
FAST_TIMEOUT = dict(v4_timeout=8.0, v5_timeout=0.001, deadline=20.0)


def count_lines(path, pattern):
    regex = re.compile(pattern)
    with open(path, encoding="utf-8", errors="replace") as fh:
        return sum(1 for line in fh if regex.search(line))


class Services:
    """Real calls are counted in the services' own logs: independent of what the gateway records."""

    def __init__(self, args):
        self.v4_log, self.v5_log = args.v4_log, args.v5_log

    def v4_calls(self):
        return count_lines(self.v4_log, r"classify: received request")

    def v5_calls(self):
        return count_lines(self.v5_log, r"classify: (ok|invalid)")

    def settle(self, delay=0.15):
        time.sleep(delay)


class Tail:
    def __init__(self, path):
        self.path, self.position = path, 0

    def read(self):
        if not os.path.exists(self.path):
            return []
        with open(self.path, encoding="utf-8") as fh:
            fh.seek(self.position)
            rows = []
            while True:
                start = fh.tell()
                line = fh.readline()
                if not line.endswith("\n"):
                    fh.seek(start)
                    break
                rows.append(json.loads(line))
            self.position = fh.tell()
        return rows


def send_case(stack, tail, raw, *, wait_for=None, timeout=20.0):
    """One request, sequential. Returns (status, delivered, new records)."""
    sink_before = len(stack.sink_records())
    client_start = time.perf_counter()
    statuses = stack.send([raw], timeout=timeout)
    client_ms = (time.perf_counter() - client_start) * 1000
    rows = []
    if wait_for is not None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            rows += tail.read()
            if wait_for(rows):
                break
            time.sleep(0.01)
    time.sleep(0.02)
    rows += tail.read()
    delivered = len(stack.sink_records()) - sink_before
    return statuses[0], delivered, rows, client_ms


def is_decision(rows):
    return any(r.get("kind") == "decision" for r in rows)


def decision_of(rows):
    found = [r for r in rows if r.get("kind") == "decision"]
    return found[-1] if found else None


def verify_case(stack, tail, checks, group, name, raw, *, status, delivered, stage=None,
                services=None, v5_delta=None, v4_delta=None, wait_for=is_decision):
    v5_before = services.v5_calls() if services else None
    v4_before = services.v4_calls() if services else None
    got, reached, rows, _ = send_case(stack, tail, raw, wait_for=wait_for)
    decision = decision_of(rows)
    actual_stage = decision.get("deciding_stage") if decision else "none"
    ok = got in (status if isinstance(status, tuple) else (status,)) and reached == delivered
    if stage is not None:
        ok = ok and actual_stage == stage
    observed = dict(status=got, delivered=reached, stage=actual_stage,
                    reason=(decision or {}).get("reason"))
    if services:
        services.settle()
        observed["v5_calls"] = services.v5_calls() - v5_before
        observed["v4_calls"] = services.v4_calls() - v4_before
        if v5_delta is not None:
            ok = ok and observed["v5_calls"] == v5_delta
        if v4_delta is not None:
            ok = ok and observed["v4_calls"] == v4_delta
    if decision and decision.get("wire_sha256") and reached:
        sink = stack.sink_records()[-1]
        observed["decided_equals_delivered"] = sink["wire_sha256"] == decision["wire_sha256"]
        ok = ok and observed["decided_equals_delivered"]
    checks.add(group, name, ok, **observed)
    return decision


def start(stack):
    stack.start()
    return Tail(os.path.join(stack.workdir, "decisions.jsonl"))


def group_routes(args, checks, services):
    """CASCADE_ACTIVE: every route, real services, the real return to V4."""
    group = "active_routes"
    stack = LC.make_stack(args, f"{args.label}_active", mode="CASCADE_ACTIVE", fast_path=True,
                          overrides=OVERRIDES)
    tail = start(stack)
    try:
        detail = stack.wait_ready(timeout=30.0, require_cascade=True)
        checks.add(group, "ready against the real V5 contract", not detail["cascade_problems"],
                   detail=detail)
        v = lambda *a, **k: verify_case(stack, tail, checks, group, *a, services=services, **k)  # noqa: E731
        v("V5 route: forwarded on a real ALLOW", BENIGN, status=200, delivered=1, stage="v5",
          v5_delta=1, v4_delta=0)
        v("V5 route: denied on a real BLOCK", V5_BLOCKED, status=403, delivered=0, stage="v5", v5_delta=1,
          v4_delta=0)
        decision = v("Model 2 route: early BLOCK, no V5 call", TRAVERSAL, status=403, delivered=0,
                     stage="model2", v5_delta=0, v4_delta=0)
        checks.add(group, "Model 2 policy stays LAB_EXPERIMENTAL in the record",
                   (decision or {}).get("model2", {}).get("policy_status") == "LAB_EXPERIMENTAL")
        v("Fast Path fixture route: no synchronous model call", HEALTHZ, status=200, delivered=1,
          stage="fast_path", v4_delta=0)
        audits = LC.wait_records(stack, lambda r: r.get("kind") == "fast_path_audit", 5.0)
        checks.add(group, "real V5 audited the fixture permit, no retroactive effect",
                   audits and audits[-1]["status"] == "AUDITED"
                   and audits[-1]["retroactive_effect"] == "none", verdict=(audits or [{}])[-1].get("verdict"))
        v("canonical reject: protocol answer, no model", TWO_TYPES, status=400, delivered=0,
          stage="protocol", v5_delta=0, v4_delta=0)
        v("out of scope: HTTP/1.0", HTTP10, status=505, delivered=0, stage="framing", v5_delta=0,
          v4_delta=0)
        v("ambiguous framing stopped before the addon", DUP_CL, status=(400, 403, 501, 502),
          delivered=0, v5_delta=0, v4_delta=0, wait_for=None)

        LC._kill_model2(stack)
        v("Model 2 worker killed: defers to the real V5", BENIGN, status=200, delivered=1, stage="v5",
          v5_delta=1)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline and stack.status()["model2_worker"]["state"] != "READY":
            time.sleep(0.05)
        v("Model 2 worker restarted: early BLOCK again", TRAVERSAL, status=403, delivered=0,
          stage="model2", v5_delta=0)

        # Return to V4 without a restart, against the real V4.
        stack.rollback(True)
        before = len(stack.sink_records())
        v4_before, v5_before = services.v4_calls(), services.v5_calls()
        status = stack.send([BENIGN], timeout=20.0)[0]
        services.settle()
        checks.add(group, "return to V4: real V4 decides, real V5 not called",
                   services.v4_calls() == v4_before + 1 and services.v5_calls() == v5_before
                   and (status == 200) == (len(stack.sink_records()) == before + 1),
                   status=status, effective=stack.status()["effective_mode"])
        ready, body = stack.admin("/readyz")
        checks.add(group, "readiness follows V4 during the return", ready == 200, body=body[:160].decode())
        stack.rollback(False)
        stack.wait_ready(timeout=10.0)
        v("authority back to the cascade", BENIGN, status=200, delivered=1, stage="v5", v5_delta=1,
          v4_delta=0)
        privacy = LC._privacy_scan(stack)
        checks.add(group, "no sentinel of these requests in records or log", not privacy, hits=privacy)
    finally:
        stack.stop()

    # A real timeout: the service is healthy, the client gives up.
    stack = LC.make_stack(args, f"{args.label}_active_timeout", mode="CASCADE_ACTIVE",
                          overrides=FAST_TIMEOUT)
    tail = start(stack)
    try:
        stack.wait_ready(timeout=30.0, require_cascade=True)
        verify_case(stack, tail, checks, group, "real V5 timeout denies", BENIGN, status=503,
                    delivered=0, stage="v5")
    finally:
        stack.stop()


def group_contract(args, checks, services):
    """A manifest that does not describe the running service must stop readiness."""
    group = "real_contract"
    with open(args.manifest, encoding="utf-8") as fh:
        document = json.load(fh)
    variants = {
        "another recipe": (lambda d: d["v5"].update(recipe_sha256="0" * 64), "v5_recipe_sha256_mismatch"),
        "another adapter": (lambda d: d["v5"].update(adapter_sha256="0" * 64), "v5_adapter_mismatch"),
        "another runtime profile": (lambda d: d["v5"].update(runtime_profile_sha256="0" * 64),
                                    "v5_runtime_profile_mismatch"),
        "another vocabulary": (lambda d: d["v5"]["vocabulary"].append("x"), "v5_vocabulary_mismatch"),
    }
    if "runtime_profile_sha256" in document["v5"]:
        variants["a manifest that names no runtime profile"] = (
            lambda d: d["v5"].pop("runtime_profile_sha256"), "v5_runtime_profile_mismatch")
    for name, (change, reason) in variants.items():
        doc = json.loads(json.dumps(document))
        change(doc)
        path = os.path.join(args.work, f"{args.label}_manifest_{reason}.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh)
        stack = LC.make_stack(args, f"{args.label}_contract_{reason}", mode="CASCADE_ACTIVE",
                              overrides=OVERRIDES, manifest=path)
        tail = start(stack)
        try:
            detail = stack.wait_ready(want=False, timeout=15.0)
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline and reason not in detail["cascade_problems"]:
                time.sleep(0.05)
                detail = json.loads(stack.admin("/readyz")[1])
            status = stack.send([BENIGN], timeout=10.0)[0]
            checks.add(group, f"{name}: not ready, fail-closed",
                       reason in detail["cascade_problems"] and status == 503
                       and not stack.sink_records(), status=status,
                       problems=detail["cascade_problems"])
        finally:
            stack.stop()


def group_observe(args, checks, services):
    group = "observe"
    stack = LC.make_stack(args, f"{args.label}_observe", mode="CASCADE_OBSERVE", overrides=OVERRIDES)
    tail = start(stack)
    computed = lambda rows: any(r.get("observation") for r in rows)  # noqa: E731
    try:
        stack.wait_ready(timeout=30.0, require_cascade=True)
        for name, raw in (("benign", BENIGN), ("v5_blocked", V5_BLOCKED), ("traversal", TRAVERSAL)):
            v4_before = services.v4_calls()
            status, delivered, rows, _ = send_case(stack, tail, raw, wait_for=computed)
            record = decision_of(rows) or {}
            services.settle()
            checks.add(group, f"{name}: V4 decides, cascade recorded beside it",
                       services.v4_calls() == v4_before + 1 and record.get("deciding_stage") == "v4"
                       and record.get("cascade_applied") in ("FORWARD", "DENY")
                       and (status == 200) == (delivered == 1)
                       and (record.get("applied") == "FORWARD") == (status == 200),
                       status=status, delivered=delivered, v4=record.get("applied"),
                       cascade=record.get("cascade_applied"), cascade_stage=record.get("cascade_stage"))
        LC._kill_model2(stack)
        status, delivered, rows, _ = send_case(stack, tail, BENIGN, wait_for=computed)
        checks.add(group, "Model 2 worker killed: V4 action unchanged", status == 200 and delivered == 1,
                   status=status)
    finally:
        stack.stop()

    stack = LC.make_stack(args, f"{args.label}_observe_timeout", mode="CASCADE_OBSERVE",
                          overrides=FAST_TIMEOUT)
    tail = start(stack)
    try:
        stack.wait_ready(timeout=30.0, require_cascade=True)
        status, delivered, rows, _ = send_case(stack, tail, BENIGN, wait_for=computed)
        record = decision_of(rows) or {}
        checks.add(group, "real V5 timeout in the cascade: V4 action unchanged, DENY only recorded",
                   status == 200 and delivered == 1 and record.get("cascade_applied") == "DENY",
                   status=status, cascade=record.get("cascade_applied"))
    finally:
        stack.stop()


def group_v5_only(args, checks, services):
    group = "v5_only"
    stack = LC.make_stack(args, f"{args.label}_v5only", mode="V5_ONLY", overrides=OVERRIDES)
    tail = start(stack)
    try:
        stack.wait_ready(timeout=30.0, require_cascade=True)
        v = lambda *a, **k: verify_case(stack, tail, checks, group, *a, services=services, **k)  # noqa: E731
        v("real V5 allows", BENIGN, status=200, delivered=1, stage="v5", v5_delta=1, v4_delta=0)
        v("real V5 blocks", V5_BLOCKED, status=403, delivered=0, stage="v5", v5_delta=1, v4_delta=0)
        status, delivered, rows, _ = send_case(stack, tail, TRAVERSAL, wait_for=is_decision)
        decision = decision_of(rows) or {}
        checks.add(group, "no Model 2 and no Fast Path consulted",
                   decision.get("model2") is None and decision.get("fast_path") is None
                   and decision.get("deciding_stage") == "v5", status=status)
    finally:
        stack.stop()


def group_v4_only(args, checks, services):
    group = "v4_only"
    stack = LC.make_stack(args, f"{args.label}_v4only", mode="V4_ONLY", overrides=OVERRIDES)
    stack.start()
    try:
        for name, raw in (("benign", BENIGN), ("v5_blocked", V5_BLOCKED)):
            v4_before, v5_before = services.v4_calls(), services.v5_calls()
            before = len(stack.sink_records())
            status = stack.send([raw], timeout=20.0)[0]
            delivered = len(stack.sink_records()) - before
            services.settle()
            checks.add(group, f"{name}: real V4 decides, V5 not called, no runtime",
                       services.v4_calls() == v4_before + 1 and services.v5_calls() == v5_before
                       and status in (200, 403) and (status == 200) == (delivered == 1)
                       and stack.admin("/readyz")[0] is None, status=status, delivered=delivered)
    finally:
        stack.stop()


def reference_kind(row):
    family = row.get("family")
    if family in BENIGN_FAMILIES:
        return "authored_benign"
    if family in CONTEXT_FAMILIES:
        return "authored_attempt_needs_state_context"
    return "authored_constructed_attempt"


def population(args, checks, services, mode):
    """Every authored DEV case, in order, through one mode. Returns safe per-case rows."""
    group = f"population_{mode}"
    with open(args.inputs, encoding="utf-8") as fh:
        rows = [json.loads(line) for line in fh]
    rows = [r for r in rows if r["cohort"] == "authored_paired_dev"]
    if args.limit:
        rows = rows[:args.limit]
    stack = LC.make_stack(args, f"{args.label}_population_{mode}", mode=mode, overrides=OVERRIDES)
    tail = start(stack)
    output = []
    v5_start, v4_start = services.v5_calls(), services.v4_calls()
    observing = mode == "CASCADE_OBSERVE"
    wait = None if mode == "V4_ONLY" else (
        (lambda r: any(x.get("observation") for x in r)) if observing else is_decision)
    started = time.time()
    try:
        if mode != "V4_ONLY":
            stack.wait_ready(timeout=30.0, require_cascade=True)
        else:
            time.sleep(1.0)
        for i, row in enumerate(rows):
            status, delivered, new, client_ms = send_case(stack, tail, row["wire"].encode("utf-8"),
                                                          wait_for=wait)
            record = decision_of(new) or {}
            if mode == "V4_ONLY" or (observing and "applied" not in record):
                # V4 acted. L2 is about that action, so a skipped observation is not an L2 fault;
                # it is counted apart in `observations`.
                record = {**record, "applied": "FORWARD" if status == 200 else "DENY",
                          "deciding_stage": "v4"}
            levels = LC.l_levels(row["id"], row["label"], record, status, delivered == 1,
                                 reference_kind(row))
            levels.update({
                "family": row.get("family"), "mode": mode, "http_status": status,
                "client_ms": client_ms, "applied": record.get("applied"),
                "cascade_applied": record.get("cascade_applied"),
                "cascade_stage": record.get("cascade_stage"), "observation": record.get("observation"),
                "reason": record.get("reason"),
                "v5": {k: (record.get("v5") or {}).get(k) for k in ("status", "decision", "invalid_reason")},
                "model2": {k: (record.get("model2") or {}).get(k) for k in ("status", "decision", "p_block")},
                "fast_path": (record.get("fast_path") or {}).get("decision")})
            output.append(levels)
            if (i + 1) % 50 == 0:
                print(f"  {mode}: {i + 1}/{len(rows)}", flush=True)
        status_doc = stack.status() if mode != "V4_ONLY" else None
    finally:
        stack.stop()
    services.settle(0.3)
    summary = summarize(output)
    summary.update(mode=mode, duration_s=time.time() - started,
                   real_v5_calls=services.v5_calls() - v5_start,
                   real_v4_calls=services.v4_calls() - v4_start, final_status=status_doc)
    checks.add(group, "every case answered", len(output) == len(rows) and not summary["no_response"],
               cases=len(output), no_response=summary["no_response"])
    checks.add(group, "L2 conformant on every case", summary["L2_conformant"] == len(output),
               conformant=summary["L2_conformant"], cases=len(output))
    if mode == "V4_ONLY":
        checks.add(group, "V5 never called", summary["real_v5_calls"] == 0)
    if mode == "V5_ONLY":
        checks.add(group, "V4 never called", summary["real_v4_calls"] == 0)
    if mode == "CASCADE_ACTIVE":
        checks.add(group, "V4 never called, V5 only on deferred requests",
                   summary["real_v4_calls"] == 0
                   and summary["real_v5_calls"] == summary["routes"].get("v5", 0),
                   v5_calls=summary["real_v5_calls"], routes=summary["routes"])
    if observing:
        checks.add(group, "every case observed", summary["observations"].get("computed") == len(output),
                   observations=summary["observations"])
    return output, summary


def summarize(rows):
    kinds = collections.defaultdict(collections.Counter)
    families = collections.defaultdict(collections.Counter)
    for r in rows:
        kinds[r["reference_kind"]][r["L1_decision"]] += 1
        kinds[r["reference_kind"]][r["L3_outcome"]] += 1
        families[r["family"]][r["L1_decision"]] += 1
    return {
        "cases": len(rows),
        "no_response": sum(1 for r in rows if r["http_status"] is None),
        "http_statuses": dict(collections.Counter(str(r["http_status"]) for r in rows)),
        "L1_agrees_with_reference": sum(r["L1_agrees_with_reference"] for r in rows),
        "L2_conformant": sum(r["L2_conformant"] for r in rows),
        "L3_outcomes": dict(collections.Counter(r["L3_outcome"] for r in rows)),
        "routes": dict(collections.Counter(r["deciding_stage"] for r in rows)),
        "reasons": dict(collections.Counter(str(r["reason"]) for r in rows)),
        "cascade_routes": dict(collections.Counter(str(r["cascade_stage"]) for r in rows)),
        "observations": dict(collections.Counter(str(r["observation"]) for r in rows)),
        "by_reference_kind": {k: dict(v) for k, v in kinds.items()},
        "by_family": {k: dict(v) for k, v in families.items()},
        "out_of_vocabulary_families": list(OUT_OF_VOCABULARY_FAMILIES),
    }


GROUPS = {"active_routes": group_routes, "real_contract": group_contract, "observe": group_observe,
          "v5_only": group_v5_only, "v4_only": group_v4_only}
MODES = ("V4_ONLY", "V5_ONLY", "CASCADE_OBSERVE", "CASCADE_ACTIVE")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--inputs", required=True)
    parser.add_argument("--v4-url", required=True)
    parser.add_argument("--v5-url", required=True)
    parser.add_argument("--v4-log", required=True)
    parser.add_argument("--v5-log", required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("--group", action="append", choices=tuple(GROUPS))
    parser.add_argument("--population", action="append", choices=MODES)
    parser.add_argument("--limit", type=int, default=0)
    args = parser.parse_args()
    args.work = os.path.join(args.work, args.label)
    os.makedirs(args.out, exist_ok=True)
    os.makedirs(args.work, exist_ok=True)

    checks = LC.Checks()
    services = Services(args)
    started = time.time()
    summaries = {}
    selected = args.group if args.group is not None else list(GROUPS)
    for name in selected:
        print(f"=== {name}", flush=True)
        try:
            GROUPS[name](args, checks, services)
        except Exception as exc:  # noqa: BLE001 — a group that dies is a failed check, not a skip
            checks.add(name, "group completed", False, error=f"{type(exc).__name__}: {exc}")
    for mode in (args.population if args.population is not None else MODES):
        print(f"=== population {mode}", flush=True)
        try:
            rows, summary = population(args, checks, services, mode)
        except Exception as exc:  # noqa: BLE001
            checks.add(f"population_{mode}", "group completed", False,
                       error=f"{type(exc).__name__}: {exc}")
            continue
        summaries[mode] = summary
        with open(os.path.join(args.out, f"{args.label}_population_{mode}.jsonl"), "x",
                  encoding="utf-8") as fh:
            for row in rows:
                fh.write(json.dumps(row, sort_keys=True) + "\n")
    failed = [c for c in checks.rows if not c["passed"]]
    result = {
        "schema": "firewall-gateway-real-check/v1", "label": args.label,
        "scope": "REAL V4 and V5 on DEV; both loaded on one GPU, so no time here is a benchmark. "
                 "Reverse proxy, HTTP/1.1 cleartext. Not a deployment, D70, P9/R3, Fast Path or "
                 "threshold approval.",
        "reference_note": "References are authored expectations, not confirmed attacks. JWT/CSRF "
                          "need state. L3 delivery to an inert sink is not exploitation.",
        "started_utc": started, "duration_s": time.time() - started, "checks": checks.rows,
        "total": len(checks.rows), "passed": len(checks.rows) - len(failed), "failed": len(failed),
        "population": summaries}
    with open(os.path.join(args.out, f"{args.label}_real_check.json"), "x", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(f"TOTAL {result['passed']}/{result['total']} passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
