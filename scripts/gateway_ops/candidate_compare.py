"""
Every case of a delivered evaluation, as a real request through the gateway, one mode at a time.

    .venv-dataplane/bin/python scripts/gateway_ops/candidate_compare.py --manifest <v2 manifest> \
        --mode V5_ONLY --cases <cases.private.jsonl> --wires <inputs.private.jsonl> \
        --census <predictions.jsonl> --out <new directory> --work <private directory>

A census asks the V5 API directly. This sends bytes to the gateway and keeps what each layer did apart,
because they answer different questions and none of them implies another:

  classification   what Model 2 and V5 said, compared with a reference that is an expectation
  action           what the gateway applied
  status           the HTTP status the client read
  reception        what the independent sink got, by hash of the bytes sent

THE WIRE. Authored cases have a recorded wire. URL cases exist only as canonical text, so a wire is built
from it. That wire proves nothing until the canonical text the gateway derives from it is the census's:
the forwarder between the gateway and V5 hashes what V5 receives. A case whose hash differs is reported,
never counted as a verified round trip. Model 2's early blocks never reach V5, so that check needs
V5_ONLY over the same wires.

The gateway acts on the status and the decision and does not keep the reason sentence, so a census is
compared on those two. Reasons belong to the census.

The destination is an inert sink: a delivered request proves delivery and says nothing of effect. The
cohorts are known DEV and selection data, so nothing here is an independent evaluation, and nothing here
selects a threshold, a runtime or a candidate. `--out` gets ids, closed codes and numbers only.
"""
import argparse
import collections
import hashlib
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path[:0] = [HERE, os.path.join(REPO, "data_plane")]

import canonical_request as cr    # noqa: E402
import candidate_walkthrough as W  # noqa: E402
import fault_proxy as FP          # noqa: E402
import gpu_gate                   # noqa: E402
import live_check as LC           # noqa: E402
import load_lib as LL             # noqa: E402
import real_check as R            # noqa: E402

MODES = ("V5_ONLY", "CASCADE_ACTIVE")
SCHEMA = "firewall-candidate-compare/v1"


def build_wire(canonical_text):
    """A request whose canonical form should be `canonical_text`. Only the gateway can confirm it."""
    parts = cr.parse_canonical(canonical_text)
    head = [parts.method + b" " + parts.target + b" HTTP/1.1", R.HOST.rstrip(b"\r\n")]
    head += [name + b": " + value for name, value in parts.headers]
    if parts.body:
        head.append(b"Content-Length: %d" % len(parts.body))
    return b"\r\n".join(head) + b"\r\n\r\n" + parts.body


def file_sha256(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def read_jsonl(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def load_population(cases_path, wires_path, cohort=None, limit=0):
    recorded = {r["id"]: r for r in read_jsonl(wires_path) if r.get("wire_ok")}
    population = []
    for case in read_jsonl(cases_path):
        if cohort and case["cohort"] != cohort:
            continue
        known = recorded.get(case["id"])
        wire = known["wire"].encode("utf-8") if known else build_wire(case["canonical_text"])
        population.append({**case, "wire_bytes": wire, "wire_origin": "recorded" if known else "built",
                           "wire_sha256": hashlib.sha256(wire).hexdigest()})
    return population[:limit or None]


def layered_row(case, mode, status, received, record, *, sink_sha256, seen_sha256, client_ms, census):
    """The four layers of one case. `seen_sha256` is what V5 got, None when nothing reached it."""
    v5 = {**(record.get("v5") or {}), **(record.get("v5_service") or {})}
    model2 = record.get("model2") or {}
    called_v5 = v5.get("status") is not None and seen_sha256 is not None
    return {
        "id": case["id"], "cohort": case["cohort"], "category": case.get("category"), "mode": mode,
        "carrier": case.get("carrier"), "reference": case["label"], "wire_origin": case["wire_origin"],
        "canonical_outcome": record.get("canonical_outcome"),
        "canonical_equals_census": seen_sha256 == case["canonical_sha256"] if called_v5 else None,
        "classification": {
            "model2": {k: model2.get(k) for k in ("status", "decision", "p_block")},
            "v5": {k: v5.get(k) for k in ("status", "decision", "invalid_reason", "decoder_verified",
                                          "decoder_fallback", "generated_tokens")}},
        "action": {"applied": record.get("applied"), "deciding_stage": record.get("deciding_stage"),
                   "reason": record.get("reason")},
        "status": status,
        "reception": {"received": received,
                      "bytes_equal_sent": sink_sha256 == case["wire_sha256"] if received else None},
        "v5_equals_census": (v5.get("status"), v5.get("decision")) == (census["status"], census["decision"])
                            if census and called_v5 else None,
        "client_ms": client_ms, "gateway_ms": record.get("gateway_ms")}


def run_population(args, population, census, out_rows):
    """One service, one gateway, every case in order, one at a time."""
    service = W.V5Service(args)
    service.start()
    proxy, stack = None, None
    rows, started = [], time.time()
    try:
        service.wait()
        proxy = FP.FaultProxy(service.url)
        args.v5_url, args.v4_url = proxy.url, W.UNUSED_V4
        stack = LC.make_stack(args, f"compare_{args.mode}", mode=args.mode, overrides=R.OVERRIDES)
        tail = R.start(stack)
        stack.wait_ready(timeout=W.READY_TIMEOUT, require_cascade=True)
        status_doc = stack.status()
        with open(out_rows, "x", encoding="utf-8") as fh:
            for index, case in enumerate(population):
                calls = proxy.classify_calls
                status, received, new, client_ms = R.send_case(stack, tail, case["wire_bytes"],
                                                               wait_for=R.is_decision)
                record = R.decision_of(new) or {}
                sink = stack.sink_records()[-1]["wire_sha256"] if received else None
                seen = proxy.canonical_sha256 if proxy.classify_calls > calls else None
                row = layered_row(case, args.mode, status, received, record, sink_sha256=sink,
                                  seen_sha256=seen, client_ms=client_ms, census=census.get(case["id"]))
                rows.append(row)
                fh.write(json.dumps(row, sort_keys=True) + "\n")
                fh.flush()
                if (index + 1) % 200 == 0:
                    print(f"  {args.mode}: {index + 1}/{len(population)}", flush=True)
        final_status = stack.status()
    finally:
        if stack is not None:
            stack.stop()
        if proxy is not None:
            proxy.close()
        service.stop()
    return rows, {"started_utc": started, "duration_s": time.time() - started,
                  "manifest_id": status_doc["manifest_id"], "manifest_sha256": status_doc["manifest_sha256"],
                  "model2_policy_status": status_doc.get("model2_policy_status"),
                  "final_queues": final_status.get("queues")}


def decided(row):
    """The decision of the gateway's classification layers: V5 if it answered, else Model 2's block."""
    v5 = row["classification"]["v5"]
    if v5["status"] == "ok":
        return v5["decision"]
    if row["classification"]["model2"]["decision"] == "BLOCK":
        return "BLOCK"
    return None


def confusion(rows):
    out = collections.Counter()
    for row in rows:
        decision, reference = decided(row), row["reference"]
        if decision is None:
            out["NO_DECISION"] += 1
        elif reference == "BLOCK":
            out["TP" if decision == "BLOCK" else "FN"] += 1
        else:
            out["FP" if decision == "BLOCK" else "TN"] += 1
    return {k: out.get(k, 0) for k in ("TP", "TN", "FP", "FN", "NO_DECISION")}


def action_follows(row):
    decision, applied = decided(row), row["action"]["applied"]
    return (decision == "ALLOW" and applied == "FORWARD") or (decision == "BLOCK" and applied == "DENY")


def status_follows(row):
    applied = row["action"]["applied"]
    return (applied == "FORWARD" and row["status"] == 200) or \
           (applied == "DENY" and row["status"] in (400, 403, 503))


def reception_follows(row):
    received = row["reception"]["received"]
    if row["action"]["applied"] == "FORWARD":
        return received == 1 and row["reception"]["bytes_equal_sent"] is True
    return received == 0


def summarize(rows):
    by_cohort = collections.defaultdict(list)
    for row in rows:
        by_cohort[row["cohort"]].append(row)
    out = {}
    for cohort, members in sorted(by_cohort.items()):
        reach = [r for r in members if r["canonical_equals_census"] is not None]
        with_census = [r for r in members if r["v5_equals_census"] is not None]
        latency = [r["client_ms"] for r in members if r["status"] is not None]
        out[cohort] = {
            "cases": len(members),
            "wire_origin": dict(collections.Counter(r["wire_origin"] for r in members)),
            "classification": confusion(members),
            "deciding_stage": dict(collections.Counter(str(r["action"]["deciding_stage"]) for r in members)),
            "action": dict(collections.Counter(str(r["action"]["applied"]) for r in members)),
            "status": dict(collections.Counter(str(r["status"]) for r in members)),
            "received": dict(collections.Counter(str(r["reception"]["received"]) for r in members)),
            "action_follows_decision": sum(action_follows(r) for r in members),
            "status_follows_action": sum(status_follows(r) for r in members),
            "reception_follows_action": sum(reception_follows(r) for r in members),
            "round_trip": {"reached_v5": len(reach),
                           "canonical_equal": sum(r["canonical_equals_census"] for r in reach),
                           "different": sorted(r["id"] for r in reach if not r["canonical_equals_census"])},
            "census": {"compared": len(with_census),
                       "same_status_and_decision": sum(r["v5_equals_census"] for r in with_census),
                       "different": sorted(r["id"] for r in with_census if not r["v5_equals_census"])},
            "sequential_client_ms": LL.dist(latency),
            "note": "Sequential classification pass. These times are not a load result."}
    return out


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--mode", required=True, choices=MODES)
    parser.add_argument("--cases", required=True, help="private: the delivered evaluation cases")
    parser.add_argument("--wires", required=True, help="private: recorded wires of the authored cases")
    parser.add_argument("--census", help="that runtime's API predictions, to compare per case")
    parser.add_argument("--cohort", help="only this cohort")
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--out", required=True)
    parser.add_argument("--work", required=True, help="private: holds logs")
    parser.add_argument("--doubles", action="store_true", help="V5 double: proves the harness only")
    args = parser.parse_args(argv)
    if not args.doubles:
        problem = gpu_gate.refusal()
        if problem:
            print(f"REFUSED: {problem}", flush=True)
            return 4
    os.makedirs(args.out, exist_ok=True)
    os.makedirs(args.work, exist_ok=True)
    population = load_population(args.cases, args.wires, args.cohort, args.limit)
    census = {r["id"]: r for r in read_jsonl(args.census)
              if r.get("phase", "quality") == "quality"} if args.census else {}
    rows, run = run_population(args, population, census, os.path.join(args.out, f"rows-{args.mode}.jsonl"))
    document = {
        "schema": SCHEMA, "mode": args.mode, "v5": "double" if args.doubles else "real", "v4": "not used",
        "manifest_file_sha256": file_sha256(args.manifest), **run,
        "cases_sha256": file_sha256(args.cases), "wires_sha256": file_sha256(args.wires),
        "census_sha256": file_sha256(args.census) if args.census else None,
        "scope": "Known DEV and selection data, reverse proxy, HTTP/1.1 cleartext, inert sink. Sequential. "
                 "Not an independent evaluation. No threshold, runtime or candidate selected.",
        "attack_effect": W.ATTACK_EFFECT, "cohorts": summarize(rows)}
    with open(os.path.join(args.out, f"summary-{args.mode}.json"), "x", encoding="utf-8") as fh:
        json.dump(document, fh, indent=2, sort_keys=True)
        fh.write("\n")
    for cohort, part in document["cohorts"].items():
        print(f"{args.mode} {cohort}: {part['classification']} stages={part['deciding_stage']} "
              f"round_trip={part['round_trip']['canonical_equal']}/{part['round_trip']['reached_v5']} "
              f"census_same={part['census']['same_status_and_decision']}/{part['census']['compared']}",
              flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
