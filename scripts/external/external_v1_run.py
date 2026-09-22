"""External Test v1 — Phase F: execute the FROZEN 400-case set through the gateway + V4.

THREE LEVELS ARE NEVER COLLAPSED (protocol section 2):
  L1 model      ground truth  vs  V4 decision
  L2 gateway    V4 decision   vs  actual data-plane behaviour (D34 contract)
  L3 end-to-end ground truth  vs  did the request reach the protected destination

"Malicious request delivered" == a ground-truth BLOCK request REACHED lab-app. It never means
successful exploitation.

This module keeps OFFLINE logic (frozen-integrity gate, deterministic consistency subset,
L1/L2/L3 outcome derivation, D19 scoring wiring) separate from the LIVE-gateway steps (gateway
replay, direct /classify). The offline pieces are unit-tested; nothing here contacts /classify
or runs V4 until the `gateway`/`direct` subcommands are invoked against a live lab.

Subcommands:
  verify     re-verify frozen integrity (hard-fail) and write run metadata     [offline]
  subset     compute + write the predeclared 100-case direct-consistency subset [offline]
  gateway    replay 400 frozen cases x3 through the data plane                   [LIVE gateway]
  direct     POST the 100-case subset x3 to /classify                           [LIVE control-plane]
  assemble   correlate raw evidence -> results.jsonl with L1/L2/L3              [offline, post-exec]
  score      L1/L2/L3 metrics from results.jsonl (imports D19 score_binary)     [offline, post-exec]
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import spec_lib  # noqa: E402

REPO_ROOT = spec_lib.REPO_ROOT
EXT = os.path.join(REPO_ROOT, "datasets", "external_v1")
FROZEN_CASES = os.path.join(EXT, "cases.jsonl")
FROZEN_MANIFEST = os.path.join(EXT, "manifest.json")

RUN_ID = "external-v1-run-001"
RUN_DIR = os.path.join(REPO_ROOT, "reports", "external", RUN_ID)
FREEZE_COMMIT = "36df2ee"
FROZEN_INTEGRITY_HASH = "ccac5f55eee27f94a79295f0022edf6eac792abe828ed1a1fe5f43ac85c5e52b"

CELLS = spec_lib.BENIGN_SLICES + spec_lib.ATTACK_CATEGORIES

# Direct-consistency subset: predeclared BEFORE execution, independent of any V4 output.
SUBSET_SEED = "external-v1-run-001-consistency"
SUBSET_PER_CELL = 10   # 10 x 10 cells = 100

# Published V4 INTERNAL held-out recall (protocol section 6.2 / task) for the RQ2 gap.
V4_INTERNAL_RECALL = {
    "sqli": (743, 817), "cmdi": (117, 134), "xss": (None, None),
    "path-traversal": (None, None), "ssrf": (62, 63),
}
V4_INTERNAL_RECALL_PCT = {"sqli": 90.94, "cmdi": 87.31, "xss": 100.0,
                          "path-traversal": 100.0, "ssrf": 98.41}


def sha_text(t):
    return hashlib.sha256(t.encode("utf-8")).hexdigest()


def load_jsonl(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


# ══════════════════════════════════════════════════════════════════════════
# frozen-integrity gate (hard-fail before any execution)
# ══════════════════════════════════════════════════════════════════════════
def verify_frozen(cases_path=FROZEN_CASES, manifest_path=FROZEN_MANIFEST):
    problems = []
    m = json.load(open(manifest_path, encoding="utf-8"))
    rows = load_jsonl(cases_path)
    from collections import Counter
    per = Counter(r["primary_cell"] for r in rows)
    dec = Counter(r["expected_decision"] for r in rows)
    if m.get("status") != "FROZEN" or not m.get("frozen"):
        problems.append("manifest status is not FROZEN")
    if len(rows) != 400:
        problems.append(f"cases {len(rows)} != 400")
    if dec.get("ALLOW") != 200:
        problems.append(f"ALLOW {dec.get('ALLOW')} != 200")
    if dec.get("BLOCK") != 200:
        problems.append(f"BLOCK {dec.get('BLOCK')} != 200")
    for c in CELLS:
        if per.get(c) != 40:
            problems.append(f"cell {c} has {per.get(c)} != 40")
    with open(cases_path, "rb") as _f:
        artifact_sha = hashlib.sha256(_f.read()).hexdigest()
    if artifact_sha != m.get("artifact_sha256"):
        problems.append("artifact_sha256 does not match manifest")
    for r in rows:
        if sha_text(r["request_text"]) != r["request_sha256"]:
            problems.append(f"{r['case_id']} request_sha256 does not recompute")
    ordered = sorted(rows, key=lambda r: (CELLS.index(r["primary_cell"]), r["selection_key"]))
    canonical = "\n".join(f"{r['case_id']}|{r['request_sha256']}" for r in ordered)
    ihash = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    if ihash != m.get("integrity_hash"):
        problems.append("recomputed integrity_hash != manifest")
    if ihash != FROZEN_INTEGRITY_HASH:
        problems.append(f"integrity_hash != anchor {FROZEN_INTEGRITY_HASH}")
    return rows, m, ihash, problems


# ══════════════════════════════════════════════════════════════════════════
# deterministic direct-consistency subset (declared before execution)
# ══════════════════════════════════════════════════════════════════════════
def subset_key(case, seed=SUBSET_SEED):
    return hashlib.sha256(
        f"{seed}|{case['primary_cell']}|{case['case_id']}|{case['request_sha256']}"
        .encode("utf-8")).hexdigest()


def consistency_subset(cases, per_cell=SUBSET_PER_CELL, seed=SUBSET_SEED):
    """Balanced 10-per-cell (100 total) chosen by a seeded, content-independent key. Never a
    headline metric; only checks the proxy and the API agree on identical text."""
    by_cell = {c: [] for c in CELLS}
    for case in cases:
        by_cell[case["primary_cell"]].append(case)
    chosen = []
    for cell in CELLS:
        ordered = sorted(by_cell[cell], key=lambda c: subset_key(c, seed))
        chosen.extend(ordered[:per_cell])
    return chosen


# ══════════════════════════════════════════════════════════════════════════
# L1 / L2 / L3 outcome derivation (pure)
# ══════════════════════════════════════════════════════════════════════════
def l1_outcome(ground_truth, decision, status):
    """BLOCK is the positive class. An invalid classifier output is recorded as 'invalid'
    (scoring maps it to the opposite of expected, per D19 / protocol section 3; never coerced
    to a correct decision here)."""
    if status != "ok" or decision not in ("ALLOW", "BLOCK"):
        return "invalid"
    if ground_truth == "BLOCK":
        return "TP" if decision == "BLOCK" else "FN"
    return "FP" if decision == "BLOCK" else "TN"


def l2_conformant(decision, status, http_status, destination_receipt):
    """D34 enforcement contract, judged INDEPENDENTLY of ground truth:
        ALLOW  -> forwarded (receipt present, not a gateway 403/503)
        BLOCK  -> 403 and no receipt
        invalid/fail-closed -> 503 and no receipt
    """
    if status == "ok" and decision == "ALLOW":
        expected = "forward: receipt present, not gateway-blocked"
        ok = destination_receipt is True and http_status not in (403, 503)
    elif status == "ok" and decision == "BLOCK":
        expected = "403 + no receipt"
        ok = http_status == 403 and not destination_receipt
    else:
        expected = "503 + no receipt (fail-closed)"
        ok = http_status == 503 and not destination_receipt
    return ok, expected


def l3_outcome(ground_truth, destination_receipt):
    """End-to-end outcome. 'attack_delivered' == a BLOCK request reached lab-app (NOT
    exploitation)."""
    if ground_truth == "ALLOW":
        return "benign_delivered" if destination_receipt else "benign_broken"
    return "attack_delivered" if destination_receipt else "attack_stopped"


def build_record(case, repetition, channel, decision, reason, status, http_status,
                 destination_receipt, fail_closed_cause, model_latency_ms, sent_sha256):
    gt = case["expected_decision"]
    l2_ok, _ = l2_conformant(decision, status, http_status, destination_receipt)
    return {
        "case_id": case["case_id"], "primary_cell": case["primary_cell"],
        "ground_truth": gt, "repetition": repetition, "channel": channel,
        "registered_sha256": case["request_sha256"], "sent_sha256": sent_sha256,
        "text_matches_registered": (sent_sha256 == case["request_sha256"]
                                    if sent_sha256 is not None else None),
        "decision": decision, "reason": reason, "status": status,
        "http_status": http_status, "destination_receipt": destination_receipt,
        "fail_closed_cause": fail_closed_cause, "model_latency_ms": model_latency_ms,
        "l1_outcome": l1_outcome(gt, decision, status),
        "l2_conformant": l2_ok,
        "l3_outcome": l3_outcome(gt, destination_receipt),
    }


# ══════════════════════════════════════════════════════════════════════════
# determinism across repetitions (never silently majority-vote)
# ══════════════════════════════════════════════════════════════════════════
def determinism_report(records, channel="gateway"):
    """Group a channel's records by case_id; flag any case whose (decision,status) differs
    across repetitions. Headline uses repetition 1; nondeterministic cases are flagged,
    counted, disclosed, and excluded from the headline (protocol section 11)."""
    by_case = {}
    for r in records:
        if r["channel"] != channel:
            continue
        by_case.setdefault(r["case_id"], []).append(r)
    flagged = []
    for cid, reps in by_case.items():
        keys = {(r["decision"], r["status"]) for r in reps}
        if len(keys) > 1:
            flagged.append({"case_id": cid,
                            "repetitions": sorted((r["repetition"], r["decision"], r["status"])
                                                  for r in reps)})
    return flagged


# ══════════════════════════════════════════════════════════════════════════
# data-plane log + receipt parsing (used by `assemble`)
# ══════════════════════════════════════════════════════════════════════════
_ALLOW_RE = re.compile(r"\] ALLOW (\S+ \S+) reason=(.*) \(classifier ([\d.]+) ms\)")
_BLOCK_RE = re.compile(r"\] BLOCK (\S+ \S+) reason=(.*) \(classifier ([\d.]+) ms\)")
_FAILCLOSED_RE = re.compile(r"\] BLOCK \(fail-closed\) (\S+ \S+) cause=(.*) \(after ([\d.]+) ms\)")


def parse_dataplane_log(text):
    """Ordered list of decisions from the data-plane log (one per classified request)."""
    out = []
    for line in text.splitlines():
        m = _FAILCLOSED_RE.search(line)
        if m:
            out.append({"decision": None, "status": "invalid", "reason": None,
                        "target": m.group(1), "fail_closed_cause": m.group(2).strip(),
                        "model_latency_ms": float(m.group(3))})
            continue
        m = _ALLOW_RE.search(line)
        if m:
            out.append({"decision": "ALLOW", "status": "ok", "reason": m.group(2).strip(),
                        "target": m.group(1), "fail_closed_cause": None,
                        "model_latency_ms": float(m.group(3))})
            continue
        m = _BLOCK_RE.search(line)
        if m:
            out.append({"decision": "BLOCK", "status": "ok", "reason": m.group(2).strip(),
                        "target": m.group(1), "fail_closed_cause": None,
                        "model_latency_ms": float(m.group(3))})
    return out


# ══════════════════════════════════════════════════════════════════════════
# L1 scoring (imports the frozen D19 code — never a reimplementation)
# ══════════════════════════════════════════════════════════════════════════
def score_l1(records, score_fn=None):
    """L1 metrics from the gateway channel, repetition 1, excluding nondeterministic cases.
    `score_fn` defaults to the FROZEN D19 scorer (imported lazily — it pulls in torch, so it
    runs in the ML environment at scoring time, not here). Tests inject a stub."""
    if score_fn is None:
        sys.path.insert(0, os.path.join(REPO_ROOT, "scripts", "evaluation"))
        from test_model import score_binary as score_fn  # noqa: E402  frozen D19, BLOCK=positive
    rep1 = [r for r in records if r["channel"] == "gateway" and r["repetition"] == 1]
    flagged = {f["case_id"] for f in determinism_report(records, "gateway")}
    headline = [r for r in rep1 if r["case_id"] not in flagged]
    scored = [{"expected": r["ground_truth"], "predicted": r["decision"], "status": r["status"]}
              for r in headline]
    overall = score_fn(scored)
    per_cell = {}
    for cell in CELLS:
        rows = [{"expected": r["ground_truth"], "predicted": r["decision"], "status": r["status"]}
                for r in headline if r["primary_cell"] == cell]
        per_cell[cell] = score_fn(rows) if rows else None
    return {"overall": overall, "per_cell": per_cell,
            "headline_n": len(headline), "excluded_nondeterministic": sorted(flagged)}


# ══════════════════════════════════════════════════════════════════════════
# CLI
# ══════════════════════════════════════════════════════════════════════════
def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def cmd_verify(args):
    rows, m, ihash, problems = verify_frozen()
    for p in problems:
        print(f"  [FAIL] {p}")
    if problems:
        raise SystemExit("FROZEN INTEGRITY FAILED — refusing to proceed to execution")
    print(f"  [PASS] frozen integrity: 400 cases, 200/200, 40/cell, integrity {ihash[:16]}...")
    os.makedirs(RUN_DIR, exist_ok=True)
    os.makedirs(os.path.join(RUN_DIR, "raw"), exist_ok=True)
    meta = {
        "run_id": RUN_ID, "phase": "F — execution (pre-execution metadata)",
        "generated_utc": _now(), "freeze_commit": FREEZE_COMMIT,
        "frozen_integrity_hash": ihash, "frozen_artifact_sha256": m["artifact_sha256"],
        "status_at_write": "PRE-EXECUTION",
        "v4_exposure": "zero (no /classify contacted yet)",
        "levels": {"L1": "ground truth vs V4 decision", "L2": "V4 decision vs gateway behaviour",
                   "L3": "ground truth vs destination delivery"},
        "execution_plan": {
            "gateway": "400 frozen cases x 3 repetitions = 1200 executions",
            "direct_consistency": f"{SUBSET_PER_CELL*10} cases x 3 = 300 direct /classify calls",
            "headline": "repetition 1; nondeterministic cases flagged and excluded",
            "path": "frozen request -> data-plane -> control-plane /classify -> V4 -> "
                    "enforcement -> lab-app (capture-proxy is NOT the enforcing gateway)",
        },
        "consistency_subset": {"seed": SUBSET_SEED, "per_cell": SUBSET_PER_CELL,
                               "key_formula": "SHA256(seed|primary_cell|case_id|request_sha256)",
                               "declared_before_execution": True, "not_based_on_v4": True},
        "d32_no_overwrite": "the runner refuses to overwrite a run id that already has results",
    }
    with open(os.path.join(RUN_DIR, "run_manifest.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)
    print(f"  wrote {os.path.relpath(RUN_DIR, REPO_ROOT)}/run_manifest.json "
          f"(freeze_commit={FREEZE_COMMIT})")
    return 0


def cmd_subset(args):
    rows, _, _, problems = verify_frozen()
    if problems:
        raise SystemExit("FROZEN INTEGRITY FAILED — refusing to declare a subset")
    sub = consistency_subset(rows)
    os.makedirs(RUN_DIR, exist_ok=True)
    payload = {
        "run_id": RUN_ID, "generated_utc": _now(),
        "purpose": "per-layer consistency control ONLY (proxy vs direct /classify agree on "
                   "identical text). Never a headline metric.",
        "seed": SUBSET_SEED, "per_cell": SUBSET_PER_CELL, "total": len(sub),
        "key_formula": "SHA256(seed|primary_cell|case_id|request_sha256)",
        "declared_before_execution": True, "selected_by": "deterministic key, not V4 output",
        "case_ids_by_cell": {cell: sorted(c["case_id"] for c in sub
                                          if c["primary_cell"] == cell) for cell in CELLS},
    }
    with open(os.path.join(RUN_DIR, "consistency_subset.json"), "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)
    from collections import Counter
    per = Counter(c["primary_cell"] for c in sub)
    print(f"  consistency subset: {len(sub)} cases ({dict(per)})")
    print(f"  wrote {os.path.relpath(RUN_DIR, REPO_ROOT)}/consistency_subset.json")
    return 0


def count_lines(path):
    if not os.path.exists(path):
        return 0
    n = 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for _ in f:
            n += 1
    return n


def _frozen_ordered_and_map():
    rows, m, ihash, problems = verify_frozen()
    if problems:
        for p in problems:
            print(f"  [FAIL] {p}")
        raise SystemExit("FROZEN INTEGRITY FAILED — refusing LIVE execution")
    return rows, {r["case_id"]: r for r in rows}, ihash


# ══════════════════════════════════════════════════════════════════════════
# gateway (LIVE): byte-exact replay of 400 frozen cases x N through the data plane
# ══════════════════════════════════════════════════════════════════════════
def cmd_gateway(args):
    import replay  # raw-socket, byte-exact replay engine (reused, already validated)
    rows, _, ihash = _frozen_ordered_and_map()

    os.makedirs(os.path.join(RUN_DIR, "raw"), exist_ok=True)
    out = os.path.join(RUN_DIR, "raw", "gateway_raw.jsonl")
    if os.path.exists(out) and not args.force:
        raise SystemExit(f"REFUSING to overwrite existing run results: {out} "
                         "(this run id already has gateway results — D32).")

    receipt_log = args.receipt_log
    started = _now()
    print(f"gateway replay: {len(rows)} cases x {args.repetitions} reps -> "
          f"{args.gateway_host}:{args.gateway_port} (byte-exact wire replay)")
    failures = 0
    with open(out, "w", encoding="utf-8") as f:
        for rep in range(1, args.repetitions + 1):
            for i, case in enumerate(rows, 1):
                text = case["request_text"]
                before = count_lines(receipt_log)
                rec = {"run_id": RUN_ID, "case_id": case["case_id"],
                       "primary_cell": case["primary_cell"],
                       "ground_truth": case["expected_decision"], "repetition": rep,
                       "registered_sha256": case["request_sha256"],
                       "sent_sha256": sha_text(text),        # byte-exact (Phase B verified)
                       "method": case.get("method"), "route": case.get("route"),
                       "path": case.get("path")}
                try:
                    r = replay.replay_one(args.gateway_host, args.gateway_port, text,
                                          args.timeout)
                    rec.update({"http_status": r["http_status"],
                                "response_bytes": r["response_bytes"],
                                "elapsed_ms": r["elapsed_ms"], "error": None})
                except Exception as exc:              # preserve the failure, never retry
                    failures += 1
                    rec.update({"http_status": None, "response_bytes": None,
                                "elapsed_ms": None, "error": f"{type(exc).__name__}: {exc}"})
                after = count_lines(receipt_log)
                rec["receipt_delta"] = after - before
                rec["destination_receipt"] = after > before
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                f.flush()
                if args.delay_ms:
                    import time
                    time.sleep(args.delay_ms / 1000.0)
            print(f"  rep {rep}/{args.repetitions} done", flush=True)

    # snapshot destination receipts as committed evidence (not only in docker/.lab-logs)
    if os.path.exists(receipt_log):
        import shutil
        shutil.copyfile(receipt_log, os.path.join(RUN_DIR, "raw", "lab-app-receipts-snapshot.jsonl"))
    meta = {"run_id": RUN_ID, "phase": "F gateway", "freeze_commit": FREEZE_COMMIT,
            "frozen_integrity_hash": ihash, "started_utc": started, "finished_utc": _now(),
            "gateway": f"{args.gateway_host}:{args.gateway_port}",
            "planned_executions": len(rows) * args.repetitions,
            "repetitions": args.repetitions, "failures": failures,
            "note": "capture-proxy NOT used; enforcing data-plane only. No metrics computed here. "
                    "Capture the data-plane decision log separately "
                    "(docker compose logs --no-color data-plane > raw/data-plane.log) for L2."}
    with open(os.path.join(RUN_DIR, "raw", "gateway_meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)
    print(f"  wrote raw/gateway_raw.jsonl ({len(rows)*args.repetitions} rows, {failures} error(s))")
    print("  next: docker compose logs --no-color data-plane > "
          f"{os.path.relpath(RUN_DIR, REPO_ROOT)}/raw/data-plane.log ; then run `assemble`.")
    return 1 if failures else 0


# ══════════════════════════════════════════════════════════════════════════
# direct (LIVE): 100-case consistency subset x N straight to /classify
# ══════════════════════════════════════════════════════════════════════════
def cmd_direct(args):
    import httpx
    _, by_id, ihash = _frozen_ordered_and_map()
    subset_path = args.subset or os.path.join(RUN_DIR, "consistency_subset.json")
    if not os.path.exists(subset_path):
        raise SystemExit(f"predeclared subset not found: {subset_path} (run `subset` first)")
    payload = json.load(open(subset_path, encoding="utf-8"))
    ids = [cid for cell in CELLS for cid in payload["case_ids_by_cell"].get(cell, [])]
    if len(ids) != 100:
        raise SystemExit(f"consistency subset has {len(ids)} != 100 case ids")

    os.makedirs(os.path.join(RUN_DIR, "raw"), exist_ok=True)
    out = os.path.join(RUN_DIR, "raw", "direct_raw.jsonl")
    if os.path.exists(out) and not args.force:
        raise SystemExit(f"REFUSING to overwrite existing direct results: {out} (D32).")

    import time
    started = _now()
    print(f"direct /classify: {len(ids)} subset cases x {args.repetitions} reps -> "
          f"{args.classifier_url} (consistency control only, NOT headline)")
    failures = 0
    with open(out, "w", encoding="utf-8") as f, httpx.Client(timeout=args.timeout,
                                                             trust_env=False) as c:
        for rep in range(1, args.repetitions + 1):
            for cid in ids:
                case = by_id[cid]
                text = case["request_text"]
                rec = {"run_id": RUN_ID, "case_id": cid, "primary_cell": case["primary_cell"],
                       "ground_truth": case["expected_decision"], "repetition": rep,
                       "registered_sha256": case["request_sha256"], "sent_sha256": sha_text(text),
                       "channel": "direct"}
                t0 = time.perf_counter()
                try:
                    resp = c.post(args.classifier_url, json={"request": text})
                    wall = (time.perf_counter() - t0) * 1000
                    body = resp.json() if resp.headers.get("content-type", "").startswith(
                        "application/json") else {}
                    rec.update({"http_status": resp.status_code,
                                "status": body.get("status"), "decision": body.get("decision"),
                                "reason": body.get("reason"),
                                "model_latency_ms": body.get("model_latency_ms"),
                                "wall_ms": round(wall, 2), "error": None})
                except Exception as exc:
                    failures += 1
                    rec.update({"http_status": None, "status": "error", "decision": None,
                                "reason": None, "model_latency_ms": None, "wall_ms": None,
                                "error": f"{type(exc).__name__}: {exc}"})
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                f.flush()
            print(f"  rep {rep}/{args.repetitions} done", flush=True)
    meta = {"run_id": RUN_ID, "phase": "F direct-consistency", "freeze_commit": FREEZE_COMMIT,
            "frozen_integrity_hash": ihash, "started_utc": started, "finished_utc": _now(),
            "classifier_url": args.classifier_url, "planned_calls": len(ids) * args.repetitions,
            "repetitions": args.repetitions, "failures": failures,
            "note": "per-layer consistency control ONLY; never a headline metric."}
    with open(os.path.join(RUN_DIR, "raw", "direct_meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)
    print(f"  wrote raw/direct_raw.jsonl ({len(ids)*args.repetitions} rows, {failures} error(s))")
    return 1 if failures else 0


# ══════════════════════════════════════════════════════════════════════════
# assemble (offline): correlate raw evidence -> results.jsonl, L1/L2/L3 kept separate
# ══════════════════════════════════════════════════════════════════════════
def decision_from_status(http_status):
    """Enforcement-observed decision, per D34: 403->BLOCK, 503->invalid, transport-error->error,
    anything forwarded (2xx/4xx from lab-app)->ALLOW."""
    if http_status is None:
        return None, "error"
    if http_status == 403:
        return "BLOCK", "ok"
    if http_status == 503:
        return None, "invalid"
    return "ALLOW", "ok"


def cmd_assemble(args):
    _, by_id, _ = _frozen_ordered_and_map()
    gw = load_jsonl(args.gateway_raw)
    dp_decisions = []
    if args.dataplane_log and os.path.exists(args.dataplane_log):
        dp_decisions = parse_dataplane_log(open(args.dataplane_log, encoding="utf-8").read())
    dp_aligned = len(dp_decisions) == len(gw)

    results = []
    for idx, g in enumerate(gw):
        case = by_id[g["case_id"]]
        status_dec, status_status = decision_from_status(g.get("http_status"))
        reason, fail_cause, latency, decision_source = None, None, None, "http-status"
        decision, status = status_dec, status_status
        if dp_aligned:
            d = dp_decisions[idx]
            decision, status = d["decision"], d["status"]
            reason, fail_cause, latency = d["reason"], d["fail_closed_cause"], d["model_latency_ms"]
            decision_source = "data-plane-log"
        rec = build_record(case, g["repetition"], "gateway", decision, reason, status,
                           g.get("http_status"), g.get("destination_receipt"), fail_cause,
                           latency, g.get("sent_sha256"))
        rec["decision_source"] = decision_source
        rec["transport_error"] = g.get("error")
        results.append(rec)

    # direct channel (classify-only: no L2/L3)
    direct_by_case_rep = {}
    if args.direct_raw and os.path.exists(args.direct_raw):
        for d in load_jsonl(args.direct_raw):
            rec = {"case_id": d["case_id"], "primary_cell": d["primary_cell"],
                   "ground_truth": d["ground_truth"], "repetition": d["repetition"],
                   "channel": "direct", "decision": d.get("decision"),
                   "reason": d.get("reason"), "status": d.get("status"),
                   "model_latency_ms": d.get("model_latency_ms"),
                   "registered_sha256": d["registered_sha256"], "sent_sha256": d.get("sent_sha256"),
                   "text_matches_registered": d.get("sent_sha256") == d["registered_sha256"],
                   "l1_outcome": l1_outcome(d["ground_truth"], d.get("decision"), d.get("status"))}
            results.append(rec)
            if d["repetition"] == 1:
                direct_by_case_rep[d["case_id"]] = d.get("decision")

    os.makedirs(RUN_DIR, exist_ok=True)
    with open(os.path.join(RUN_DIR, "results.jsonl"), "w", encoding="utf-8") as f:
        for r in results:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    nd_gw = determinism_report(results, "gateway")
    nd_dr = determinism_report(results, "direct")
    # direct-vs-gateway consistency (rep 1)
    gw_rep1 = {r["case_id"]: r["decision"] for r in results
               if r["channel"] == "gateway" and r["repetition"] == 1}
    consistency = [{"case_id": cid, "gateway": gw_rep1.get(cid), "direct": dd,
                    "agree": gw_rep1.get(cid) == dd}
                   for cid, dd in direct_by_case_rep.items()]
    meta = {"run_id": RUN_ID, "generated_utc": _now(), "freeze_commit": FREEZE_COMMIT,
            "gateway_rows": sum(1 for r in results if r["channel"] == "gateway"),
            "direct_rows": sum(1 for r in results if r["channel"] == "direct"),
            "dataplane_log_aligned": dp_aligned,
            "decision_source": "data-plane-log" if dp_aligned else "http-status (data-plane log "
                               "not aligned/provided; L2 falls back to status-derived decision)",
            "nondeterministic_gateway": nd_gw, "nondeterministic_direct": nd_dr,
            "direct_vs_gateway_consistency": {"checked": len(consistency),
                                              "agree": sum(1 for c in consistency if c["agree"]),
                                              "disagree": [c for c in consistency if not c["agree"]]},
            "note": "No metrics computed here. L1/L2/L3 preserved separately per record."}
    with open(os.path.join(RUN_DIR, "assembly_meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)
    print(f"assembled {len(results)} result rows -> results.jsonl "
          f"(gateway {meta['gateway_rows']}, direct {meta['direct_rows']})")
    print(f"  decision source: {meta['decision_source']}")
    print(f"  nondeterministic: gateway {len(nd_gw)}, direct {len(nd_dr)}")
    print(f"  direct-vs-gateway consistency: {meta['direct_vs_gateway_consistency']['agree']}"
          f"/{meta['direct_vs_gateway_consistency']['checked']} agree")
    return 0


# ══════════════════════════════════════════════════════════════════════════
# score (offline): L1 (D19 scorer) + L2 + L3 + consistency + nondeterminism
# ══════════════════════════════════════════════════════════════════════════
def _nd(num, den):
    return {"num": num, "den": den, "pct": (100.0 * num / den) if den else None}


def cmd_score(args):
    results = load_jsonl(os.path.join(RUN_DIR, "results.jsonl"))
    l1 = score_l1(results)   # imports frozen D19 score_binary (torch / ML env)
    gw = [r for r in results if r["channel"] == "gateway"]
    rep1 = [r for r in gw if r["repetition"] == 1]

    # L2 conformance (all gateway executions)
    conf = sum(1 for r in gw if r["l2_conformant"])
    # L3 (rep 1)
    from collections import Counter
    l3 = Counter(r["l3_outcome"] for r in rep1)
    # nondeterminism + consistency from assembly_meta if present
    am = {}
    amp = os.path.join(RUN_DIR, "assembly_meta.json")
    if os.path.exists(amp):
        am = json.load(open(amp))

    # RQ2 per BLOCK cell external recall vs published internal
    rq2 = {}
    for cell in spec_lib.ATTACK_CATEGORIES:
        pc = l1["per_cell"].get(cell)
        if pc:
            tp, fn = pc["confusion_matrix"]["TP"], pc["confusion_matrix"]["FN"]
            rq2[cell] = {"external_recall": _nd(tp, tp + fn),
                         "internal_recall_pct": V4_INTERNAL_RECALL_PCT[cell],
                         "internal_recall": V4_INTERNAL_RECALL[cell]}

    o = l1["overall"]
    cm = o["confusion_matrix"]
    summary = {
        "run_id": RUN_ID, "freeze_commit": FREEZE_COMMIT, "generated_utc": _now(),
        "headline_note": "L1 from gateway channel, repetition 1, nondeterministic cases excluded.",
        "prevalence": "50/50 by construction (200 ALLOW / 200 BLOCK); not operational prevalence.",
        "L1": {
            "n": l1["headline_n"],
            "TP": cm["TP"], "TN": cm["TN"], "FP": cm["FP"], "FN": cm["FN"],
            "invalid_outputs": o["invalid_outputs"], "invalid_output_rate": o["invalid_output_rate"],
            "accuracy": _nd(o["correct"], o["support"]),
            "precision_block": _nd(cm["TP"], cm["TP"] + cm["FP"]),
            "recall_block_ADR": _nd(cm["TP"], cm["TP"] + cm["FN"]),
            "f1_block": o["f1_block"],
            "FPR": _nd(cm["FP"], cm["FP"] + cm["TN"]),
            "FNR": _nd(cm["FN"], cm["FN"] + cm["TP"]),
            "per_cell": {c: (l1["per_cell"][c] and {
                "confusion": l1["per_cell"][c]["confusion_matrix"],
                "recall_block": _nd(l1["per_cell"][c]["confusion_matrix"]["TP"],
                                    l1["per_cell"][c]["block_support"]) if c in spec_lib.ATTACK_CATEGORIES else None,
                "fpr": _nd(l1["per_cell"][c]["confusion_matrix"]["FP"],
                           l1["per_cell"][c]["allow_support"]) if c in spec_lib.BENIGN_SLICES else None,
            }) for c in CELLS},
            "excluded_nondeterministic": l1["excluded_nondeterministic"],
        },
        "L2": {"conformant": _nd(conf, len(gw)),
               "note": am.get("decision_source", "see assembly_meta.json")},
        "L3": {"benign_delivered": l3.get("benign_delivered", 0),
               "benign_broken": l3.get("benign_broken", 0),
               "attack_stopped": l3.get("attack_stopped", 0),
               "attack_delivered": l3.get("attack_delivered", 0),
               "note": "'attack_delivered' = a BLOCK request reached lab-app; NOT exploitation."},
        "RQ2_generalization": rq2,
        "direct_consistency": am.get("direct_vs_gateway_consistency"),
        "nondeterminism": {"gateway": len(am.get("nondeterministic_gateway", [])),
                           "direct": len(am.get("nondeterministic_direct", []))},
        "latency_note": "model_latency observations only; NOT a formal latency benchmark (issue #18).",
    }
    with open(os.path.join(RUN_DIR, "summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    _write_summary_md(summary)
    print(f"L1 headline (n={summary['L1']['n']}): acc {cm['TP']+cm['TN']}/{o['support']}, "
          f"recall(BLOCK) {cm['TP']}/{cm['TP']+cm['FN']}, FPR {cm['FP']}/{cm['FP']+cm['TN']}, "
          f"invalid {o['invalid_outputs']}")
    print("  wrote summary.json + summary.md")
    return 0


def _write_summary_md(s):
    L1 = s["L1"]
    lines = [f"# External Test v1 — {s['run_id']} summary", "",
             f"Freeze commit `{s['freeze_commit']}`. {s['prevalence']}",
             f"Headline: {s['headline_note']}", "",
             "## L1 — model", "",
             f"- n = {L1['n']}; TP {L1['TP']} · TN {L1['TN']} · FP {L1['FP']} · FN {L1['FN']} · "
             f"invalid {L1['invalid_outputs']}",
             f"- Accuracy {L1['accuracy']['num']}/{L1['accuracy']['den']}",
             f"- Precision(BLOCK) {L1['precision_block']['num']}/{L1['precision_block']['den']}",
             f"- Recall/ADR(BLOCK) {L1['recall_block_ADR']['num']}/{L1['recall_block_ADR']['den']}",
             f"- FPR {L1['FPR']['num']}/{L1['FPR']['den']} · FNR {L1['FNR']['num']}/{L1['FNR']['den']}",
             "", "## L2 — enforcement", "",
             f"- Conformant {s['L2']['conformant']['num']}/{s['L2']['conformant']['den']}",
             "", "## L3 — end-to-end", "",
             f"- benign delivered {s['L3']['benign_delivered']} · benign broken {s['L3']['benign_broken']}",
             f"- attacks stopped {s['L3']['attack_stopped']} · attacks delivered {s['L3']['attack_delivered']}",
             f"- {s['L3']['note']}", "", "## Notes", "", f"- {s['latency_note']}"]
    with open(os.path.join(RUN_DIR, "summary.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("verify", help="[offline] hard-verify frozen integrity + write run metadata")
    sub.add_parser("subset", help="[offline] write the predeclared 100-case consistency subset")

    g = sub.add_parser("gateway", help="[LIVE] replay 400 frozen cases x reps through data-plane")
    g.add_argument("--gateway-host", default="127.0.0.1")
    g.add_argument("--gateway-port", type=int, default=8080)
    g.add_argument("--repetitions", type=int, default=3)
    g.add_argument("--timeout", type=float, default=30.0)
    g.add_argument("--delay-ms", type=float, default=0.0)
    g.add_argument("--receipt-log",
                   default=os.path.join(REPO_ROOT, "docker", ".lab-logs", "lab-app-access.jsonl"))
    g.add_argument("--force", action="store_true", help="override the D32 no-overwrite guard")

    d = sub.add_parser("direct", help="[LIVE] 100-case consistency subset x reps -> /classify")
    d.add_argument("--classifier-url", default="http://127.0.0.1:8000/classify")
    d.add_argument("--repetitions", type=int, default=3)
    d.add_argument("--timeout", type=float, default=30.0)
    d.add_argument("--subset", default=None)
    d.add_argument("--force", action="store_true")

    a = sub.add_parser("assemble", help="[offline] correlate raw -> results.jsonl (L1/L2/L3)")
    a.add_argument("--gateway-raw", default=os.path.join(RUN_DIR, "raw", "gateway_raw.jsonl"))
    a.add_argument("--direct-raw", default=os.path.join(RUN_DIR, "raw", "direct_raw.jsonl"))
    a.add_argument("--dataplane-log", default=os.path.join(RUN_DIR, "raw", "data-plane.log"))

    sub.add_parser("score", help="[offline] L1 (D19 scorer) + L2 + L3 + consistency")

    args = ap.parse_args(argv)
    return {"verify": cmd_verify, "subset": cmd_subset, "gateway": cmd_gateway,
            "direct": cmd_direct, "assemble": cmd_assemble, "score": cmd_score}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
