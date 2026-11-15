"""Capture, seal and replay independent challenge-app HTTP cases.

Raw cases and work logs stay outside the repository. Public rows contain hashes,
closed codes and numbers only. This harness is for sequential quality/effect
trials; load, queue, failure and resource trials are separate experiments.

Order: draft direct run -> seal the unchanged cases and direct rows -> replay
the sealed cases through each pinned arm with real V5.1. An integration dry run
may use the V5 double but cannot be scored as a quality result.
"""
import argparse
import base64
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path[:0] = [str(ROOT), str(HERE), str(HERE.parent), str(ROOT / "scripts/cascade_lab")]

import adapters  # noqa: E402
from data_plane.cascade import SAFE_V5_REASONS  # noqa: E402
from gpu_lease import temporary_handoff  # noqa: E402
import smoke  # noqa: E402
import stack as S  # noqa: E402
from trial_client import TrialClient, TRANSPORTS  # noqa: E402

SCHEMA = "challenge-trial/v1"
ARMS = ("direct", "v5only", "fastv5", "fastv5_guard", "guarded", "guarded_fast", "crs")
METRICS_SPEC = Path("/home/sebas/Documents/Codex/2026-11-02/firewall-ia-cierre-pc-paper/outputs/"
                    "METRICAS_CASCADA_PAPER_2026-11-04.md")
LABELS = ("ALLOW", "BLOCK", "UNKNOWN")
LABEL_BASES = ("constructed_effect", "agent_task", "human_task", "adjudicated",
               "confirmed_incident", "unknown")
SAFE_ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}\Z")
SOURCE_FILES = (
    "scripts/local_stack/challenges/adapters.py",
    "scripts/local_stack/challenges/challenge_stack.py",
    "scripts/local_stack/challenges/trial.py",
    "scripts/local_stack/challenges/trial_client.py",
    "scripts/local_stack/challenges/score_trial.py",
    "scripts/local_stack/challenges/load_trial.py",
    "scripts/local_stack/challenges/fault_trial.py",
    "scripts/local_stack/challenges/gpu_lease.py",
    "scripts/local_stack/stack.py", "scripts/local_stack/wire_clients.py",
    "data_plane/cascade.py", "data_plane/cascade_runtime.py",
    "data_plane/cascade_gateway.py", "data_plane/gateway_framing.py",
    "data_plane/fast_path.py", "data_plane/fast_path_audit.py", "data_plane/model2_policy.py",
    "data_plane/model2_decider.py",
    "data_plane/request_guard.py",
    "data_plane/cascade_manifest.py", "data_plane/cascade_canonical.py",
    "data_plane/canonical_request.py", "data_plane/http1_wire.py",
    "scripts/gateway_ops/launch.py", "scripts/gateway_ops/live_stack.py",
    "scripts/local_stack/challenges/static_contract.py",
)


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def source_hashes():
    return {name: sha(ROOT / name) for name in SOURCE_FILES}


def read_jsonl(path):
    return [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]


def body_bytes(case):
    return base64.b64decode(case.get("body_b64", ""), validate=True)


def validate_cases(path, app):
    path = Path(path).resolve()
    if path.is_relative_to(ROOT):
        raise ValueError("private raw cases must be outside the firewall repository")
    cases = read_jsonl(path)
    if not cases:
        raise ValueError("empty case set")
    seen = set()
    for case in cases:
        required = ("case_id", "group_id", "session_id", "app", "method", "target", "label",
                    "label_basis", "family")
        if not isinstance(case, dict) or any(not isinstance(case.get(k), str) or not case[k]
                                             for k in required):
            raise ValueError("missing or invalid required case field")
        cid = case["case_id"]
        if cid in seen or case["app"] != app or case["label"] not in LABELS \
                or case["label_basis"] not in LABEL_BASES:
            raise ValueError(f"duplicate id, app or label error: {cid}")
        seen.add(cid)
        if any(not SAFE_ID.fullmatch(case[k]) for k in
               ("case_id", "group_id", "session_id", "app", "family")):
            raise ValueError(f"non-opaque identifier: {cid}")
        if case["label_basis"] == "agent_task":
            if (case["label"] != "ALLOW" or
                    any(not isinstance(case.get(k), str) or not SAFE_ID.fullmatch(case[k])
                        for k in ("generator_id", "task_id"))):
                raise ValueError(f"agent task requires benign label and opaque provenance: {cid}")
        seq = case.get("attack_sequence_id")
        role = case.get("sequence_role")
        if seq is not None or role is not None:
            if (not isinstance(seq, str) or not SAFE_ID.fullmatch(seq)
                    or role not in ("attack", "observe", "setup")
                    or (role == "attack" and case["label"] != "BLOCK")):
                raise ValueError(f"invalid attack sequence metadata: {cid}")
        target = case["target"]
        if not target.startswith("/") or target.startswith("//") or "#" in target \
                or "\r" in target or "\n" in target:
            raise ValueError(f"unsafe target: {cid}")
        if case["method"] not in ("GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"):
            raise ValueError(f"unsupported method: {cid}")
        headers = case.get("headers", [])
        if (not isinstance(headers, list) or any(not isinstance(x, list) or len(x) != 2
                or not all(isinstance(v, str) for v in x) for x in headers)):
            raise ValueError(f"headers must be name/value pairs: {cid}")
        if any(n.lower() in ("host", "content-length", "transfer-encoding") for n, _ in headers):
            raise ValueError(f"framing headers are generated by the client: {cid}")
        if len(body_bytes(case)) > 65536:
            raise ValueError(f"case body exceeds front request cap: {cid}")
        oracle = case.get("effect_oracle")
        expected_reason = case.get("expected_v5_reason")
        if expected_reason is not None and (case["label"] != "BLOCK" or
                                            not isinstance(expected_reason, str) or
                                            expected_reason not in SAFE_V5_REASONS):
            raise ValueError(f"invalid expected V5 reason: {cid}")
        if oracle is not None:
            if (not isinstance(oracle, dict) or oracle.get("type") not in
                    ("body_contains_b64", "body_sha256", "status", "location_prefix")):
                raise ValueError(f"invalid effect oracle: {cid}")
            if oracle["type"] == "body_contains_b64":
                if not base64.b64decode(oracle.get("value_b64", ""), validate=True):
                    raise ValueError(f"empty body oracle: {cid}")
            elif oracle["type"] == "body_sha256" and (not isinstance(oracle.get("value"), str) or not re.fullmatch(r"[0-9a-f]{64}", oracle["value"])):
                raise ValueError(f"invalid body hash oracle: {cid}")
            elif oracle["type"] == "status" and not isinstance(oracle.get("value"), int):
                raise ValueError(f"invalid status oracle: {cid}")
            elif oracle["type"] == "location_prefix" and (not isinstance(oracle.get("value"), str) or not oracle["value"]):
                raise ValueError(f"invalid location oracle: {cid}")
    return cases


def effect(oracle, response):
    if oracle is None or response.get("error") is not None:
        return None
    body = response.get("body") or b""
    kind = oracle["type"]
    if kind == "body_contains_b64":
        return base64.b64decode(oracle["value_b64"], validate=True) in body
    if kind == "body_sha256":
        return hashlib.sha256(body).hexdigest() == oracle["value"]
    if kind == "status":
        return response.get("status") == oracle["value"]
    location = next((v for n, v in response.get("headers", []) if n.lower() == "location"), "")
    return location.startswith(oracle["value"])


def config_arm(arm):
    return ("guarded", True) if arm == "guarded_fast" else (arm, False)


def seal(args):
    cases = validate_cases(args.cases, args.app)
    if args.population == "L2_AGENT_LAB" and any(c["label_basis"] != "agent_task" for c in cases):
        raise ValueError("agent-lab population requires agent-task labels for every case")
    if not 0 <= args.audit_sample_rate <= 1:
        raise ValueError("Fast Path audit sample rate must be in 0..1")
    direct = read_jsonl(args.direct_rows)
    if len(direct) != len(cases) or {r.get("case_id") for r in direct} != {c["case_id"] for c in cases}:
        raise ValueError("direct baseline does not cover exactly the case set")
    if any(r.get("source_cases_sha256") != sha(args.cases) or r.get("arm") != "direct" for r in direct):
        raise ValueError("direct baseline did not use these exact cases")
    summary_path = args.direct_rows.parent / "SUMMARY.json"
    direct_summary = json.loads(summary_path.read_text())
    if (direct_summary.get("status") != "COMPLETE" or
            direct_summary.get("scope") != "DIRECT_DRAFT" or
            direct_summary.get("rows_sha256") != sha(args.direct_rows) or
            direct_summary.get("cases_sha256") != sha(args.cases)):
        raise ValueError("direct baseline summary or rows do not match")
    transport = direct_summary["transport"]
    if any(r.get("transport") != transport for r in direct):
        raise ValueError("direct baseline used mixed transports")
    if args.out.exists():
        raise FileExistsError("new seal directory required")
    commit = subprocess.run(["git", "-C", adapters.DEFAULT_APPS_ROOT, "rev-parse", "HEAD"],
                            capture_output=True, text=True, check=True).stdout.strip()
    if commit != adapters.PINNED_APPS_COMMIT:
        raise ValueError("applications repository differs from the pinned commit")
    args.out.mkdir(parents=True)
    configs = {}
    for arm in ARMS:
        mapped, fast = config_arm(arm)
        path = args.out / f"{args.app}.{arm}.stack.json"
        command = [str(ROOT / ".venv-dataplane/bin/python"), "-B", str(HERE / "challenge_stack.py"),
                   "config", "--app", args.app, "--arm", mapped, "--out", str(path)]
        if fast or arm in ("fastv5", "fastv5_guard"):
            command.extend(("--fast-path", "--audit-sample-rate", str(args.audit_sample_rate)))
        proc = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
        if proc.returncode:
            raise RuntimeError(f"config {arm} failed: {proc.stderr[-400:]}")
        cfg = S.load_config(str(path))
        if cfg["gateway"]["body_size_limit"] != "16m" or cfg["front"]["max_body"] != "64k":
            raise RuntimeError("body limits differ from pre-registered challenge profile")
        configs[arm] = {"path": str(path), "sha256": sha(path),
                        "fast_path_policy_sha256": (cfg["fast_path"] or {}).get("policy_sha256")}
    if configs["direct"]["sha256"] != direct_summary["config_sha256"]:
        raise ValueError("direct stack configuration changed before seal")
    manifest = {"schema": SCHEMA, "status": "SEALED", "population": args.population,
                "app": args.app, "apps_commit": commit, "cases_sha256": sha(args.cases),
                "direct_rows_sha256": sha(args.direct_rows), "cases_count": len(cases),
                "transport": transport,
                "groups_count": len({c["group_id"] for c in cases}),
                "sessions_count": len({c["session_id"] for c in cases}),
                "generators": sorted({c["generator_id"] for c in cases
                                      if c["label_basis"] == "agent_task"}),
                "labels": dict(Counter(c["label"] for c in cases)),
                "gateway_body_size_limit": "16m", "front_request_body_limit": "64k",
                "fast_path_audit_sample_rate": args.audit_sample_rate,
                "metrics_spec_sha256": sha(METRICS_SPEC), "source_sha256": source_hashes(),
                "configs": configs,
                "created_utc": time.time(), "no_model_selection_after_seal": True}
    (args.out / "SEAL.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return {"seal": str(args.out / "SEAL.json"), "cases": len(cases), "app": args.app}


def attribute(state, before, target, arm):
    deadline = time.monotonic() + 2.0
    while True:
        attr = smoke.attribution(state, target, before)
        crs = state.get("crs")
        if crs:
            audit_rows, _ = smoke.new_json_lines(crs["audit_log"], before["crs_off"])
            attr["crs_interrupted"] = any(r.get("transaction", {}).get("is_interrupted") is True
                                          for r in audit_rows)
            attr["crs_rule_ids"] = sorted({str(m.get("details", {}).get("ruleId"))
                                           for r in audit_rows
                                           for m in r.get("transaction", {}).get("messages", [])
                                           if m.get("details", {}).get("ruleId") is not None})
            scores = [int(match.group(1)) for r in audit_rows
                      for m in r.get("transaction", {}).get("messages", [])
                      if (match := re.search(r"Total Score:\s*(\d+)", m.get("message", "")))]
            attr["crs_anomaly_score"] = max(scores) if scores else None
        front_rows, _ = smoke.new_json_lines(state["front_access_log"], before["front_off"])
        decision = attr.get("gateway_last_decision")
        ready = bool(front_rows) and (arm not in ("v5only", "fastv5", "fastv5_guard", "guarded", "guarded_fast") or decision is not None)
        if ready or time.monotonic() >= deadline:
            return attr, front_rows[-1] if front_rows else None
        time.sleep(0.05)


def run(args):
    cases = validate_cases(args.cases, args.app)
    if args.arm != "direct" and args.seal is None:
        raise ValueError("only a direct baseline may run before sealing")
    if args.arm != "direct" and args.v5 != "real" and not args.integration_double:
        raise ValueError("quality arms require real V5.1; double needs --integration-double")
    if args.seal:
        manifest = json.loads(args.seal.read_text())
        if manifest.get("schema") != SCHEMA or manifest.get("status") != "SEALED" \
                or manifest.get("app") != args.app or manifest.get("cases_sha256") != sha(args.cases) \
                or manifest.get("metrics_spec_sha256") != sha(METRICS_SPEC) \
                or manifest.get("source_sha256") != source_hashes() \
                or (args.transport != "h1_plain_gateway" and manifest.get("transport") != args.transport):
            raise ValueError("sealed identity mismatch")
        pinned = manifest["configs"][args.arm]
        config = Path(pinned["path"])
        if sha(config) != pinned["sha256"]:
            raise ValueError("stack config changed after sealing")
    else:
        if args.arm != "direct":
            raise ValueError("draft baseline must be direct")
        config = args.out / f"{args.app}.direct.stack.json"
    if args.out.exists() or args.work.exists():
        raise FileExistsError("new output and private work directories required")
    args.out.mkdir(parents=True)
    args.work.mkdir(parents=True)
    mapped, fast = config_arm(args.arm)
    if args.seal is None:
        proc = subprocess.run([str(ROOT / ".venv-dataplane/bin/python"), "-B", str(HERE / "challenge_stack.py"),
                               "config", "--app", args.app, "--arm", mapped, "--out", str(config)],
                              cwd=ROOT, capture_output=True, text=True)
        if proc.returncode:
            raise RuntimeError(f"direct config failed: {proc.stderr[-400:]}")
    up_cmd = [str(ROOT / ".venv-dataplane/bin/python"), "-B", str(HERE / "challenge_stack.py"),
              "up", "--app", args.app, "--arm", mapped, "--config", str(config),
              "--work", str(args.work), "--v5", args.v5]
    # Startup diagnostics can include runtime paths and are private evidence.
    out_log = args.work / "stack.stdout.txt"
    client = None
    rows = []
    run_id = secrets.token_hex(12)
    try:
        with out_log.open("x") as handle:
            up = subprocess.run(up_cmd, cwd=ROOT, stdout=handle, stderr=subprocess.STDOUT, timeout=600)
        if up.returncode:
            raise RuntimeError("stack startup failed; see stack.stdout.txt")
        state = json.loads((args.work / "stack-state.json").read_text())
        if state.get("apps_commit") != adapters.PINNED_APPS_COMMIT:
            raise RuntimeError("application commit drift")
        if state.get("v5") != args.v5:
            raise RuntimeError("requested V5 runtime differs from running stack")
        client = TrialClient(state, args.transport)
        for case in cases:
            before = smoke.snapshot(state)
            body = body_bytes(case)
            response = client.request(case["method"], case["target"], case.get("headers", []), body)
            attr, front = attribute(state, before, case["target"], args.arm)
            decision = attr.get("gateway_last_decision") or {}
            stage = decision.get("deciding_stage")
            if decision:
                applied = decision.get("applied")
                layer = "firewall" if applied == "DENY" else "application"
            elif attr.get("crs_interrupted") and response.get("status") == 403:
                applied, layer = "DENY", "crs"
            elif front and not front.get("upstream_status"):
                applied, layer = None, "front"
            elif attr["app_received"]:
                applied, layer = "FORWARD", "application"
            else:
                applied, layer = None, "unattributed"
            result_body = response.get("body") or b""
            rows.append({"schema": "challenge-trial-row/v1", "event_id": secrets.token_hex(12),
                         "run_id": run_id,
                         "case_id": case["case_id"], "group_id": case["group_id"],
                         "session_id": case["session_id"], "app": args.app, "arm": args.arm,
                         "transport": args.transport, "label": case["label"],
                         "label_basis": case["label_basis"], "family": case["family"],
                         "attack_sequence_id": case.get("attack_sequence_id"),
                         "sequence_role": case.get("sequence_role"),
                         "generator_id": case.get("generator_id"),
                         "task_id": case.get("task_id"),
                         "expected_v5_reason": case.get("expected_v5_reason"),
                         "source_cases_sha256": sha(args.cases),
                         "population": manifest["population"] if args.seal else "L2_DRAFT",
                         "split": "TEST_SEALED" if args.seal else "DRAFT",
                         "method": case["method"], "target_sha256": hashlib.sha256(case["target"].encode()).hexdigest(),
                         "body_bytes": len(body), "body_sha256": hashlib.sha256(body).hexdigest(),
                         "status": response.get("status"), "complete": response.get("error") is None,
                         "response_bytes": len(result_body),
                         "response_sha256": hashlib.sha256(result_body).hexdigest(),
                         "effect_observed": effect(case.get("effect_oracle"), response),
                         "effect_oracle_type": (case.get("effect_oracle") or {}).get("type"),
                         "effect_eligible": (case["label"] == "BLOCK" and
                             (case.get("effect_oracle") or {}).get("type") in ("body_contains_b64", "body_sha256", "location_prefix")),
                         "app_received": attr["app_received"], "layer": layer, "applied": applied,
                         "crs_rule_ids": attr.get("crs_rule_ids"),
                         "crs_anomaly_score": attr.get("crs_anomaly_score"),
                         "deciding_stage": stage, "canonical_outcome": decision.get("canonical_outcome"),
                         "canonical_size": decision.get("canonical_size"),
                         "canonical_text_bytes": decision.get("canonical_text_bytes"),
                         "canonical_text_sha256": decision.get("canonical_text_sha256"),
                         "correlation_id": decision.get("correlation_id"),
                         "manifest_sha256": decision.get("manifest_sha256"),
                         "gateway_ms": decision.get("gateway_ms"),
                         "request_guard": decision.get("request_guard"),
                         "fast_path": decision.get("fast_path"), "model2": decision.get("model2"),
                         "v5": decision.get("v5"), "gateway_reason": decision.get("reason"),
                         "gateway_stage_ms": decision.get("stage_ms"),
                         "v5_service": decision.get("v5_service"),
                         "client_ms": response.get("elapsed_ms"), "alpn": response.get("alpn"),
                         "tcp_connect_ms": response.get("tcp_connect_ms"),
                         "tls_handshake_ms": response.get("tls_handshake_ms"),
                         "tls_version": response.get("tls_version"),
                         "tls_session_reused": response.get("tls_session_reused"),
                         "connection_requests": response.get("connection_requests"),
                         "front_request_ms": float(front["request_time"]) * 1000
                         if front and front.get("request_time") is not None else None,
                         "front_status": (front or {}).get("status"),
                         "front_upstream_status": (front or {}).get("upstream_status")})
        rows_path = args.out / "ROWS.jsonl"
        with rows_path.open("x") as handle:
            for row in rows:
                handle.write(json.dumps(row, sort_keys=True) + "\n")
        admin_snapshot = None
        if state.get("firewall") == "cascade":
            status, body = S.http_get(state["endpoints"]["gateway_admin"] + "/status", timeout=2)
            if status == 200:
                admin_snapshot = json.loads(body)
        summary = {"schema": SCHEMA, "scope": "INTEGRATION_DOUBLE" if args.integration_double else
                   ("DIRECT_DRAFT" if args.seal is None else "SEALED_REAL"),
                   "run_id": run_id, "gateway_final_status": admin_snapshot,
                   "app": args.app, "arm": args.arm, "transport": args.transport, "cases": len(rows),
                   "cases_sha256": sha(args.cases), "config_sha256": sha(config),
                   "seal_sha256": sha(args.seal) if args.seal else None,
                   "rows_sha256": sha(rows_path), "apps_commit": state["apps_commit"],
                   "crs_effective": state["crs"]["effective"] if state.get("crs") else None,
                   "crs_image_id": state["crs"]["image_id"] if state.get("crs") else None,
                   "v5": args.v5 if args.arm in ("v5only", "fastv5", "fastv5_guard", "guarded", "guarded_fast") else "N/A",
                   "status": "COMPLETE_PENDING_CLEAN"}
        (args.out / "SUMMARY.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    finally:
        if client:
            client.close()
        if (args.work / "stack-state.json").exists():
            subprocess.run([str(ROOT / ".venv-dataplane/bin/python"), "-B", str(HERE / "challenge_stack.py"),
                            "down", "--work", str(args.work)], cwd=ROOT, capture_output=True, text=True)
            clean = subprocess.run([str(ROOT / ".venv-dataplane/bin/python"), "-B", str(HERE / "challenge_stack.py"),
                                    "check-clean", "--work", str(args.work)], cwd=ROOT,
                                   capture_output=True, text=True)
            clean_doc = json.loads(clean.stdout) if clean.returncode == 0 else {"clean": False}
            (args.out / "CLEAN.json").write_text(json.dumps(clean_doc, indent=2) + "\n")
            if not clean_doc.get("clean"):
                raise RuntimeError("stack did not clean up")
    summary["gateway_shutdown_accounting"] = shutdown_accounting(state)
    summary["status"] = "COMPLETE"
    (args.out / "SUMMARY.json").write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary



def shutdown_accounting(state):
    """Read closed accounting only after stack.down has drained the auditor."""
    path = state.get('gateway_decisions')
    if not path or not Path(path).exists():
        return None
    records = read_jsonl(path)
    return next((r for r in reversed(records) if r.get('kind') == 'shutdown_accounting'), None)

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("seal")
    p.add_argument("--app", choices=adapters.APP_NAMES, required=True)
    p.add_argument("--cases", type=Path, required=True)
    p.add_argument("--direct-rows", type=Path, required=True)
    p.add_argument("--population", choices=("L2_SCRIPTED_LAB", "L2_AGENT_LAB",
                                             "L2_HUMAN_LAB"), required=True)
    p.add_argument("--audit-sample-rate", type=float, default=0.0,
                   help="predeclared optional V5 audit rate for the separate Fast Path variant")
    p.add_argument("--out", type=Path, required=True)
    p = sub.add_parser("run")
    p.add_argument("--app", choices=adapters.APP_NAMES, required=True)
    p.add_argument("--arm", choices=ARMS, required=True)
    p.add_argument("--cases", type=Path, required=True)
    p.add_argument("--seal", type=Path)
    p.add_argument("--transport", choices=TRANSPORTS, required=True)
    p.add_argument("--v5", choices=("real", "double"), default="real")
    p.add_argument("--integration-double", action="store_true")
    p.add_argument("--handoff-gpu", action="store_true",
                   help="temporary owner-authorized real V5.1 GPU hand-off, released after cleanup")
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--work", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.cmd == "seal":
            result = seal(args)
        else:
            needs_gpu = args.arm in ("v5only", "fastv5", "fastv5_guard", "guarded", "guarded_fast") and args.v5 == "real"
            if args.handoff_gpu and not needs_gpu:
                raise ValueError("GPU hand-off applies only to a real V5.1 arm")
            lease_dir = args.work.parent / (args.work.name + ".gpu-lease")
            with temporary_handoff(args.handoff_gpu, lease_dir):
                result = run(args)
    except (ValueError, FileExistsError, RuntimeError, OSError) as exc:
        parser.exit(2, f"challenge-trial: {exc}\n")
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
