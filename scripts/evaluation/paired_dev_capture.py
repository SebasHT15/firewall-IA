"""
firewall-IA — gateway capture + V4 decision recorder for the paired development diagnostic
(issue #59). Runs INSIDE the lab `generator` container, on the firewall-lab network.

For every case in cases.jsonl it performs, in order, three faithful passes and records one raw
record. No marker or correlation id is ever added to a request under test (methodology section 8);
cases are sent strictly sequentially, one request each (raw socket, no redirect following), so a
pass's single capture line is identified by sequence.

  1. FIDELITY (capture-proxy, no model): wire.to_wire(designed_text) is sent to the CAPTURE
     proxy, which imports the production render_request (object identity asserted by
     tests/test_external_capture) and appends one capture line. The rendered text must equal the
     designed text byte-for-byte (capture_ok). This establishes the D1 text the SAME renderer
     produces from the wire bytes. It is NOT a byte-capture of the live data-plane -> control-
     plane channel; that the data plane behaves the same is shown empirically by pass 2 vs pass 3
     agreement (gateway_consistent).
  2. GATEWAY ENFORCEMENT (data-plane, V4 in the path): the SAME wire bytes are sent to the
     firewall data plane. Its HTTP status is the enforced decision: 403 -> BLOCK (model),
     503 -> fail-closed BLOCK, anything else -> ALLOW (forwarded to the lab app). D34.
  3. DECISION + REASON (control-plane /classify, on the captured text): POST {"request": text}
     to the control plane, exactly as the gateway's ask_classifier does. Records decision,
     reason, status (ok/invalid), model_latency_ms. Because the text is byte-identical to what
     the gateway renders, this is V4's actual decision + reason for the gateway path.

A consistency flag records whether the gateway enforcement (pass 2) agrees with the /classify
decision (pass 3). Never re-runs a case to obtain a preferred outcome; failures are recorded.

    python3 /opt/eval/paired_dev_capture.py \
        --cases /opt/out/cases.jsonl --out /opt/out/raw \
        --capture-file /logs/capture/paired-dev.jsonl
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import socket
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
for cand in ("/opt/external", os.path.join(os.path.dirname(os.path.dirname(HERE)), "scripts", "external")):
    if os.path.isdir(cand) and cand not in sys.path:
        sys.path.insert(0, cand)

import wire  # noqa: E402  (stdlib only; the one D1<->wire converter)


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def sha_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def count_lines(path):
    if not os.path.exists(path):
        return 0
    with open(path, encoding="utf-8", errors="replace") as f:
        return sum(1 for _ in f)


def read_line(path, index):
    """1-based line `index` of a JSONL file, parsed, or None."""
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8", errors="replace") as f:
        for i, line in enumerate(f, 1):
            if i == index:
                line = line.strip()
                return json.loads(line) if line else None
    return None


def send_wire(host, port, text, timeout):
    """One raw-socket request through an explicit proxy; returns a result dict."""
    wire.assert_canonical(text)
    payload = wire.to_wire(text, strict=True)
    started = time.perf_counter()
    sock = socket.create_connection((host, port), timeout=timeout)
    try:
        sock.settimeout(timeout)
        sock.sendall(payload)
        status, headers, body = wire.read_response(sock)
    finally:
        sock.close()
    return {"http_status": status, "response_bytes": len(body),
            "response_body_prefix": body[:160].decode("utf-8", errors="replace"),
            "wire_bytes": len(payload), "elapsed_ms": round((time.perf_counter() - started) * 1000, 2)}


def classify(control_url, text, timeout):
    import httpx
    with httpx.Client(trust_env=False, timeout=timeout) as c:
        r = c.post(control_url, json={"request": text})
    r.raise_for_status()
    b = r.json()
    return {"decision": b.get("decision"), "reason": b.get("reason"), "status": b.get("status"),
            "model_latency_ms": b.get("model_latency_ms")}


def enforced_decision(http_status):
    if http_status == 403:
        return "BLOCK"
    if http_status == 503:
        return "BLOCK_FAILCLOSED"
    return "ALLOW"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.strip().split("\n")[0])
    ap.add_argument("--cases", required=True)
    ap.add_argument("--out", required=True, help="raw output directory")
    ap.add_argument("--capture-file", default="/logs/capture/paired-dev.jsonl")
    ap.add_argument("--control-url", default="http://control-plane:8000/classify")
    ap.add_argument("--capture-proxy", default="capture-proxy:8081")
    ap.add_argument("--gateway-proxy", default="data-plane:8080")
    ap.add_argument("--timeout", type=float, default=30.0)
    ap.add_argument("--delay-ms", type=float, default=50.0)
    args = ap.parse_args(argv)

    cap_host, cap_port = args.capture_proxy.split(":")
    gw_host, gw_port = args.gateway_proxy.split(":")
    cap_port, gw_port = int(cap_port), int(gw_port)

    cases = [json.loads(l) for l in open(args.cases, encoding="utf-8") if l.strip()]
    os.makedirs(args.out, exist_ok=True)
    records_path = os.path.join(args.out, "records_raw.jsonl")
    meta_path = os.path.join(args.out, "capture_run_meta.json")
    for p in (records_path, meta_path):
        if os.path.exists(p):
            raise SystemExit(f"REFUSING to overwrite {p}")

    start_lines = count_lines(args.capture_file)
    if start_lines:
        print(f"NOTE: capture file already has {start_lines} line(s); new lines are appended",
              flush=True)

    n_capture_ok = n_gateway_err = n_classify_err = n_inconsistent = 0
    with open(records_path, "w", encoding="utf-8") as out:
        for i, case in enumerate(cases, 1):
            designed = case["request_text"]
            rec = {"case_id": case["case_id"], "seq": i, "sent_utc": now(),
                   "designed_sha256": case["request_sha256"], "label": case["label"],
                   "family": case["family"], "role": case["role"]}
            # pass 1: capture-proxy fidelity
            before = count_lines(args.capture_file)
            try:
                rec["capture_response"] = send_wire(cap_host, cap_port, designed, args.timeout)
                after = count_lines(args.capture_file)
                rec["capture_lines_added"] = after - before
                cap_rec = read_line(args.capture_file, after) if after == before + 1 else None
                captured = cap_rec.get("request_text") if cap_rec else None
                rec["captured_sha256"] = cap_rec.get("request_sha256") if cap_rec else None
                rec["capture_ok"] = bool(captured is not None and captured == designed
                                         and rec["captured_sha256"] == case["request_sha256"]
                                         and rec["capture_lines_added"] == 1)
            except Exception as exc:
                rec["capture_error"] = f"{type(exc).__name__}: {exc}"
                rec["capture_ok"] = False
                captured = None
            n_capture_ok += bool(rec.get("capture_ok"))
            scored_text = captured if captured is not None else designed
            rec["scored_text_is_captured"] = captured is not None
            rec["scored_sha256"] = sha_text(scored_text)
            # pass 2: gateway enforcement (data-plane, V4 in path)
            try:
                gw = send_wire(gw_host, gw_port, designed, args.timeout)
                rec["gateway_response"] = gw
                rec["gateway_enforced"] = enforced_decision(gw["http_status"])
            except Exception as exc:
                rec["gateway_error"] = f"{type(exc).__name__}: {exc}"
                rec["gateway_enforced"] = None
                n_gateway_err += 1
            # pass 3: decision + reason on the captured text
            try:
                c = classify(args.control_url, scored_text, args.timeout)
                rec["v4"] = c
                rec["v4_decision"] = c["decision"] if c["status"] == "ok" else "INVALID"
                rec["v4_reason"] = c["reason"]
                rec["v4_status"] = c["status"]
            except Exception as exc:
                rec["classify_error"] = f"{type(exc).__name__}: {exc}"
                rec["v4_decision"] = None
                n_classify_err += 1
            # consistency: gateway enforcement vs /classify decision
            enf, dec = rec.get("gateway_enforced"), rec.get("v4_decision")
            if enf is not None and dec is not None:
                agree = ((enf == "BLOCK" and dec == "BLOCK")
                         or (enf == "ALLOW" and dec == "ALLOW")
                         or (enf == "BLOCK_FAILCLOSED" and dec in ("INVALID", "BLOCK")))
                rec["gateway_consistent"] = agree
                n_inconsistent += not agree
            else:
                rec["gateway_consistent"] = None
            out.write(json.dumps(rec, ensure_ascii=False) + "\n")
            out.flush()
            if args.delay_ms:
                time.sleep(args.delay_ms / 1000.0)
            if i % 50 == 0:
                print(f"  {i}/{len(cases)} (capture_ok {n_capture_ok}, "
                      f"gw_err {n_gateway_err}, clf_err {n_classify_err})", flush=True)

    meta = {"run": "v4-analyzer-paired-dev-v1 capture", "finished_utc": now(),
            "n_cases": len(cases), "capture_ok": n_capture_ok,
            "gateway_errors": n_gateway_err, "classify_errors": n_classify_err,
            "gateway_inconsistent": n_inconsistent,
            "capture_file": args.capture_file, "capture_file_start_lines": start_lines,
            "control_url": args.control_url, "capture_proxy": args.capture_proxy,
            "gateway_proxy": args.gateway_proxy,
            "records_sha256": sha256_file(records_path)}
    with open(meta_path, "w", encoding="utf-8") as f:
        f.write(json.dumps(meta, indent=2, ensure_ascii=False) + "\n")
    print(f"capture done: {len(cases)} cases; capture_ok {n_capture_ok}/{len(cases)}; "
          f"gateway_errors {n_gateway_err}; classify_errors {n_classify_err}; "
          f"inconsistent {n_inconsistent}", flush=True)
    return 1 if (n_gateway_err or n_classify_err or n_capture_ok != len(cases)) else 0


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


if __name__ == "__main__":
    sys.exit(main())
