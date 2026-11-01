"""
Cascade lab driver — one PAIRED pass over a development sample that records, per
request, the canonical outcome, BOTH Model 2 candidates' score+decision, the real
V5 decision (over HTTP), the Fast Path decision, and per-stage timings. From this
one JSONL every sub-experiment is derived (V5-only, Model 2 baseline34-only, Model
2 path-ablation32-only, cascade with each candidate), so the systems are compared
on the SAME eligible requests with each model's own representation.

V5 runs in the control-plane service (/usr/bin/python3.12, GPU); this driver runs
in `.venv-analyzer` (numpy/sklearn for the Model 2 FINAL load) and calls V5 over
HTTP. No protected set is read. No payloads are written to logs — only ids,
decisions, scores, categories and timings.

Run (service on :8001 already up):
    .venv-analyzer/bin/python scripts/cascade_lab/run_cascade.py \
        --sample reports/v5/hybrid/cascade-lab/dev_sample_v1.jsonl \
        --out    reports/v5/hybrid/cascade-lab/results/dev_paired_v1.jsonl \
        --v5-url http://127.0.0.1:8001
"""
import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(REPO, "data_plane"))
sys.path.insert(0, REPO)

import canonical_request as CR   # noqa: E402
import cascade_runtime as RT     # noqa: E402
import fast_path as fp           # noqa: E402
import http1_wire as W           # noqa: E402
import model2_decider as MD      # noqa: E402

FINAL = os.path.join(REPO, "model-output-model2/final/v4-d82-20261027T052308Z")
POL = os.path.join(REPO, "reports/v5/hybrid/cascade-lab/policies")
SHA = {
    "baseline34": "da6f6eb85c5a687bd038c6298baf59abdbe0489a80c8993b74a34dae7c60aa38",
    "path-ablation32": "6fda4fa0d0bacd7573234e3b2ebdda23706af1a6312c3fe33e185c0237664d15",
}


def load_deciders():
    b = MD.Model2Decider.from_policy_file(
        os.path.join(FINAL, "baseline34.json"), expected_sha256=SHA["baseline34"],
        policy_path=os.path.join(POL, "model2_lab_baseline34.json"))
    a = MD.Model2Decider.from_policy_file(
        os.path.join(FINAL, "path-ablation32.json"), expected_sha256=SHA["path-ablation32"],
        policy_path=os.path.join(POL, "model2_lab_path-ablation32.json"))
    return b, a


def model2_record(decider, outcome, text):
    t0 = time.perf_counter()
    o = decider.decide(canonical_outcome=outcome, canonical_text=text)
    ms = (time.perf_counter() - t0) * 1000
    return {"decision": o.decision, "status": o.status, "p_block": o.p_block,
            "threshold": o.threshold, "ms": ms}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sample", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--v5-url", default="http://127.0.0.1:8001")
    ap.add_argument("--v5-timeout", type=float, default=30.0)
    ap.add_argument("--limit", type=int, default=0)
    args = ap.parse_args()

    base_dec, abl_dec = load_deciders()
    v5 = RT.V5HttpClient(args.v5_url, timeout_s=args.v5_timeout)
    limits = RT.v5_limits(415)

    rows = [json.loads(l) for l in open(args.sample, encoding="utf-8") if l.strip()]
    if args.limit:
        rows = rows[:args.limit]

    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    n = 0
    t_run = time.perf_counter()
    with open(args.out, "w", encoding="utf-8") as out:
        for r in rows:
            rec = {"id": r["id"], "label": r["label"], "category": r["category"]}
            wire = r["wire"].encode("utf-8")
            # 1. wire parse + framing
            try:
                w = W.parse_request(wire)
            except W.WireError as e:
                rec.update({"wire_ok": False, "wire_reason": e.reason,
                            "canonical_outcome": None})
                out.write(json.dumps(rec) + "\n"); n += 1
                continue
            rec["wire_ok"] = True
            rec["framing"] = w.framing.status
            # 2. canonicalize once
            t0 = time.perf_counter()
            snap = RT.build_snapshot(w.parts, w.framing, limits, correlation_id=r["id"])
            rec["canon_ms"] = (time.perf_counter() - t0) * 1000
            canon = snap.canonical
            rec["canonical_outcome"] = canon.outcome
            rec["canonical_reject"] = canon.reject
            rec["canonical_signals"] = list(canon.signals)
            rec["canonical_size"] = canon.size
            if canon.outcome != "ACCEPT":
                out.write(json.dumps(rec) + "\n"); n += 1
                continue
            text = canon.text
            # 3. Fast Path (no policy in this pass -> CONTINUE), records route fraction
            t0 = time.perf_counter()
            fpd = fp.safe_evaluate(RT.make_fast_path_input(snap), None)
            rec["fast_path"] = {"decision": fpd.decision, "reasons": list(fpd.reasons),
                                "ms": (time.perf_counter() - t0) * 1000}
            # 4. both Model 2 candidates
            rec["model2_baseline34"] = model2_record(base_dec, canon.outcome, text)
            rec["model2_ablation32"] = model2_record(abl_dec, canon.outcome, text)
            # 5. real V5 over HTTP (for every ACCEPT, so V5-only and cascade both derivable)
            t0 = time.perf_counter()
            reply = v5(text)
            rt_ms = (time.perf_counter() - t0) * 1000
            rec["v5"] = {"status": reply.status, "decision": reply.decision,
                         "invalid_reason": reply.invalid_reason,
                         "generate_ms": reply.generate_ms, "roundtrip_ms": rt_ms}
            out.write(json.dumps(rec) + "\n"); n += 1
            if n % 50 == 0:
                print("... %d/%d (%.1fs)" % (n, len(rows), time.perf_counter() - t_run), flush=True)

    print("wrote %d records to %s in %.1fs" % (n, args.out, time.perf_counter() - t_run))


if __name__ == "__main__":
    main()
