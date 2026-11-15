"""
firewall-IA — WIRE-EVIDENCE RUNNER (issue #68, §8). Drives the local lab (harness.py) over every
vector and writes the evidence artifacts under reports/v5/canonical-request-v1/wire-evidence-v1/.

    .venv-dataplane/bin/python -I scripts/wire_evidence/run_wire_evidence.py

Everything is loopback-only. If the live lab cannot start (no mitmdump, cannot bind, cannot spawn),
the runner records the EXACT failed step and reason, still writes the vector catalogue and the
contract-level residual evidence, and exits non-zero. It never substitutes a header-only fixture for
wire evidence.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import socket
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import harness as H  # noqa: E402

REPORT_DIR = os.path.join(H.REPO_ROOT, "reports", "v5", "canonical-request-v1", "wire-evidence-v1")
RESULTS_JSON = os.path.join(REPORT_DIR, "wire_evidence_results.json")
METADATA_JSON = os.path.join(REPORT_DIR, "run_metadata.json")
MITM_LOG = os.path.join(REPORT_DIR, "mitmdump_lab.log")


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(65536), b""):
            h.update(block)
    return h.hexdigest()


def collect_metadata(prof: "H.LabProfile") -> dict:
    meta = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "supersedes": "An earlier run_metadata.json listed lab_profile.stream_large_bodies=0, which "
                      "was INACCURATE: the launcher leaves stream_large_bodies UNSET. This fresh "
                      "timestamped run records REQUESTED options (from argv) and EFFECTIVE options "
                      "(read back from the running lab via lab_addon) separately. Prior raw per-vector "
                      "results were not retro-edited; this is a new executed run.",
        "python": platform.python_version(),
        "platform": platform.platform(),
        "versions": {},
        "version_pins_note": None,     # filled below (honesty: what is pinned vs merely observed)
        "config_yaml_sha256": None,
        "lab_profile": {
            "proxy": "mitmdump reverse proxy -> local sink",
            "classifier": "local deterministic ALLOW stub",
            "observer": "canonical-request/v1 observer ENABLED via lab_addon (config.yaml untouched)",
            "requested_options": prof.requested_options(),
            "effective_options": "<read back from the running lab after start; see effective_options>",
            "note": "Evidence establishes behaviour of THIS tested profile only; runtime framing "
                    "stays UNAVAILABLE/UNVERIFIED globally until a scoped control is implemented and "
                    "approved. VERIFIED is NOT set globally.",
        },
        "effective_options": None,     # filled after the run from the lab log
    }
    for mod in ("mitmproxy", "brotli", "zstandard"):
        try:
            m = __import__(mod)
            if mod == "mitmproxy":
                from mitmproxy import version as mv
                meta["versions"][mod] = mv.VERSION
            else:
                meta["versions"][mod] = getattr(m, "__version__", "?")
        except Exception as exc:  # noqa: BLE001
            meta["versions"][mod] = f"import-failed:{type(exc).__name__}"
    meta["version_pins_note"] = (
        "mitmproxy==12.2.3 is a PINNED data-plane dependency (requirements-data-plane.txt). "
        "Brotli and zstandard are reported as OBSERVED in .venv-dataplane (transitive deps of "
        "mitmproxy); they are NOT ratified direct deployment pins here. Version/profile claims are "
        "derived from this runtime metadata, not asserted independently.")
    try:
        from mitmproxy import version as mv
        meta["versions"]["mitmproxy"] = mv.VERSION
    except Exception:  # noqa: BLE001
        pass
    cfg = os.path.join(H.REPO_ROOT, "config.yaml")
    if os.path.exists(cfg):
        meta["config_yaml_sha256"] = _sha256_file(cfg)
    return meta


def _scan_shutdown(logpath: str) -> dict:
    """Report, from the actual lab log, whether the pre-repair shutdown defect is gone:
    `BaseSubprocessTransport.__del__ ... RuntimeError: Event loop is closed`. A §repair expects it
    eliminated, with at most a benign asyncio 'Close running child process' info line instead."""
    found = {"del_runtimeerror": False, "event_loop_is_closed": False,
             "close_running_child_process": False, "other_tracebacks": 0, "lines": []}
    if not os.path.exists(logpath):
        return {"present": False}
    with open(logpath, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            low = line.lower()
            if "basesubprocesstransport.__del__" in low:
                found["del_runtimeerror"] = True
                found["lines"].append(line.strip()[:200])
            if "event loop is closed" in low:
                found["event_loop_is_closed"] = True
                found["lines"].append(line.strip()[:200])
            if "close running child process" in low:
                found["close_running_child_process"] = True
            if "traceback (most recent call last)" in low:
                found["other_tracebacks"] += 1
    found["present"] = True
    found["del_runtimeerror_gone"] = not (found["del_runtimeerror"] or found["event_loop_is_closed"])
    return found


def parse_effective_options(logpath: str) -> dict:
    """Read the EFFECTIVE mitmproxy option values that lab_addon logged from the running instance."""
    import re
    out = {}
    if not os.path.exists(logpath):
        return {"present": False}
    pat = re.compile(r"LAB EFFECTIVE OPTION (\w+)=(.*)$")
    with open(logpath, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            m = pat.search(line.rstrip("\n"))
            if m:
                out[m.group(1)] = m.group(2)
    out["present"] = bool(out)
    return out


def parse_observer_log(logpath: str) -> dict:
    """Extract the gateway's own observation evidence from the mitmdump log: the 'CANONICAL OBS'
    lines (closed vocabulary, NO request bytes by design) and a tally of the gateway decision lines.
    This shows the REAL canonical observer ran end-to-end over the forwarded wire traffic."""
    import re
    obs_lines, decisions = [], {"received": 0, "ALLOW": 0, "BLOCK": 0, "fail_closed": 0}
    status_tally, outcome_tally, form_tally = {}, {}, {}
    tag_path: dict = {}          # tag -> the request path on its "received" line (for correlation)
    correlated = []
    tag_re = re.compile(r"\[([0-9a-f]{8})\]")
    if not os.path.exists(logpath):
        return {"present": False}
    with open(logpath, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            m = tag_re.search(line)
            tag = m.group(1) if m else None
            if "] received " in line:
                decisions["received"] += 1
                # "... received METHOD host:port/path (body N bytes)"
                try:
                    seg = line.split("] received ", 1)[1]
                    method = seg.split(" ", 1)[0]
                    hostpath = seg.split(" ", 1)[1].split(" (body", 1)[0]
                    path = hostpath.split("/", 1)[-1] if "/" in hostpath else hostpath.split(":")[-1]
                    if tag:
                        tag_path[tag] = f"{method} /{path}" if not hostpath.endswith("*") else f"{method} *"
                except (IndexError, ValueError):
                    pass
            elif "CANONICAL OBS" in line:
                frag = line[line.index("CANONICAL OBS"):].strip()
                obs_lines.append(frag)
                toks = frag.split()
                if len(toks) >= 3:
                    status_tally[toks[2]] = status_tally.get(toks[2], 0) + 1
                for t in toks:
                    if t.startswith("outcome="):
                        outcome_tally[t] = outcome_tally.get(t, 0) + 1
                    if t.startswith("target_form="):
                        form_tally[t] = form_tally.get(t, 0) + 1
                correlated.append({"received": tag_path.get(tag), "obs": frag})
            elif "] ALLOW " in line:
                decisions["ALLOW"] += 1
            elif "] BLOCK (fail-closed)" in line:
                decisions["fail_closed"] += 1
            elif "] BLOCK " in line:
                decisions["BLOCK"] += 1
    return {"present": True, "canonical_obs_count": len(obs_lines),
            "status_tally": status_tally, "outcome_tally": outcome_tally,
            "target_form_tally": form_tally, "decision_tally": decisions,
            "correlated": correlated, "sample_lines": obs_lines[:40]}


def run_vector(client: H.RawClient, vec: H.Vector, sink: H.UpstreamSink,
               stub: H.ClassifierStub) -> dict:
    sink.drain()
    before = stub.hit_count()
    res = client.send(vec.raw)
    time.sleep(0.4)   # let the reverse-proxy forward + sink record + addon log settle
    recs = sink.drain()
    classifier_called = stub.hit_count() > before
    sink_delivered = len(recs) > 0
    outcome = H.classify(res, sink_delivered, classifier_called)
    sink_summary = None
    # Byte-identity across the hop (SHA-256), not just length. Only meaningful when the body was
    # delivered and is not chunked (the sink de-chunks, so a chunk-framed client body intentionally
    # will not match the de-chunked sink sha; marked None with a reason).
    sent = H.client_body(vec.raw)
    byte_identity = None
    if recs:
        r = recs[0]
        if sent and not r.chunked:
            byte_identity = {
                "sent_body_sha256": H.body_sha256(sent),
                "sent_body_len": len(sent),
                "upstream_body_sha256": r.body_sha256,
                "upstream_body_len": r.body_len,
                "byte_identical": H.bodies_identical(sent, r.body_sha256),
            }
        elif r.chunked:
            byte_identity = {"byte_identical": None,
                             "reason": "chunked: client body is chunk-framed, sink de-chunked; "
                                       "length-only comparison would be misleading"}
        sink_summary = {
            "request_line": r.request_line,
            "header_names": r.header_names,
            "content_length_hdr": r.content_length_hdr,
            "transfer_encoding_hdr": r.transfer_encoding_hdr,
            "body_len": r.body_len,
            "chunked": r.chunked,
            "truncated": r.truncated,
            "body_sha256": r.body_sha256,
        }
    return {
        "vid": vec.vid,
        "group": vec.group,
        "description": vec.description,
        "justification": vec.justification,
        "expected_parser": vec.expected_parser,
        "expected_contract": vec.expected_contract,
        "facts_lost": vec.facts_lost,
        "counterpart": vec.counterpart,
        "sent_bytes": res.sent_bytes,
        "client_status": res.status_code,
        "client_status_line": res.status_line,
        "client_reset": res.reset,
        "client_timed_out": res.timed_out,
        "client_error": res.error,
        "client_elapsed_ms": round(res.elapsed_ms, 2),
        "classifier_called": classifier_called,
        "upstream_delivered": sink_delivered,
        "upstream": sink_summary,
        "byte_identity": byte_identity,
        "observed_outcome": outcome,
    }


def run_drift(sink: H.UpstreamSink, stub: H.ClassifierStub, logdir: str) -> dict:
    """Pick a discriminating vector and run it under validate_inbound_headers true vs false.
    If the outcome differs, the control is demonstrated for that vector; otherwise report that it
    was NOT demonstrated (do NOT require every vector to flip)."""
    vectors = {v.vid: v for v in H.all_vectors()}
    probe = vectors["R1-TECL"]
    out = {"probe_vid": probe.vid, "runs": {}}
    for flag in (True, False):
        prof = H.LabProfile(sink_url=sink.url, classifier_url=stub.url,
                            validate_inbound_headers=flag, observer=False)
        logp = os.path.join(logdir, f"drift_vih_{str(flag).lower()}.log")
        try:
            prof.start(logp)
            client = H.RawClient(H.LOOPBACK, prof.listen_port)
            rec = run_vector(client, probe, sink, stub)
            out["runs"][f"validate_inbound_headers={flag}"] = {
                "observed_outcome": rec["observed_outcome"],
                "client_status": rec["client_status"],
                "upstream_delivered": rec["upstream_delivered"],
            }
        except Exception as exc:  # noqa: BLE001
            out["runs"][f"validate_inbound_headers={flag}"] = {"error": f"{type(exc).__name__}: {exc}"}
        finally:
            prof.stop()
            time.sleep(0.5)
    runs = out["runs"]
    a = runs.get("validate_inbound_headers=True", {})
    b = runs.get("validate_inbound_headers=False", {})
    demonstrated = ("error" not in a and "error" not in b
                    and a.get("observed_outcome") != b.get("observed_outcome"))
    out["control_demonstrated"] = demonstrated
    out["interpretation"] = (
        "The validate_inbound_headers control changes this vector's wire outcome under the tested "
        "profile." if demonstrated else
        "The control was NOT demonstrated by this vector: the outcome did not differ (or a run "
        "failed). This is reported honestly; it does not prove the control is absent.")
    return out


def main() -> int:
    os.makedirs(REPORT_DIR, exist_ok=True)
    report = {"metadata": None, "wire_evidence": None, "drift": None,
              "contract_level_residual": None, "live_run": None}

    # Contract-level residual evidence always runs (pure, no network).
    try:
        report["contract_level_residual"] = {
            "note": "PARTS-LEVEL evidence of the project-owned canonical_request.canonicalize() "
                    "control. This is NOT wire evidence; it exercises the residual-R1/R2/R4 checks on "
                    "parts that survive parsing.",
            "cases": H.contract_level_residual(),
        }
    except Exception as exc:  # noqa: BLE001
        report["contract_level_residual"] = {"error": f"{type(exc).__name__}: {exc}"}

    stub = H.ClassifierStub()
    sink = H.UpstreamSink()
    prof = H.LabProfile(sink_url=sink.url, classifier_url=stub.url,
                        validate_inbound_headers=True, observer=True)
    meta = collect_metadata(prof)
    report["metadata"] = meta
    live = {"ok": False, "failed_step": None, "reason": None}
    try:
        stub.start()
        sink.start()
    except Exception as exc:  # noqa: BLE001
        live["failed_step"] = "start local stub/sink"
        live["reason"] = f"{type(exc).__name__}: {exc}"
        report["live_run"] = live
        _write(report)
        print("LIVE LAB UNAVAILABLE:", live, file=sys.stderr)
        return 2

    live["mitmdump_argv"] = prof.argv()
    try:
        prof.start(MITM_LOG)
    except Exception as exc:  # noqa: BLE001
        live["failed_step"] = "start mitmdump lab profile"
        live["reason"] = f"{type(exc).__name__}: {exc}"
        live["mitmdump_cmd"] = " ".join(prof.argv())
        report["live_run"] = live
        stub.stop(); sink.stop()
        _write(report)
        print("LIVE LAB UNAVAILABLE at mitmdump start:", live["reason"], file=sys.stderr)
        print("Vector catalogue + contract-level residual were still written.", file=sys.stderr)
        return 3

    try:
        client = H.RawClient(H.LOOPBACK, prof.listen_port)
        # Warm-up with a known-good request so the observer worker is up before the catalogue.
        client.send(H.all_vectors()[0].raw)
        time.sleep(0.5)
        sink.drain()
        results = [run_vector(client, v, sink, stub) for v in H.all_vectors()]
        report["wire_evidence"] = {
            "proxy_listen_port": prof.listen_port,
            "sink_url": sink.url, "classifier_url": stub.url,
            "total_classifier_hits": stub.hit_count(),
            "results": results,
        }
        live["ok"] = True
    finally:
        prof.stop()
        time.sleep(0.8)   # let the observer worker flush its last CANONICAL OBS line to the log
    report["wire_evidence"]["observer_evidence"] = parse_observer_log(MITM_LOG)
    eff = parse_effective_options(MITM_LOG)
    meta["effective_options"] = eff
    meta["lab_profile"]["effective_options"] = eff
    # Shutdown-honesty: did A's fixed observer eliminate the BaseSubprocessTransport.__del__ error?
    report["wire_evidence"]["shutdown_health"] = _scan_shutdown(MITM_LOG)

    # Drift experiment reuses the same sink/stub but its own short-lived proxies.
    try:
        report["drift"] = run_drift(sink, stub, REPORT_DIR)
    except Exception as exc:  # noqa: BLE001
        report["drift"] = {"error": f"{type(exc).__name__}: {exc}"}

    stub.stop(); sink.stop()
    report["live_run"] = live
    _write(report)
    _print_summary(report)
    return 0


def _write(report: dict):
    os.makedirs(REPORT_DIR, exist_ok=True)
    with open(METADATA_JSON, "w", encoding="utf-8") as f:
        json.dump(report["metadata"], f, indent=2, sort_keys=True)
    with open(RESULTS_JSON, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, sort_keys=True)


def _print_summary(report: dict):
    we = report.get("wire_evidence") or {}
    print("=== WIRE EVIDENCE SUMMARY ===")
    for r in we.get("results", []):
        print(f"{r['vid']:<20} {r['group']:<6} outcome={r['observed_outcome']:<18} "
              f"client={r['client_status']} upstream={r['upstream_delivered']} "
              f"classifier={r['classifier_called']} (expected_parser={r['expected_parser']})")
    d = report.get("drift") or {}
    print(f"\nDRIFT ({d.get('probe_vid')}): control_demonstrated={d.get('control_demonstrated')}")
    print(f"\nArtifacts written to: {REPORT_DIR}")


if __name__ == "__main__":
    sys.exit(main())
