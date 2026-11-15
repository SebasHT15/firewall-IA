"""
firewall-IA — WIRE-EVIDENCE RUNNER v2 (issue #68, Track B). Drives the SAME local raw-socket lab
(harness.py) over every vector with BOTH the shadow canonical observer AND the shadow FRAMING observer
enabled, and writes the v2 evidence artifacts under
reports/v5/canonical-request-v1/wire-evidence-v2/.

    .venv-dataplane/bin/python -I scripts/wire_evidence/run_wire_evidence_v2.py

WHAT IS NEW vs v1 (run_wire_evidence.py, which this does NOT modify and whose v1 report it preserves):
  * The gateway is built with framing_observer=True (via lab_addon + WIRE_LAB_FRAMING=1), so mitmproxy
    drives the gateway's own configure() hook (sampling the EFFECTIVE profile, establishing the
    relevant-profile generation) and a FRAMING OBS line is logged beside each CANONICAL OBS line.
  * For every vector we record FIVE SEPARATE dimensions: (1) exact client outcome, (2) whether the
    parser normalized or rejected it and how, (3) reachability (addon / classifier / upstream sink),
    (4) the CANONICAL OBS line (status/outcome/reject), (5) the FRAMING OBS line (PROFILE_MATCHED /
    UNATTESTABLE / UNAVAILABLE + reasons). We do NOT assert all 14 R1 vectors were HTTP rejects.
  * Per-vector attribution is ORDER-BASED over the FULLY-FLUSHED log (mitmdump block-buffers its log
    stream, so a mid-run byte-offset read is unreliable). After the run, the log is parsed into ordered
    "flows" (each a request that reached the addon = has a `received` line, with its CANONICAL/FRAMING
    lines keyed by the same tag). Vectors are sent SERIALLY with a settle delay and the observer is
    single-in-flight (no queue), so the flows appear in send order; the ONE warm-up flow is skipped and
    the remaining flows map 1:1, in order, to the vectors that reached the addon. A per-flow method
    consistency check (flow method == vector method) guards the mapping.
  * Drift runs vih=true vs vih=false WITH BOTH OBSERVERS ON, so the framing outcome under a wrong
    configuration is recorded (not just the wire outcome). Effective options are saved per drift run.

HONESTY BARS (reproduced from v1 so the code cannot drift from them):
  * "A request reached the addon" is NOT evidence of R1. A parser rejection BEFORE the addon has
    socket evidence only and NO in-hook/project record — we never fabricate a CANONICAL/FRAMING line
    for a vector the parser rejected before the request hook ran.
  * A NORMALIZED forward is NOT enforcement. obs-fold's canonical R4 surfaces as UNATTESTABLE /
    CANONICAL_REJECT, never relabelled residual-framing success. bare-LF MAY reach PROFILE_MATCHED
    under the limited semantics yet is normalized traffic with wire verification unavailable.
  * The surrounding mitmdump log is a pre-existing gateway stream NOT covered by the observer's
    closed-vocabulary privacy guarantee.

Loopback only. If the live lab cannot start, the exact failed step/reason is recorded and the runner
exits non-zero; it never substitutes a fixture for wire evidence.
"""
from __future__ import annotations

import json
import os
import platform
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import harness as H  # noqa: E402
import run_wire_evidence as V1  # noqa: E402  (reuse the scan/parse helpers only; no file writes at import)

# The output directory is chosen at run time (argv[1], or WIRE_V2_REPORT_DIR) so a CORRECTED run can
# land in its own sibling (e.g. .../wire-evidence-v2/corrected/) WITHOUT overwriting the prior v2 run.
# The default is the original v2 dir, preserved only for the first (prior) build; the corrected run
# MUST pass an explicit `corrected` dir. v1 is never a valid target (guarded in __main__).
DEFAULT_REPORT_DIR = os.path.join(H.REPO_ROOT, "reports", "v5", "canonical-request-v1",
                                  "wire-evidence-v2")

# Implementation files whose SHA-256 the corrected-run metadata records as source provenance.
_SOURCE_FILES = ("data_plane/framing_evidence.py", "data_plane/canonical_observer.py",
                 "data_plane/canonical_adapter.py", "data_plane/canonical_request.py",
                 "data_plane/data_plane.py", "scripts/wire_evidence/harness.py",
                 "scripts/wire_evidence/lab_addon.py", "scripts/wire_evidence/run_wire_evidence_v2.py")


def _paths(report_dir: str) -> dict:
    return {"results": os.path.join(report_dir, "wire_evidence_v2_results.json"),
            "metadata": os.path.join(report_dir, "run_metadata.json"),
            "mitm_log": os.path.join(report_dir, "mitmdump_lab.log")}


_TAG_RE = re.compile(r"\[([0-9a-f]{8})\]")
_RECEIVED_RE = re.compile(r"\]\s+received\s+([A-Z]+)\s+(\S+?)(\*)?\s+\(body")


def _frag(line: str, marker: str) -> str:
    return line[line.index(marker):].strip()


def _parse_canonical(frag: str) -> dict:
    toks = frag.split()
    out = {"line": frag, "status": toks[2] if len(toks) >= 3 else None,
           "outcome": None, "reject": None, "reason": None, "target_form": None}
    for t in toks:
        for key in ("outcome", "reject", "reason", "target_form"):
            if t.startswith(key + "="):
                out[key] = t.split("=", 1)[1]
    return out


def _parse_framing(frag: str) -> dict:
    toks = frag.split()
    out = {"line": frag, "status": toks[2] if len(toks) >= 3 else None,
           "reasons": [], "canonical_status": None, "canonical_outcome": None,
           "target_form": None, "gen": None}
    for t in toks:
        if t.startswith("reasons="):
            out["reasons"] = t.split("=", 1)[1].split(",")
        elif t.startswith("canonical_status="):
            out["canonical_status"] = t.split("=", 1)[1]
        elif t.startswith("canonical_outcome="):
            out["canonical_outcome"] = t.split("=", 1)[1]
        elif t.startswith("target_form="):
            out["target_form"] = t.split("=", 1)[1]
        elif t.startswith("gen="):
            out["gen"] = t.split("=", 1)[1]
    return out


def _parse_flows(logpath: str) -> list:
    """Parse the FULLY-FLUSHED mitmdump log into an ordered list of flows. A flow is opened by a
    `received` line (the gateway's request hook ran = the addon was reached) and carries the
    CANONICAL/FRAMING lines that share its tag. Flows appear in log order = send order."""
    flows: list = []
    by_tag: dict = {}
    if not os.path.exists(logpath):
        return flows
    with open(logpath, "r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            tm = _TAG_RE.search(raw)
            tag = tm.group(1) if tm else None
            if "] received " in raw:
                rm = _RECEIVED_RE.search(raw)
                method = rm.group(1) if rm else None
                target = (rm.group(2) if rm else None)
                if rm and rm.group(3):           # asterisk-form appends '*' to host:port
                    target = "*"
                flow = {"tag": tag, "method": method, "target": target,
                        "received": raw.strip(), "canonical": None, "framing": None}
                flows.append(flow)
                if tag is not None:
                    by_tag[tag] = flow
            elif "CANONICAL OBS" in raw and tag in by_tag:
                by_tag[tag]["canonical"] = _parse_canonical(_frag(raw, "CANONICAL OBS"))
            elif "FRAMING OBS" in raw and tag in by_tag:
                by_tag[tag]["framing"] = _parse_framing(_frag(raw, "FRAMING OBS"))
    return flows


def _parser_verdict(outcome: str, client_status, upstream_delivered: bool) -> str:
    """A closed token describing what the third-party parser did to the vector (separate dimension)."""
    if outcome == H.OUT_PARSER_REJECT:
        return f"REJECTED_{client_status}" if client_status else "REJECTED"
    if outcome == H.OUT_CONN_RESET:
        return "CONN_RESET_NO_RESPONSE"
    if outcome == H.OUT_TIMEOUT:
        return "NO_RESPONSE_TIMEOUT"
    if outcome == H.OUT_NORMALIZED_FORWARD:
        return "NORMALIZED_FORWARD"
    if outcome == H.OUT_FAIL_CLOSED:
        return "ACCEPTED_THEN_GATEWAY_FAILCLOSED"   # parser passed it to the addon; gateway 503'd
    if outcome == H.OUT_ADDON_BLOCK:
        return "ACCEPTED_THEN_ADDON_BLOCK"
    if outcome == H.OUT_CLIENT_ERROR:
        return "CLIENT_ERROR"
    return outcome


# ── one vector: the WIRE dimensions (no log read; observations attached later) ─
def run_vector_wire(client: H.RawClient, vec: H.Vector, sink: H.UpstreamSink,
                    stub: H.ClassifierStub, settle_s: float) -> dict:
    sink.drain()
    before = stub.hit_count()
    res = client.send(vec.raw)
    time.sleep(settle_s)   # forward + sink record + background observer completion + log flush
    recs = sink.drain()
    classifier_called = stub.hit_count() > before
    upstream_delivered = len(recs) > 0
    outcome = H.classify(res, upstream_delivered, classifier_called)

    # Upstream (hop-2) summary + byte identity, same as v1.
    sink_summary = None
    sent = H.client_body(vec.raw)
    byte_identity = None
    if recs:
        r = recs[0]
        if sent and not r.chunked:
            byte_identity = {
                "sent_body_sha256": H.body_sha256(sent), "sent_body_len": len(sent),
                "upstream_body_sha256": r.body_sha256, "upstream_body_len": r.body_len,
                "byte_identical": H.bodies_identical(sent, r.body_sha256)}
        elif r.chunked:
            byte_identity = {"byte_identical": None,
                             "reason": "chunked: client body chunk-framed, sink de-chunked"}
        sink_summary = {"request_line": r.request_line, "header_names": r.header_names,
                        "content_length_hdr": r.content_length_hdr,
                        "transfer_encoding_hdr": r.transfer_encoding_hdr,
                        "body_len": r.body_len, "chunked": r.chunked, "truncated": r.truncated,
                        "body_sha256": r.body_sha256}

    # Reachability from WIRE signals only (log is attributed later). The addon ran iff V4 was asked
    # (classifier hit), the request was forwarded, OR the gateway fail-closed (503) after the hook ran.
    addon_reached = upstream_delivered or classifier_called or (res.status_code == 503)

    dim_client = {"observed_outcome": outcome, "client_status": res.status_code,
                  "client_status_line": res.status_line, "client_reset": res.reset,
                  "client_timed_out": res.timed_out, "client_error": res.error,
                  "client_elapsed_ms": round(res.elapsed_ms, 2)}
    dim_parser = {"verdict": _parser_verdict(outcome, res.status_code, upstream_delivered),
                  "upstream_delivered": upstream_delivered, "upstream": sink_summary,
                  "byte_identity": byte_identity}
    dim_reach = {"addon_reached": addon_reached, "classifier_called": classifier_called,
                 "upstream_sink_reached": upstream_delivered}

    return {
        "vid": vec.vid, "group": vec.group, "description": vec.description,
        "justification": vec.justification, "expected_parser": vec.expected_parser,
        "expected_contract": vec.expected_contract, "counterpart": vec.counterpart,
        "sent_bytes": res.sent_bytes,
        "dimensions": {
            "1_client_outcome": dim_client,
            "2_parser": dim_parser,
            "3_reachability": dim_reach,
            "4_canonical": None,   # attached from the log by order after the run
            "5_framing": None,
        },
        "_expected_method": vec.raw.split(b" ", 1)[0].decode("latin-1", "replace"),
    }


def attach_observations(results: list, flows: list) -> dict:
    """Map the fully-flushed log flows to the vectors that reached the addon, IN ORDER. The leading
    warm-up flow(s) are skipped (n_warmup = #flows - #addon-reaching results). Returns a correlation
    report (any method mismatch or count skew is recorded, never silently papered over)."""
    addon_results = [r for r in results if r["dimensions"]["3_reachability"]["addon_reached"]]
    n_warmup = len(flows) - len(addon_results)
    report = {"total_flows": len(flows), "addon_reaching_vectors": len(addon_results),
              "assumed_warmup_flows": n_warmup, "method_mismatches": [], "count_skew": False,
              "assignments": []}
    if n_warmup < 0:
        report["count_skew"] = True
        n_warmup = 0
    usable = flows[n_warmup:]
    for r, fl in zip(addon_results, usable):
        r["dimensions"]["4_canonical"] = fl["canonical"]
        r["dimensions"]["5_framing"] = fl["framing"]
        match = (fl["method"] == r["_expected_method"])
        r["correlation"] = {"flow_tag": fl["tag"], "flow_method": fl["method"],
                            "flow_target": fl["target"], "method_matches": match}
        report["assignments"].append({"vid": r["vid"], "tag": fl["tag"],
                                      "flow_method": fl["method"], "method_matches": match})
        if not match:
            report["method_mismatches"].append({"vid": r["vid"], "expected": r["_expected_method"],
                                                "flow_method": fl["method"]})
    if len(addon_results) != len(usable):
        report["count_skew"] = True
    for r in results:
        r.pop("_expected_method", None)
    return report


# ── drift: vih true vs false, BOTH observers on, framing outcomes recorded ─────
def run_drift_v2(sink: H.UpstreamSink, stub: H.ClassifierStub, logdir: str) -> dict:
    """Run the discriminating TE+CL vector under validate_inbound_headers true vs false, each with the
    canonical AND framing observers ON, saving the EFFECTIVE options and the framing outcome per run.

      * vih=true  (tested profile): the parser REJECTS TE+CL at the wire -> the addon never runs ->
        there is NO in-hook CANONICAL/FRAMING record (socket evidence only). We do NOT fabricate one.
      * vih=false: the parser FORWARDS the smuggling vector -> the addon runs -> canonical REJECT (R1)
        and framing must be UNATTESTABLE (profile is no longer the tested one: VALIDATE_INBOUND_HEADERS
        _OFF + PROFILE_NOT_TESTED, plus CANONICAL_REJECT). It can NEVER be PROFILE_MATCHED.
    """
    vectors = {v.vid: v for v in H.all_vectors()}
    probe = vectors["R1-TECL"]
    out = {"probe_vid": probe.vid, "runs": {}}
    for flag in (True, False):
        prof = H.LabProfile(sink_url=sink.url, classifier_url=stub.url,
                            validate_inbound_headers=flag, observer=True, framing=True)
        logp = os.path.join(logdir, f"drift_vih_{str(flag).lower()}.log")
        run = {"effective_options": None}
        try:
            prof.start(logp)
            client = H.RawClient(H.LOOPBACK, prof.listen_port)
            # Warm the observer worker with a valid request so the probe is observed if forwarded.
            client.send(vectors["VALID-GET"].raw)
            time.sleep(0.6)
            rec = run_vector_wire(client, probe, sink, stub, settle_s=0.9)
            run["observed_outcome"] = rec["dimensions"]["1_client_outcome"]["observed_outcome"]
            run["client_status"] = rec["dimensions"]["1_client_outcome"]["client_status"]
            run["upstream_delivered"] = rec["dimensions"]["2_parser"]["upstream_delivered"]
            run["parser_verdict"] = rec["dimensions"]["2_parser"]["verdict"]
            run["addon_reached"] = rec["dimensions"]["3_reachability"]["addon_reached"]
        except Exception as exc:  # noqa: BLE001
            run["error"] = f"{type(exc).__name__}: {exc}"
        finally:
            prof.stop()
            time.sleep(0.8)   # flush the log before parsing it
        # Attribute the probe's observation from the fully-flushed drift log (warm-up = first flow).
        run["canonical"] = run["framing"] = None
        if "error" not in run and run.get("addon_reached"):
            flows = _parse_flows(logp)
            probe_flows = flows[1:]   # skip the single warm-up flow
            if probe_flows:
                fl = probe_flows[0]
                run["canonical"] = fl["canonical"]
                run["framing"] = fl["framing"]
                run["flow_tag"] = fl["tag"]
        run["effective_options"] = V1.parse_effective_options(logp)
        out["runs"][f"validate_inbound_headers={flag}"] = run

    a = out["runs"].get("validate_inbound_headers=True", {})
    b = out["runs"].get("validate_inbound_headers=False", {})
    wire_demonstrated = ("error" not in a and "error" not in b
                         and a.get("observed_outcome") != b.get("observed_outcome"))
    # Framing-level demonstration: with the control OFF, framing must NOT be PROFILE_MATCHED for the
    # smuggling vector that is now forwarded (it is UNATTESTABLE). With the control ON, the vector
    # never reaches the addon, so there is no framing line at all (socket-only rejection).
    fb = b.get("framing")
    framing_demonstrated = bool(fb and fb.get("status") == "UNATTESTABLE")
    out["wire_control_demonstrated"] = wire_demonstrated
    out["framing_control_demonstrated"] = framing_demonstrated
    out["interpretation"] = (
        "vih=true: parser rejects TE+CL at the wire; the addon never runs so there is no in-hook "
        "CANONICAL/FRAMING record (socket evidence only; not fabricated). vih=false: the vector is "
        "forwarded, the addon runs, canonical REJECTs it R1 and framing is UNATTESTABLE "
        "(VALIDATE_INBOUND_HEADERS_OFF + PROFILE_NOT_TESTED [+ CANONICAL_REJECT]) — never "
        "PROFILE_MATCHED. The control changes both the wire outcome and the framing conclusion.")
    return out


# ── metadata ──────────────────────────────────────────────────────────────────
def collect_metadata(prof: "H.LabProfile", report_dir: str) -> dict:
    meta = {
        "report": "wire-evidence-v2 (corrected)" if report_dir.rstrip("/").endswith("corrected")
                  else "wire-evidence-v2",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "d70_status": "D70 APPROVED (was PROPOSED). This CORRECTED run is against the gateway after "
                      "defects A (framing requires EXACTLY HTTP/1.1; HTTP/1.0 OK+ACCEPT -> UNATTESTABLE "
                      "HTTP_VERSION_NOT_11), B (mode validation checks transport+address: reverse+http+"
                      "loopback), and C (reservation ownership) were fixed. Observe-only / default-off "
                      "invariants unchanged.",
        "extends": "reports/v5/canonical-request-v1/wire-evidence-v1 (PRESERVED UNCHANGED) and the "
                   "PRIOR reports/v5/canonical-request-v1/wire-evidence-v2 run (also PRESERVED; this "
                   "corrected run is written to its own directory and does NOT rewrite prior hashes). "
                   "v2 adds the shadow FRAMING observer on top of the canonical observer, five "
                   "per-vector dimensions, the framing outcome under vih drift, and (corrected) the "
                   "HTTP/1.0 vs HTTP/1.1 version boundary.",
        "python": platform.python_version(),
        "platform": platform.platform(),
        "versions": {},
        "version_pins_note": (
            "mitmproxy==12.2.3 is a PINNED data-plane dependency (requirements-data-plane.txt). "
            "Brotli and zstandard are reported as OBSERVED in .venv-dataplane (transitive deps); they "
            "are NOT ratified direct deployment pins. Version/profile claims derive from this runtime "
            "metadata, not asserted independently."),
        "config_yaml_sha256": None,
        "lab_profile": {
            "proxy": "mitmdump reverse proxy -> local sink (dynamic loopback port)",
            "classifier": "local deterministic ALLOW stub",
            "canonical_observer": "canonical-request/v1 observer ENABLED via lab_addon "
                                  "(config.yaml / data_plane.py untouched)",
            "framing_observer": "shadow framing observer ENABLED (WIRE_LAB_FRAMING=1); the gateway's "
                                "own configure() hook samples the EFFECTIVE profile and the FRAMING "
                                "OBS line is logged beside each CANONICAL OBS line",
            "caps": {"max_decoded_body": 1 << 20, "max_body_bytes": 1 << 20,
                     "token_budget": "UNSET (size stays UNCHECKED; Fast Path ineligible)"},
            "requested_options": prof.requested_options(),
            "profile_marker": "reverse_proxy:loopback_dynamic_port",
            "note": "Evidence establishes behaviour of THIS tested profile only; runtime framing "
                    "stays UNAVAILABLE/UNVERIFIED globally. PROFILE_MATCHED means only 'profile + "
                    "observed snapshot met the defined conditions' — never VERIFIED / safe to forward "
                    "/ Fast-Path eligible / wire-equivalent.",
        },
        "effective_options": None,
    }
    for mod in ("mitmproxy", "brotli", "zstandard"):
        try:
            if mod == "mitmproxy":
                from mitmproxy import version as mv
                meta["versions"][mod] = mv.VERSION
            else:
                m = __import__(mod)
                meta["versions"][mod] = getattr(m, "__version__", "?")
        except Exception as exc:  # noqa: BLE001
            meta["versions"][mod] = f"import-failed:{type(exc).__name__}"
    cfg = os.path.join(H.REPO_ROOT, "config.yaml")
    if os.path.exists(cfg):
        meta["config_yaml_sha256"] = V1._sha256_file(cfg)
    meta["config_yaml_provenance"] = (
        "The prior v2 run recorded config_yaml_sha256=23c1854… ; this corrected run records the "
        "CURRENT config.yaml SHA above. The only difference is a coordinator COMMENT-ONLY edit "
        "('D70 PROPOSED' -> 'D70') made after the prior run; no runtime setting or gateway behaviour "
        "changed. The prior metadata is not overwritten.")
    # Source provenance: identify (by SHA-256) the exact implementation files this run exercised, so
    # the corrected run is tied to the corrected gateway sources, not merely asserted.
    src = {}
    for rel in _SOURCE_FILES:
        p = os.path.join(H.REPO_ROOT, rel)
        src[rel] = V1._sha256_file(p) if os.path.exists(p) else "MISSING"
    meta["source_provenance"] = {
        "note": "SHA-256 of the implementation files used by this lab run (the corrected gateway "
                "sources + the lab harness). data_plane/* are the coordinator's/Track A's corrected "
                "files, imported by lab_addon.py and NEVER modified by this track.",
        "files": src}
    return meta


def _tally(results: list) -> dict:
    client, parser, canonical, framing = {}, {}, {}, {}
    for r in results:
        d = r["dimensions"]
        o = d["1_client_outcome"]["observed_outcome"]
        client[o] = client.get(o, 0) + 1
        pv = d["2_parser"]["verdict"]
        parser[pv] = parser.get(pv, 0) + 1
        c = d["4_canonical"]
        ck = "none" if c is None else (c["status"] if c["outcome"] is None
                                       else f"{c['status']}/{c['outcome']}"
                                       + (f"/{c['reject']}" if c["reject"] else ""))
        canonical[ck] = canonical.get(ck, 0) + 1
        f = d["5_framing"]
        fk = "none" if f is None else (f["status"] + (f"/{'+'.join(f['reasons'])}" if f["reasons"] else ""))
        framing[fk] = framing.get(fk, 0) + 1
    return {"client_outcome": client, "parser_verdict": parser,
            "canonical": canonical, "framing": framing}


def main(report_dir: str) -> int:
    paths = _paths(report_dir)
    results_json, metadata_json, mitm_log = paths["results"], paths["metadata"], paths["mitm_log"]
    os.makedirs(report_dir, exist_ok=True)
    report = {"metadata": None, "wire_evidence": None, "drift": None,
              "contract_level_residual": None, "live_run": None}

    try:
        report["contract_level_residual"] = {
            "note": "PARTS-LEVEL evidence of canonical_request.canonicalize() (NOT wire evidence); "
                    "reproduced from the shared harness so v2 is self-contained.",
            "cases": H.contract_level_residual()}
    except Exception as exc:  # noqa: BLE001
        report["contract_level_residual"] = {"error": f"{type(exc).__name__}: {exc}"}

    stub = H.ClassifierStub()
    sink = H.UpstreamSink()
    prof = H.LabProfile(sink_url=sink.url, classifier_url=stub.url,
                        validate_inbound_headers=True, observer=True, framing=True)
    meta = collect_metadata(prof, report_dir)
    report["metadata"] = meta
    live = {"ok": False, "failed_step": None, "reason": None, "framing_observer": True,
            "report_dir": report_dir}
    try:
        stub.start()
        sink.start()
    except Exception as exc:  # noqa: BLE001
        live.update(failed_step="start local stub/sink", reason=f"{type(exc).__name__}: {exc}")
        report["live_run"] = live
        _write(report, results_json, metadata_json)
        print("LIVE LAB UNAVAILABLE:", live, file=sys.stderr)
        return 2

    live["mitmdump_argv"] = prof.argv()
    live["mitmdump_cmd"] = " ".join(prof.argv())
    try:
        prof.start(mitm_log)
    except Exception as exc:  # noqa: BLE001
        live.update(failed_step="start mitmdump lab profile", reason=f"{type(exc).__name__}: {exc}")
        report["live_run"] = live
        stub.stop(); sink.stop()
        _write(report, results_json, metadata_json)
        print("LIVE LAB UNAVAILABLE at mitmdump start:", live["reason"], file=sys.stderr)
        return 3

    results = []
    try:
        client = H.RawClient(H.LOOPBACK, prof.listen_port)
        client.send(H.all_vectors()[0].raw)   # warm the worker before the catalogue
        time.sleep(0.8)
        sink.drain()
        for v in H.all_vectors():
            results.append(run_vector_wire(client, v, sink, stub, settle_s=0.8))
        live["ok"] = True
    finally:
        prof.stop()
        time.sleep(0.8)   # flush the whole log before parsing it

    # Order-based attribution over the fully-flushed log (mitmdump block-buffers during the run).
    flows = _parse_flows(mitm_log)
    correlation = attach_observations(results, flows)
    report["wire_evidence"] = {
        "proxy_listen_port": prof.listen_port, "sink_url": sink.url,
        "classifier_url": stub.url, "total_classifier_hits": stub.hit_count(),
        "correlation": correlation, "tallies": _tally(results), "results": results}
    report["wire_evidence"]["observer_evidence"] = V1.parse_observer_log(mitm_log)
    eff = V1.parse_effective_options(mitm_log)
    meta["effective_options"] = eff
    meta["lab_profile"]["effective_options"] = eff
    report["wire_evidence"]["shutdown_health"] = V1._scan_shutdown(mitm_log)

    try:
        report["drift"] = run_drift_v2(sink, stub, report_dir)
    except Exception as exc:  # noqa: BLE001
        report["drift"] = {"error": f"{type(exc).__name__}: {exc}"}

    stub.stop(); sink.stop()
    report["live_run"] = live
    _write(report, results_json, metadata_json)
    _print_summary(report, report_dir)
    return 0


def _write(report: dict, results_json: str, metadata_json: str):
    os.makedirs(os.path.dirname(results_json), exist_ok=True)
    with open(metadata_json, "w", encoding="utf-8") as f:
        json.dump(report["metadata"], f, indent=2, sort_keys=True)
    with open(results_json, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, sort_keys=True)


def _print_summary(report: dict, report_dir: str):
    we = report.get("wire_evidence") or {}
    print("=== WIRE EVIDENCE v2 SUMMARY (client / parser / reach / canonical / framing) ===")
    for r in we.get("results", []):
        d = r["dimensions"]
        c = d["4_canonical"]
        f = d["5_framing"]
        cs = "-" if c is None else (f"{c['status']}"
                                    + (f"/{c['outcome']}" if c["outcome"] else "")
                                    + (f"/{c['reject']}" if c["reject"] else ""))
        fs = "-" if f is None else (f"{f['status']}"
                                    + (f"[{','.join(f['reasons'])}]" if f["reasons"] else ""))
        print(f"{r['vid']:<20} {r['group']:<6} "
              f"client={d['1_client_outcome']['observed_outcome']:<18} "
              f"parser={d['2_parser']['verdict']:<32} "
              f"addon={str(d['3_reachability']['addon_reached']):<5} "
              f"canon={cs:<22} framing={fs}")
    print("\nTALLIES:", json.dumps(we.get("tallies"), sort_keys=True))
    dr = report.get("drift") or {}
    print(f"\nDRIFT wire_demonstrated={dr.get('wire_control_demonstrated')} "
          f"framing_demonstrated={dr.get('framing_control_demonstrated')}")
    print(f"Artifacts written to: {report_dir}")


def _resolve_report_dir() -> str:
    """Pick the output directory: argv[1], else $WIRE_V2_REPORT_DIR, else the default v2 dir. A path
    under wire-evidence-v1 is REFUSED (v1 is historical evidence, preserved byte-for-byte)."""
    chosen = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("WIRE_V2_REPORT_DIR")
    report_dir = os.path.abspath(chosen) if chosen else DEFAULT_REPORT_DIR
    if "wire-evidence-v1" in os.path.normpath(report_dir).split(os.sep):
        raise SystemExit("refusing to write into wire-evidence-v1 (preserved historical evidence)")
    return report_dir


if __name__ == "__main__":
    sys.exit(main(_resolve_report_dir()))
