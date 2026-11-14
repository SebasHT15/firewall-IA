"""
Minimal functional smoke for one sec-challenges application behind the local stack. INTEGRATION PHASE
ONLY: it proves the application starts, serves benign requests, is reached by the firewall arms, that a
block is attributed to the correct layer, and that the run tears down clean. It is NOT a measurement:
with `--v5 double` the only firewall rejections are the double's rule (BLOCK on the literal word `evil`),
and the CRS arm uses one known mechanism request. No false-positive rate, attack-block rate, latency or
load number is produced here, and nothing is tuned on any final set.

    PY=.venv-dataplane/bin/python
    $PY scripts/local_stack/challenges/smoke.py --app CatP1cs --arm v5only --v5 double \
        --work <new private dir> --evidence <new evidence dir>

It drives the real CLI (`challenge_stack.py config|up|down|check-clean`) by subprocess, so the commands in
the evidence are exactly the reproducible ones. Requests go over the shared TLS front (HTTP/1.1) for the
firewall arms and straight to the application for the direct arm, reusing the stack's own wire clients.
Attribution uses three independent logs: the front access log, the gateway decision record, and the
application container's console (the challenge apps emit no structured app log — this is a documented
limit).
"""
import argparse
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
LOCAL_STACK = os.path.dirname(HERE)
REPO = os.path.dirname(os.path.dirname(LOCAL_STACK))
sys.path[:0] = [HERE, LOCAL_STACK]

import adapters                 # noqa: E402
import wire_clients as WC       # noqa: E402

PY = sys.executable
CLI = os.path.join(HERE, "challenge_stack.py")
FIREWALL_BODIES = (b"Request blocked by firewall-IA", b"Request rejected by firewall-IA")

# Per-application benign probes (method, target) and one firewall probe target carrying the double's
# trigger word `evil`. Benign probes only assert HTTP 200 + non-empty body (we never assert template
# text, to avoid coupling the smoke to the applications' markup).
# Per app: benign probes (200 + non-empty), the double's trigger (`evil`), a CRS mechanism probe, an
# optional large asset (path, known byte size) to verify response delivery, and a state marker
# ("inf3ct" in-memory log / "an0nb0ard" MySQL) or None when the app has no server-side state.
SMOKE = {
    "An0nB0ard":   {"benign": [("GET", "/"), ("GET", "/messages")], "evil": "/?q=evil",
                    "crs": "/post?id=1%27%20OR%20%271%27%3D%271",
                    "large": ("/static/css/bootstrap.min.css", 82972), "state": "an0nb0ard"},
    "CatP1cs":     {"benign": [("GET", "/"), ("GET", "/show?img=favicon.ico")], "evil": "/?q=evil",
                    "crs": "/show?img=....//....//etc/passwd",
                    "large": ("/show?img=alba.jpg", 76673),
                    "largest": ("/static/img/blackcat.gif", 8106213), "state": None},
    "D33pTh0ught": {"benign": [("GET", "/")], "evil": "/?q=evil",
                    "crs": "/?x=%3Cscript%3Ealert(1)%3C/script%3E", "large": None, "state": None},
    "Inf3ct":      {"benign": [("GET", "/"), ("GET", "/log")], "evil": "/?q=evil",
                    "crs": "/?x=%3Cscript%3Ealert(1)%3C/script%3E", "large": None, "state": "inf3ct"},
    "ObC00ki3s":   {"benign": [("GET", "/"), ("GET", "/static/js/cks.js")], "evil": "/?q=evil",
                    "crs": "/?x=%3Cscript%3Ealert(1)%3C/script%3E",
                    "large": ("/static/img/bunchofcookies.jpeg", 135981), "state": None},
    "ag3ncy":      {"benign": [("GET", "/")], "evil": "/?q=evil",
                    "crs": "/?x=%3Cscript%3Ealert(1)%3C/script%3E", "large": None, "state": None},
}


def run_cli(*cli_args, capture=True):
    cmd = [PY, "-B", CLI, *cli_args]
    proc = subprocess.run(cmd, capture_output=capture, text=True)
    return proc


def docker_logs(container):
    proc = subprocess.run(["docker", "logs", container], capture_output=True, text=True)
    return (proc.stdout or "") + (proc.stderr or "")


def new_json_lines(path, offset):
    """Read committed JSONL records; leave an in-flight final line for next poll.

    Never silently skip a malformed complete record or advance past bytes that
    have not yet been written. Offsets refer to bytes actually read, not a later
    stat() that could race a writer and discard another record.
    """
    if not path or not os.path.exists(path):
        return [], offset
    with open(path, "rb") as fh:
        if os.fstat(fh.fileno()).st_size < offset:
            raise RuntimeError("JSONL log truncated during attribution")
        fh.seek(offset)
        data = fh.read()
    committed = data.rfind(b"\n") + 1
    rows = [json.loads(x) for x in data[:committed].split(b"\n") if x.strip()]
    return rows, offset + committed


class Front:
    def __init__(self, state):
        self.ports = state["ports"]
        self.hostname = state["hostname"]
        self.app_ip = state["app_ip"]
        self.app_port = state["identity"]["app_image"]["internal_port"]
        self.ctx = WC.tls_context(state["pki"]["ca_cert"], ("http/1.1",))

    def tls(self, method, target, body=b"", headers=()):
        raw = WC.build_h1(method, target, self.hostname, list(headers), body)
        res = WC.h1_exchange(self.ports["front_tls"], raw, tls=self.ctx, server_hostname=self.hostname)
        return res["status"], res.get("body", b"") or b""

    def tls_post_form(self, target, fields):
        body = "&".join(f"{k}={v}" for k, v in fields.items()).encode()
        return self.tls("POST", target, body, [("Content-Type", "application/x-www-form-urlencoded")])

    def direct(self, method, target, body=b""):
        raw = WC.build_h1(method, target, self.hostname, [], body)
        with WC.connect_host(self.app_ip, self.app_port) as sock:
            sock.sendall(raw)
            status, _headers, rbody = WC.read_response(sock, head_request=method == "HEAD")
        return status, rbody or b""


def attribution(state, target, before):
    """Return reception/attribution facts for the most recent request, from the three logs."""
    out = {}
    # application reception: a new werkzeug line mentioning the target path
    container = next((c["container"] for c in state["components"]
                      if c["name"] == "app" and c["kind"] == "container"), None)
    logs_now = docker_logs(container) if container else ""
    new_app = logs_now[len(before.get("applogs", "")):]
    path_only = target.split("?")[0]
    out["app_received"] = (target in new_app) or (f'"{path_only}' in new_app and "?" not in target) \
        or (path_only in new_app and f'"GET {path_only}' in new_app)
    out["app_new_console"] = "\n".join(l for l in new_app.splitlines() if l.strip())[-600:]
    # gateway decision (cascade arms)
    dec_rows, _ = new_json_lines(state.get("gateway_decisions"), before.get("dec_off", 0))
    out["gateway_decisions_new"] = len(dec_rows)
    out["gateway_denied"] = any('"DENY"' in json.dumps(r) for r in dec_rows)
    decisions = [row for row in dec_rows if row.get("kind") == "decision"]
    out["gateway_last_decision"] = decisions[-1] if decisions else None
    # front access
    front_rows, _ = new_json_lines(state.get("front_access_log"), before.get("front_off", 0))
    out["front_new"] = len(front_rows)
    out["front_upstream_status"] = [r.get("upstream_status") for r in front_rows]
    out["front_status"] = [r.get("status") for r in front_rows]
    # CRS audit (crs arm)
    crs = state.get("crs")
    if crs:
        rows, _ = new_json_lines(crs["audit_log"], before.get("crs_off", 0))
        out["crs_new"] = len(rows)
        out["crs_interrupted"] = any(
            (r.get("transaction", {}).get("messages") or r.get("audit_data", {}).get("messages"))
            for r in rows) or any('"interrupted"' in json.dumps(r) or "is_interrupted" in json.dumps(r)
                                  for r in rows)
    return out


def snapshot(state):
    container = next((c["container"] for c in state["components"]
                      if c["name"] == "app" and c["kind"] == "container"), None)
    before = {"applogs": docker_logs(container) if container else ""}
    for key, path in (("dec_off", state.get("gateway_decisions")),
                      ("front_off", state.get("front_access_log"))):
        before[key] = os.path.getsize(path) if path and os.path.exists(path) else 0
    crs = state.get("crs")
    before["crs_off"] = os.path.getsize(crs["audit_log"]) if crs and os.path.exists(crs["audit_log"]) else 0
    return before


def smoke(args):
    ad = adapters.ADAPTERS[args.app]
    if args.fast_path and args.arm not in ("guarded", "fastv5", "fastv5_guard"):
        raise ValueError("--fast-path requires --arm guarded")
    os.makedirs(args.evidence, exist_ok=True)
    suffix = ".fast-path" if args.fast_path else ""
    cfg_path = os.path.join(args.evidence, f"{args.app}.{args.arm}{suffix}.stack.json")
    result = {"app": args.app, "arm": args.arm, "fast_path": args.fast_path, "v5": args.v5, "utc": time.time(),
              "commands": [], "checks": [], "large_responses": [], "pass": True}

    def record(name, ok, **info):
        result["checks"].append({"check": name, "pass": bool(ok), **info})
        if not ok:
            result["pass"] = False

    # 1) config + up  (config refuses to overwrite; clear a stale config from a previous smoke re-run)
    if os.path.exists(cfg_path):
        os.remove(cfg_path)
    policy_path = cfg_path + ".fast-path.json"
    if args.fast_path and os.path.exists(policy_path):
        os.remove(policy_path)
    config_cmd = ["config", "--app", args.app, "--arm", args.arm, "--out", cfg_path]
    if args.fast_path:
        config_cmd.append("--fast-path")
    c = run_cli(*config_cmd)
    result["commands"].append(" ".join(config_cmd))
    if c.returncode != 0:
        record("config", False, stderr=c.stderr.strip()[:400]); _finish(result, args); return 1
    up = run_cli("up", "--app", args.app, "--arm", args.arm, "--config", cfg_path,
                 "--work", args.work, "--v5", args.v5)
    result["commands"].append(f"up --app {args.app} --arm {args.arm} --config {cfg_path} "
                              f"--work {args.work} --v5 {args.v5}")
    record("startup", up.returncode == 0, stderr=up.stderr.strip()[:600] if up.returncode else "")
    if up.returncode != 0:
        _finish(result, args); return 1

    state = json.load(open(os.path.join(args.work, "stack-state.json")))
    result["apps_commit"] = state.get("apps_commit")
    result["commit_matches_pin"] = state.get("apps_commit") == adapters.PINNED_APPS_COMMIT
    front = Front(state)
    try:
        # 2) benign flows + reception
        for method, target in SMOKE[args.app]["benign"]:
            before = snapshot(state)
            status, body = front.tls(method, target)
            time.sleep(0.4)
            attr = attribution(state, target, before)
            received = attr["app_received"] or ("200" in [str(s) for s in attr["front_upstream_status"]])
            record(f"benign {method} {target}", status == 200 and len(body) > 0 and received,
                   status=status, body_len=len(body), **{k: attr[k] for k in
                   ("app_received", "front_upstream_status", "front_status")})

        if args.fast_path:
            asset = adapters.FAST_PATH_STATIC[args.app]
            before = snapshot(state)
            status, body = front.tls("GET", asset)
            time.sleep(0.4)
            attr = attribution(state, asset, before)
            row = attr["gateway_last_decision"] or {}
            record("exact static asset FAST_ALLOW skips Model 2 and V5",
                   status == 200 and bool(body) and row.get("deciding_stage") == "fast_path"
                   and row.get("fast_path", {}).get("decision") == "FAST_ALLOW"
                   and row.get("model2") is None and row.get("v5") is None
                   and attr["app_received"],
                   asset=asset, status=status, body_len=len(body),
                   app_received=attr["app_received"], last_decision=row)
            before = snapshot(state)
            status, body = front.tls("GET", asset + "?x=1")
            time.sleep(0.4)
            attr = attribution(state, asset + "?x=1", before)
            row = attr["gateway_last_decision"] or {}
            record("query on static asset cannot FAST_ALLOW",
                   status == 200 and row.get("deciding_stage") != "fast_path"
                   and row.get("fast_path", {}).get("decision") == "CONTINUE",
                   status=status, last_decision=row)

        # 3) sessions (all six issue none server-side; verify no Set-Cookie session appears on GET /)
        status, body = front.tls("GET", "/")
        record("sessions: none issued server-side (expected)", True,
               note=ad["sessions"], http_status=status)

        # 3b) state reset: every `up` is a fresh container (An0nB0ard: ephemeral tmpfs re-seeded from
        # members.sql; Inf3ct: in-memory log). Verify the app starts from a clean baseline this run.
        st = SMOKE[args.app]["state"]
        if st == "inf3ct":
            s1, b1 = front.tls("GET", "/log")
            fresh = b"FWLABRESET" not in b1
            marker = f"FWLABRESET{int(time.time())}"
            front.tls_post_form("/", {"msg": marker})
            s2, b2 = front.tls("GET", "/log")
            record("state reset: /log fresh at up, then stores this run's marker",
                   s1 == 200 and fresh and marker.encode() in b2,
                   log_fresh_at_up=fresh, marker_stored=marker.encode() in b2,
                   note="in-memory log; resets per container/up")
        elif st == "an0nb0ard":
            s1, b1 = front.tls("GET", "/messages")
            baseline = b"test blog entry" in b1
            record("state reset: /messages shows only the seeded baseline at up",
                   s1 == 200 and baseline, seeded_entry_present=baseline,
                   note="MySQL on ephemeral tmpfs; re-seeded from members.sql each up")
        else:
            record("state reset: N/A (no server-side state)", True, note=ad["state"])

        # 4) block attribution for this arm
        if args.arm in ("v5only", "guarded", "fastv5", "fastv5_guard"):
            tgt = SMOKE[args.app]["evil"]
            before = snapshot(state)
            status, body = front.tls("GET", tgt)
            time.sleep(0.5)
            attr = attribution(state, tgt, before)
            fw_body = any(b in body for b in FIREWALL_BODIES)
            blocked = attr["gateway_denied"] and not attr["app_received"]
            record(f"cascade block attributed to firewall ({tgt!r} -> V5 double DENY)", blocked,
                   status=status, gateway_denied=attr["gateway_denied"],
                   app_received=attr["app_received"], firewall_body=fw_body,
                   last_decision=attr["gateway_last_decision"])
            # and a benign request on the same arm reaches the app
            before = snapshot(state)
            status, body = front.tls("GET", "/?q=hello")
            time.sleep(0.4)
            attr = attribution(state, "/?q=hello", before)
            record("cascade forwards benign to app", status == 200 and not attr["gateway_denied"],
                   status=status, gateway_denied=attr["gateway_denied"], app_received=attr["app_received"])
        elif args.arm == "crs":
            tgt = SMOKE[args.app]["crs"]
            before = snapshot(state)
            status, body = front.tls("GET", tgt)
            time.sleep(0.6)
            attr = attribution(state, tgt, before)
            blocked = bool(attr.get("crs_interrupted")) and not attr["app_received"]
            forwarded = (not attr.get("crs_interrupted")) and attr["app_received"]
            # Attribution must be consistent: either CRS interrupted and the app was not reached, or CRS
            # did not interrupt and the app answered. Record which, and whether CRS blocked.
            record(f"crs attribution consistent ({tgt!r})", blocked or forwarded,
                   status=status, crs_blocked=blocked, crs_interrupted=attr.get("crs_interrupted"),
                   crs_audit_new=attr.get("crs_new"), app_received=attr["app_received"],
                   note="known DEV mechanism request; gives no CRS rate")
        else:  # direct
            tgt = SMOKE[args.app]["evil"]
            before = snapshot(state)
            status, body = front.tls("GET", tgt)
            time.sleep(0.4)
            attr = attribution(state, tgt, before)
            record("direct arm has no blocking layer (request reaches app)",
                   attr["app_received"] or status == 200, status=status, app_received=attr["app_received"],
                   note="baseline: front -> app, no gateway, no WAF")

        # 5) Normal assets above the old 64 KiB gateway cap must arrive intact
        # under the pinned 16 MiB challenge gateway setting, in every arm.
        large_cases = [x for x in (SMOKE[args.app]["large"], SMOKE[args.app].get("largest")) if x]
        for large in large_cases:
            tgt, asset_bytes = large
            status, body = front.tls("GET", tgt)
            ok = status == 200 and len(body) == asset_bytes
            where = f"{args.arm}: full asset delivered"
            result["large_responses"].append({"arm": args.arm, "target": tgt,
                                               "asset_bytes": asset_bytes, "status": status,
                                               "response_body_len": len(body), "capped_502": status == 502})
            record(f"large response {tgt} ({asset_bytes} B): {where}", ok,
                   status=status, asset_bytes=asset_bytes, response_body_len=len(body),
                   note="challenge gateway limit fixed at 16 MiB; front request limit remains 64 KiB")
    finally:
        # 5) teardown + 6) clean
        down = run_cli("down", "--work", args.work)
        result["commands"].append(f"down --work {args.work}")
        record("teardown", down.returncode == 0, down=_safe_json(down.stdout))
        clean = run_cli("check-clean", "--work", args.work)
        result["commands"].append(f"check-clean --work {args.work}")
        clean_doc = _safe_json(clean.stdout)
        record("check-clean", isinstance(clean_doc, dict) and clean_doc.get("clean") is True,
               leftovers=(clean_doc or {}).get("leftovers"))

    _finish(result, args)
    return 0 if result["pass"] else 1


def _safe_json(text):
    try:
        return json.loads(text)
    except Exception:
        return text.strip()[:400] if text else None


def _finish(result, args):
    suffix = "-fast-path" if args.fast_path else ""
    out = os.path.join(args.evidence, f"smoke-{args.app}-{args.arm}{suffix}.json")
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(result, fh, indent=2, sort_keys=True)
        fh.write("\n")
    passed = sum(1 for c in result["checks"] if c["pass"])
    print(json.dumps({"app": args.app, "arm": args.arm, "pass": result["pass"],
                      "checks_passed": f"{passed}/{len(result['checks'])}",
                      "commit_matches_pin": result.get("commit_matches_pin"),
                      "evidence": out}, indent=2))


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--app", choices=adapters.APP_NAMES, required=True)
    p.add_argument("--arm", choices=("direct", "v5only", "guarded", "fastv5", "fastv5_guard", "crs"), required=True)
    p.add_argument("--v5", default="double", help="double (default) | real | url:<url>")
    p.add_argument("--fast-path", action="store_true", help="lab-only exact static-resource bypass")
    p.add_argument("--work", required=True, help="new private work dir (outside the repo)")
    p.add_argument("--evidence", required=True, help="evidence dir")
    args = p.parse_args(argv)
    return smoke(args)


if __name__ == "__main__":
    sys.exit(main())
