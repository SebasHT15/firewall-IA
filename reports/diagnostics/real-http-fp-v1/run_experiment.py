"""Runner for the real-http-fp-v1 DIAGNOSTIC experiment (not a benchmark, not an FPR).

Run from the repository root, in its own visible terminal, with its output tee'd to
client.log (see summary.md for the four commands). Standard library only.

Flow
  preflight  wait until classifier (/health model_loaded), proxy :8080 and destination
             :9000 accept connections; write manifest.json; then wait for the GO file
  warm-up    3 direct calls, excluded from every statistic
  direct     every unique text of cases.jsonl x REPS -> POST /classify
  proxy      every unique curl spec of the pre-registered proxy subset x REPS through
             mitmdump (1 excluded warm-up request first); per request: client HTTP
             code, destination arrival (server.log), proxy and classifier log lines
  capture    the exact bodies mitmdump sent to /classify, parsed from proxy_strace.log
  resend     each captured text POSTed again directly to /classify, once per proxy call
  summary    summary.json (numbers only; interpretation is written separately)

Nothing is added to the HTTP requests under test: case ids live only in these files.
"""
import datetime
import glob
import hashlib
import json
import os
import platform
import re
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
EXPERIMENT_ID = "real-http-fp-v1"

CLASSIFIER = "http://127.0.0.1:8000"
CLASSIFY_URL = CLASSIFIER + "/classify"
PROXY_URL = "http://127.0.0.1:8080"
DEST_URL = "http://127.0.0.1:9000"
REPS = 3
N_WARMUP = 3
GO_FILE = os.path.join(HERE, "GO")

LOGS = {k: os.path.join(HERE, f"{k}.log") for k in ("classifier", "proxy", "server", "client")}
STRACE = os.path.join(HERE, "proxy_strace.log")
CASES = os.path.join(HERE, "cases.jsonl")
RESULTS = os.path.join(HERE, "results.jsonl")
MANIFEST = os.path.join(HERE, "manifest.json")
SUMMARY = os.path.join(HERE, "summary.json")

COMMANDS = {
    "classifier": ("PYTHONUNBUFFERED=1 python3.12 -m uvicorn classifier_api:app --host 127.0.0.1 "
                   "--port 8000 2>&1 | tee -a reports/diagnostics/real-http-fp-v1/classifier.log"),
    "proxy": ("PYTHONUNBUFFERED=1 strace -f -tt -xx -s 1048576 "
              "-e trace=connect,sendto,sendmsg,write,writev,close "
              "-o reports/diagnostics/real-http-fp-v1/proxy_strace.log .venv-dataplane/bin/mitmdump "
              "-s data_plane.py --listen-host 127.0.0.1 -p 8080 2>&1 | tee -a "
              "reports/diagnostics/real-http-fp-v1/proxy.log"),
    "server": ("PYTHONUNBUFFERED=1 python3.12 -m http.server 9000 --bind 127.0.0.1 --directory "
               "reports/diagnostics/real-http-fp-v1/www 2>&1 | tee -a "
               "reports/diagnostics/real-http-fp-v1/server.log"),
    "client": ("PYTHONUNBUFFERED=1 python3.12 reports/diagnostics/real-http-fp-v1/run_experiment.py "
               "2>&1 | tee -a reports/diagnostics/real-http-fp-v1/client.log"),
}

# urllib honours http_proxy & co. by default; the direct path must never go through a proxy.
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds")


def say(msg):
    print(f"{datetime.datetime.now().strftime('%H:%M:%S.%f')[:-3]}  {msg}", flush=True)


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def file_sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def sh(cmd):
    try:
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30,
                              cwd=REPO).stdout.strip()
    except Exception as e:                      # recorded, never fatal
        return f"unavailable: {e}"


def size(path):
    return os.path.getsize(path) if os.path.exists(path) else 0


def read_from(path, offset):
    if not os.path.exists(path):
        return ""
    with open(path, "rb") as f:
        f.seek(offset)
        return f.read().decode("utf-8", errors="replace")


def port_open(port):
    with socket.socket() as s:
        s.settimeout(1)
        return s.connect_ex(("127.0.0.1", port)) == 0


def get_json(url):
    with OPENER.open(url, timeout=5) as r:
        return json.loads(r.read())


def classify(text):
    """POST one text to /classify directly. Returns (record, wall_ms)."""
    body = json.dumps({"request": text}).encode()
    req = urllib.request.Request(CLASSIFY_URL, data=body,
                                 headers={"Content-Type": "application/json"})
    t0 = time.perf_counter()
    try:
        with OPENER.open(req, timeout=60) as r:
            code, payload = r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        code, payload = e.code, {}
    wall = (time.perf_counter() - t0) * 1000
    return {"classify_http_status": code, "status": payload.get("status"),
            "decision": payload.get("decision"), "reason": payload.get("reason"),
            "model_latency_ms": payload.get("model_latency_ms")}, wall


def wait_for_log(path, offset, pattern, timeout=3.0):
    """New text in `path` since `offset`, waiting briefly until `pattern` appears."""
    deadline = time.time() + timeout
    while True:
        new = read_from(path, offset)
        if re.search(pattern, new) or time.time() > deadline:
            return new
        time.sleep(0.05)


CLS_LINE = re.compile(r"classify: status=(\w+)(?: decision=(\w+) reason=(['\"])(.*?)\3)? "
                      r"model_latency_ms=([\d.]+)")
CLS_RECEIVED = re.compile(r"classify: received request \((\d+) bytes\)")
PROXY_LINE = re.compile(r"\] (ALLOW|BLOCK)(?: \(fail-closed\))? .*?(?:reason=(['\"])(.*?)\2 "
                        r"\(classifier (\d+) ms\)|cause=(.*))")


def parse_classifier_lines(text):
    out = []
    for m in CLS_LINE.finditer(text):
        out.append({"status": m.group(1), "decision": m.group(2), "reason": m.group(4),
                    "model_latency_ms": float(m.group(5))})
    return out


def parse_proxy_lines(text):
    out = []
    for line in text.splitlines():
        m = PROXY_LINE.search(line)
        if m:
            out.append({"decision": m.group(1), "reason": m.group(3),
                        "proxy_to_classifier_ms": int(m.group(4)) if m.group(4) else None,
                        "fail_closed_cause": m.group(5), "line": line.strip()})
    return out


def curl_argv(spec):
    argv = ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "30",
            "-x", PROXY_URL, "-H", f"Host: {spec['host_header']}"]
    if spec.get("user_agent"):
        argv += ["-A", spec["user_agent"]]
    for name in spec.get("remove", []):
        argv += ["-H", f"{name}:"]
    for name, value in spec.get("add", []):
        argv += ["-H", f"{name}: {value}"]
    argv.append(DEST_URL + spec["path"])
    return argv


# ── strace capture of mitmdump -> /classify ────────────────────────────────
# Lines look like `[PID ]HH:MM:SS.micro syscall(args...`; with -xx every string argument
# is printed as \xNN escapes, so the bytes can be recovered exactly.
_PFX = r"^(?:\d+\s+)?(\S+)\s+"
ST_CONNECT = re.compile(_PFX + r"connect\((\d+), \{sa_family=AF_INET6?, sin6?_port=htons\((\d+)\)")
ST_SEND = re.compile(_PFX + r"(?:sendto|write)\((\d+), \"((?:\\x[0-9a-f]{2})*)\"")
ST_VEC = re.compile(_PFX + r"(?:sendmsg|writev)\((\d+), ")
ST_IOV = re.compile(r"iov_base=\"((?:\\x[0-9a-f]{2})*)\"")
ST_CLOSE = re.compile(_PFX + r"close\((\d+)")


def _hex(s):
    return bytes.fromhex(s.replace("\\x", ""))


def parse_strace(path, port=8000):
    """Bytes mitmdump wrote on connections to `port` -> list of POST bodies, in order."""
    conn_bytes = {}          # conn number -> bytearray
    conn_start = {}          # conn number -> timestamp of connect()
    live = {}                # fd -> conn number (only for connections to `port`)
    n = 0
    with open(path, errors="replace") as f:
        for line in f:
            m = ST_CONNECT.match(line)
            if m:
                fd, p = int(m.group(2)), int(m.group(3))
                if p == port:
                    n += 1
                    live[fd] = n
                    conn_bytes[n] = bytearray()
                    conn_start[n] = m.group(1)
                else:
                    live.pop(fd, None)
                continue
            m = ST_CLOSE.match(line)
            if m:
                live.pop(int(m.group(2)), None)
                continue
            m = ST_SEND.match(line)
            if m and int(m.group(2)) in live:
                conn_bytes[live[int(m.group(2))]] += _hex(m.group(3))
                continue
            m = ST_VEC.match(line)
            if m and int(m.group(2)) in live:
                for chunk in ST_IOV.findall(line):
                    conn_bytes[live[int(m.group(2))]] += _hex(chunk)
    bodies = []
    for c in sorted(conn_bytes):
        data = bytes(conn_bytes[c])
        while data:
            head, sep, rest = data.partition(b"\r\n\r\n")
            if not sep:
                break
            m = re.search(rb"(?i)content-length:\s*(\d+)", head)
            length = int(m.group(1)) if m else 0
            body, data = rest[:length], rest[length:]
            if head.startswith(b"POST ") and b"/classify" in head.split(b"\r\n", 1)[0]:
                bodies.append({"conn": c, "t": conn_start[c], "body": body})
    return bodies


# ── manifest ───────────────────────────────────────────────────────────────
def write_manifest(extra=None):
    cases = [json.loads(l) for l in open(CASES)]
    proxy_specs = {json.dumps(c["proxy"], sort_keys=True) for c in cases if c["proxy"]}
    ds_manifest = json.load(open(os.path.join(REPO, "datasets", "manifest_v4_clean.json")))
    adapter_dir = os.path.join(REPO, "model-output-v4-clean")
    try:
        health = get_json(CLASSIFIER + "/health")
    except Exception as e:
        health = {"unavailable": str(e)}

    def ver(pkg):
        return sh(f"python3.12 -c \"import importlib.metadata as m; print(m.version('{pkg}'))\"")

    m = {
        "experiment_id": EXPERIMENT_ID,
        "experiment_type": "diagnostic",
        "interpretation_rule": ("Composition is chosen by the experimenter to find and explain "
                                "failures. Proportions of BLOCK among these benign texts are NOT "
                                "a representative false-positive rate and must not be reported "
                                "as the model's FPR or extrapolated to real traffic."),
        "not": ["external test", "representative benchmark", "FPR estimate",
                "training data", "latency benchmark"],
        "reproduces": ("design of the 2026-09-17 diagnostic, whose raw data were lost; only its "
                       "audit summary survived"),
        "created_utc": now(),
        "code": {"git_branch": sh("git rev-parse --abbrev-ref HEAD"),
                 "git_commit": sh("git rev-parse HEAD"),
                 "working_tree_dirty_files": sh("git status --short").splitlines()},
        "model": {"base_model": "TinyLlama/TinyLlama-1.1B-Chat-v1.0",
                  "adapter_dir": "model-output-v4-clean",
                  "adapter_model_sha256": file_sha(os.path.join(adapter_dir,
                                                                "adapter_model.safetensors")),
                  "adapter_config_sha256": file_sha(os.path.join(adapter_dir,
                                                                 "adapter_config.json")),
                  "classifier_health": health},
        "dataset": {"name": "V4 clean", "manifest": "datasets/manifest_v4_clean.json",
                    "manifest_artifact_sha256": ds_manifest.get("artifact_sha256"),
                    "eval_sha256_live": file_sha(os.path.join(REPO, "datasets", "v4_clean",
                                                              "eval.jsonl")),
                    "used_for": "10 ALLOW rows as in-distribution contexts (family EVALSWAP)"},
        "hardware": {"cpu": sh("grep -m1 'model name' /proc/cpuinfo | cut -d: -f2"),
                     "gpu": sh("nvidia-smi --query-gpu=name,driver_version,memory.total "
                               "--format=csv,noheader"),
                     "os": platform.platform()},
        "runtime": {"python_ml": sh("python3.12 --version"),
                    "torch": ver("torch"), "transformers": ver("transformers"),
                    "peft": ver("peft"), "bitsandbytes": ver("bitsandbytes"),
                    "fastapi": ver("fastapi"), "uvicorn": ver("uvicorn"),
                    "mitmproxy": sh(".venv-dataplane/bin/mitmdump --version").splitlines()[:1],
                    "curl": sh("curl --version").splitlines()[:1],
                    "strace": sh("strace -V").splitlines()[:1]},
        "design": {"cases": len(cases),
                   "unique_texts": len({c["text_sha256"] for c in cases}),
                   "families": dict(Counter(c["family"] for c in cases)),
                   "proxy_cases": sum(1 for c in cases if c["proxy"]),
                   "proxy_unique_curl_commands": len(proxy_specs),
                   "repetitions_per_unique_text": REPS,
                   "direct_warmup_calls_excluded": N_WARMUP,
                   "proxy_warmup_requests_excluded": 1,
                   "expected_label_all": "ALLOW (benign by construction; the model's output "
                                         "is never used to label)",
                   "seed": 42, "seed_scope": "selection of the 10 eval rows only",
                   "concurrency": 1, "request_order": "rep-major, case-file order",
                   "cases_file_sha256": file_sha(CASES)},
        "endpoints": {"classifier_url": CLASSIFY_URL, "proxy_url": PROXY_URL,
                      "destination": DEST_URL + " (python http.server, docroot www/)",
                      "ports": {"classifier": 8000, "proxy": 8080, "destination": 9000}},
        "capture": ("exact proxy->classifier bodies recorded by strace around the unchanged "
                    "mitmdump command (proxy_strace.log); no code or config was changed"),
        "commands": COMMANDS,
        "scope": ["benign GET requests (+ eval rows with their original method and body)",
                  "Host/loopback, path, port, header presence, User-Agent value, "
                  "UA x Proxy-Connection, in-distribution Host swap",
                  "direct /classify vs proxy path, and proxy enforcement (403 / arrival)"],
        "limitations": [
            "diagnostic composition: BLOCK proportions are not an FPR",
            "one client (curl 8.18.0) through the proxy; plain HTTP/1.1; GET only via proxy",
            "benign texts are constructed by hand from real client header sets, not captured "
            "from users",
            "latency figures are observations under strace and are not a benchmark (D36 is "
            "not evaluated here)",
            "single machine, single model version (V4); greedy decoding",
        ],
        "logs": {k: os.path.relpath(v, REPO) for k, v in LOGS.items()},
    }
    if os.path.exists(MANIFEST):
        m = {**json.load(open(MANIFEST)), **m}
    if extra:
        m.update(extra)
    json.dump(m, open(MANIFEST, "w"), indent=2, ensure_ascii=False)
    return m


def append(record):
    with open(RESULTS, "a") as f:
        f.write(json.dumps(record, ensure_ascii=False) + "\n")


# ── phases ─────────────────────────────────────────────────────────────────
def preflight():
    say("PREFLIGHT — waiting for classifier (model loaded), proxy :8080, destination :9000")
    while True:
        try:
            ok_cls = get_json(CLASSIFIER + "/health").get("model_loaded") is True
        except Exception:
            ok_cls = False
        ok_proxy, ok_dest = port_open(8080), port_open(9000)
        if ok_cls and ok_proxy and ok_dest:
            break
        say(f"  classifier={'ok' if ok_cls else '...'}  proxy={'ok' if ok_proxy else '...'}  "
            f"destination={'ok' if ok_dest else '...'}")
        time.sleep(5)
    if not os.path.exists(STRACE):
        sys.exit("FATAL: proxy_strace.log missing — start the proxy with the strace command")
    say("  classifier ok (model loaded) · proxy ok · destination ok · strace log present")
    write_manifest()
    say(f"  manifest.json written. READY. Waiting for GO: touch {os.path.relpath(GO_FILE, REPO)}")
    while not os.path.exists(GO_FILE):
        time.sleep(1)
    os.remove(GO_FILE)
    offsets = {k: size(v) for k, v in LOGS.items()}
    offsets["strace"] = size(STRACE)
    write_manifest({"go_utc": now(), "log_offsets_at_go": offsets})
    say("GO received")


def phase_direct(cases):
    texts, owners = [], defaultdict(list)
    for c in cases:
        if c["text_sha256"] not in owners:
            texts.append((c["text_sha256"], c["text"]))
        owners[c["text_sha256"]].append(c["case_id"])
    base = next(c for c in cases if c["case_id"] == "HOST-001")
    say(f"WARM-UP — {N_WARMUP} direct calls (excluded from all statistics)")
    for i in range(N_WARMUP):
        rec, wall = classify(base["text"])
        append({"phase": "warmup-direct", "ts_utc": now(), "rep": i + 1,
                "text_sha256": base["text_sha256"], "wall_ms": round(wall, 1), **rec})
        say(f"  warm-up {i+1}: {rec['decision']} {rec['model_latency_ms']} ms")
    say(f"DIRECT /classify — {len(texts)} unique texts x {REPS} = {len(texts)*REPS} calls")
    call = 0
    for rep in range(1, REPS + 1):
        for h, text in texts:
            call += 1
            rec, wall = classify(text)
            append({"phase": "direct", "call": call, "ts_utc": now(), "rep": rep,
                    "text_sha256": h, "case_ids": owners[h], "expected_label": "ALLOW",
                    "valid": rec["status"] == "ok", "wall_ms": round(wall, 1), **rec})
            ids = ",".join(owners[h][:2]) + ("…" if len(owners[h]) > 2 else "")
            mark = "FP " if rec["decision"] == "BLOCK" else ("INV" if rec["status"] != "ok" else "   ")
            say(f"  {mark} rep{rep} #{call:03d} {ids:<22} exp ALLOW  pred {rec['decision'] or '-':5}"
                f"  {rec['reason'] or ''}  [{rec['model_latency_ms']} ms]")


def phase_proxy(cases):
    specs, owners = [], defaultdict(list)
    for c in cases:
        if c["proxy"]:
            k = json.dumps(c["proxy"], sort_keys=True)
            if k not in owners:
                specs.append((k, c["proxy"]))
            owners[k].append(c["case_id"])
    base_spec = next(c["proxy"] for c in cases if c["case_id"] == "HOST-001")
    plan = [("warmup-proxy", 0, json.dumps(base_spec, sort_keys=True), base_spec)]
    plan += [("proxy", rep, k, s) for rep in range(1, REPS + 1) for k, s in specs]
    say(f"PROXY — 1 warm-up + {len(specs)} curl commands x {REPS} = {len(specs)*REPS} requests")
    call = 0
    for phase, rep, key, spec in plan:
        off = {k: size(v) for k, v in LOGS.items() if k != "client"}
        argv = curl_argv(spec)
        t0 = time.perf_counter()
        out = subprocess.run(argv, capture_output=True, text=True, cwd=REPO)
        wall = (time.perf_counter() - t0) * 1000
        code = out.stdout.strip()
        cls_new = wait_for_log(LOGS["classifier"], off["classifier"], r"classify: status=")
        prx_new = wait_for_log(LOGS["proxy"], off["proxy"], r"\] (ALLOW|BLOCK)")
        srv_new = wait_for_log(LOGS["server"], off["server"], r"\"GET ", timeout=0.6)
        cls, prx = parse_classifier_lines(cls_new), parse_proxy_lines(prx_new)
        arrived = [l for l in srv_new.splitlines() if '"GET ' in l or '"POST ' in l]
        if phase == "proxy":
            call += 1
        rec = {"phase": phase, "call": call if phase == "proxy" else 0, "ts_utc": now(),
               "rep": rep, "case_ids": owners.get(key, ["HOST-001"]), "curl_spec": spec,
               "curl_argv": argv, "expected_label": "ALLOW", "client_http_code": code,
               "destination_received": bool(arrived), "destination_log_lines": arrived,
               "proxy_log": prx, "classifier_log": cls,
               "classifier_received_len": [int(x) for x in CLS_RECEIVED.findall(cls_new)],
               "wall_ms": round(wall, 1)}
        append(rec)
        dec = prx[0]["decision"] if prx else "?"
        mark = "FP " if dec == "BLOCK" else "   "
        say(f"  {mark}{phase} rep{rep} {','.join(rec['case_ids'][:2]):<22} Host={spec['host_header']:<20}"
            f" {spec['path']:<30} -> proxy {dec:5} HTTP {code}  destination "
            f"{'RECEIVED' if arrived else 'not reached'}")


def phase_capture_and_resend():
    proxy_recs = [json.loads(l) for l in open(RESULTS)
                  if json.loads(l)["phase"] in ("warmup-proxy", "proxy")]
    for attempt in range(10):
        bodies = parse_strace(STRACE)
        if len(bodies) >= len(proxy_recs):
            break
        time.sleep(1)
    # the last N bodies are this experiment's; anything earlier was sent before GO
    bodies = bodies[-len(proxy_recs):] if len(bodies) >= len(proxy_recs) else bodies
    say(f"CAPTURE — {len(bodies)} /classify bodies parsed from proxy_strace.log for "
        f"{len(proxy_recs)} proxy requests")
    if len(bodies) != len(proxy_recs):
        say("  WARNING: count mismatch — capture/resend skipped; raw strace log kept")
        return
    cases = {c["case_id"]: c for c in (json.loads(l) for l in open(CASES))}
    say(f"RESEND — each captured text POSTed directly to /classify ({len(bodies)-1} calls)")
    for rec, cap in zip(proxy_recs, bodies):
        text = json.loads(cap["body"])["request"]
        constructed = cases[rec["case_ids"][0]]["text"]
        cap_rec = {"phase": "capture", "proxy_phase": rec["phase"], "proxy_call": rec["call"],
                   "rep": rec["rep"], "case_ids": rec["case_ids"], "ts_utc": now(),
                   "captured_text": text, "captured_text_sha256": sha(text),
                   # mapping check: the classifier logged len(request) for this very call
                   "length_matches_classifier_log": rec.get("classifier_received_len") == [len(text)],
                   "equals_constructed_text": text == constructed,
                   "constructed_text_sha256": sha(constructed), "strace_conn": cap["conn"],
                   "strace_time": cap["t"]}
        append(cap_rec)
        if rec["phase"] != "proxy":
            continue
        res, wall = classify(text)
        prx = rec["proxy_log"][0] if rec["proxy_log"] else {}
        clsl = rec["classifier_log"][0] if rec["classifier_log"] else {}
        append({"phase": "resend", "proxy_call": rec["call"], "rep": rec["rep"],
                "case_ids": rec["case_ids"], "ts_utc": now(),
                "text_sha256": sha(text), "expected_label": "ALLOW",
                "valid": res["status"] == "ok", "wall_ms": round(wall, 1), **res,
                "proxy_path_decision": clsl.get("decision") or prx.get("decision"),
                "proxy_path_reason": clsl.get("reason") or prx.get("reason"),
                "decision_agrees": res["decision"] == (clsl.get("decision") or prx.get("decision")),
                "reason_agrees": res["reason"] == (clsl.get("reason") or prx.get("reason"))})
        say(f"  resend call {rec['call']:02d} {rec['case_ids'][0]:<10} proxy "
            f"{clsl.get('decision') or prx.get('decision')} / direct {res['decision']}  "
            f"{'same' if res['decision'] == (clsl.get('decision') or prx.get('decision')) else 'DIFFERENT'}"
            f"  captured==constructed: {text == constructed}")


def summarize():
    recs = [json.loads(l) for l in open(RESULTS)]
    cases = [json.loads(l) for l in open(CASES)]
    by_case = {c["case_id"]: c for c in cases}
    direct = [r for r in recs if r["phase"] == "direct"]
    per_text = defaultdict(list)
    for r in direct:
        per_text[r["text_sha256"]].append(r)
    text_outcome = {}
    for h, rs in per_text.items():
        outcomes = {(r["status"], r["decision"], r["reason"]) for r in rs}
        text_outcome[h] = {"n": len(rs), "deterministic": len(outcomes) == 1,
                           "decision": rs[0]["decision"] if len(outcomes) == 1 else "MIXED",
                           "reason": rs[0]["reason"] if len(outcomes) == 1 else None}
    fams = defaultdict(lambda: Counter())
    for c in cases:
        o = text_outcome.get(c["text_sha256"], {})
        fams[c["family"]][o.get("decision")] += 1
    pairs = []
    for c in cases:
        if c["pair_with"]:
            a = text_outcome.get(by_case[c["pair_with"]]["text_sha256"], {}).get("decision")
            b = text_outcome.get(c["text_sha256"], {}).get("decision")
            pairs.append({"case_id": c["case_id"], "pair_with": c["pair_with"],
                          "family": c["family"], "group": c["group"], "value": c["value"],
                          "transition": f"{a}->{b}",
                          "reason_b": text_outcome.get(c["text_sha256"], {}).get("reason")})
    trans = defaultdict(Counter)
    for p in pairs:
        trans[p["family"]][p["transition"]] += 1
    proxy = [r for r in recs if r["phase"] == "proxy"]
    resend = [r for r in recs if r["phase"] == "resend"]
    capture = [r for r in recs if r["phase"] == "capture" and r["proxy_phase"] == "proxy"]
    enforce = Counter()
    for r in proxy:
        dec = (r["proxy_log"][0]["decision"] if r["proxy_log"] else None)
        enforce[f"{dec} / HTTP {r['client_http_code']} / "
                f"{'received' if r['destination_received'] else 'not received'}"] += 1
    lat = sorted(r["model_latency_ms"] for r in direct if r.get("model_latency_ms") is not None)

    def pct(v, q):
        import math
        return v[max(1, math.ceil(q * len(v))) - 1] if v else None

    unique_decisions = Counter(o["decision"] for o in text_outcome.values())
    s = {
        "experiment_type": "diagnostic — proportions are NOT an FPR",
        "calls": dict(Counter(r["phase"] for r in recs)),
        "direct": {"calls": len(direct), "unique_texts": len(per_text),
                   "decisions_per_call": dict(Counter(r["decision"] for r in direct)),
                   "invalid_calls": sum(1 for r in direct if r["status"] != "ok"),
                   "deterministic_texts": sum(o["deterministic"] for o in text_outcome.values()),
                   "decision_per_unique_text": dict(unique_decisions),
                   "statement": (f"{unique_decisions.get('BLOCK', 0)} false positives among "
                                 f"{len(per_text)} constructed benign unique texts")},
        "by_family_cases": {f: dict(c) for f, c in fams.items()},
        "pair_transitions_by_family": {f: dict(c) for f, c in trans.items()},
        "pairs": pairs,
        "api_vs_proxy": {"pairs": len(resend),
                         "decision_agree": sum(r["decision_agrees"] for r in resend),
                         "reason_agree": sum(r["reason_agrees"] for r in resend),
                         "capture_mapping_verified_by_length": sum(
                             r["length_matches_classifier_log"] for r in capture),
                         "captured_equals_constructed": sum(r["equals_constructed_text"]
                                                            for r in capture),
                         "captured_total": len(capture)},
        "proxy_enforcement": dict(enforce),
        "latency_observation_not_benchmark": {
            "direct_model_latency_ms": {"n": len(lat), "min": lat[0] if lat else None,
                                        "p50": pct(lat, .5), "p95": pct(lat, .95),
                                        "max": lat[-1] if lat else None},
            "note": "generate() only, repeated texts, warm-up excluded; not a D36 measurement"},
        "per_text": text_outcome,
    }
    json.dump(s, open(SUMMARY, "w"), indent=2, ensure_ascii=False)
    write_manifest({"finished_utc": now(), "result_counts": s["calls"]})
    say("SUMMARY (diagnostic, not an FPR)")
    say(f"  {s['direct']['statement']}; deterministic texts "
        f"{s['direct']['deterministic_texts']}/{len(per_text)}; invalid calls "
        f"{s['direct']['invalid_calls']}")
    for f, c in s["pair_transitions_by_family"].items():
        say(f"  pairs {f:<9} {dict(c)}")
    a = s["api_vs_proxy"]
    say(f"  API vs proxy: decision {a['decision_agree']}/{a['pairs']}, reason "
        f"{a['reason_agree']}/{a['pairs']}; captured==constructed "
        f"{a['captured_equals_constructed']}/{a['captured_total']}")
    for k, v in s["proxy_enforcement"].items():
        say(f"  enforcement {k}: {v}")
    say("DONE — summary.json written")


def main():
    if not os.path.exists(CASES):
        sys.exit("FATAL: cases.jsonl missing — run build_cases.py first")
    if os.path.exists(RESULTS) and size(RESULTS) > 0:
        sys.exit("FATAL: results.jsonl already has data; this experiment id is not overwritten")
    cases = [json.loads(l) for l in open(CASES)]
    say(f"{EXPERIMENT_ID} — DIAGNOSTIC — {len(cases)} cases, "
        f"{len({c['text_sha256'] for c in cases})} unique texts, expected label ALLOW for all")
    preflight()
    phase_direct(cases)
    phase_proxy(cases)
    phase_capture_and_resend()
    summarize()


if __name__ == "__main__":
    main()
