"""
Local Firewall-IA stack: start, stop, status and cleanliness check. LAB ONLY, not a deployment.

    client ──TLS h1/h2──> front (nginx, Docker, host loopback) ──HTTP/1.1──> gateway (mitmdump + cascade)
                                                                             ├─ canonical workers, Model 2 (CPU)
                                                                             ├─ V5: double | real service | URL
                                                                             └─ egress guard ──> fwlab-notes app
                                                                                (Docker, internal network, no route out)

    .venv-dataplane/bin/python scripts/local_stack/stack.py up --config scripts/local_stack/stack.example.json --work <private dir>
    .venv-dataplane/bin/python scripts/local_stack/stack.py status --work <private dir>
    .venv-dataplane/bin/python scripts/local_stack/stack.py down --work <private dir>
    .venv-dataplane/bin/python scripts/local_stack/stack.py check-clean --work <private dir>
    .venv-dataplane/bin/python scripts/local_stack/stack.py pin --config <base.json> --manifest <candidate.json> --mode V5_ONLY --out <new.json>

Defaults: mode V5_ONLY, V5 DOUBLE (no model, no GPU), Fast Path disabled, V4 never started. A real V5
needs `--v5 real` and the GPU hand-off in GPU_STATUS.json. CASCADE_ACTIVE needs a manifest with Model 2.
V4_ONLY and CASCADE_OBSERVE are refused: they belong to scripts/gateway_ops/launch.py.

Everything the stack starts is recorded in `<work>/stack-state.json` as it starts: process id, process
group, kernel start time and command line; container and network names with a run label. `down` stops
only what that file names and still matches (a reused pid is never signalled), so a failed `up` is
cleaned the same way. Nothing else on the machine is stopped.

`<work>` must be outside the repository: it holds the run seed, the lab private key and logs that can
carry request paths.
"""
import argparse
import hashlib
import ipaddress
import json
import os
import re
import secrets
import signal
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
OPS = os.path.join(REPO, "scripts", "gateway_ops")
sys.path[:0] = [HERE, OPS, os.path.join(REPO, "data_plane")]

import gpu_gate                   # noqa: E402
import live_stack as L            # noqa: E402
import fast_path as FP            # noqa: E402

STATE_SCHEMA = "firewall-local-stack-state/v1"
CONFIG_SCHEMA = "firewall-local-stack/v1"
STATE_FILE = "stack-state.json"
APP_SOURCE = os.path.join(HERE, "notes_app", "app.py")
NGINX_TEMPLATE = os.path.join(HERE, "front", "nginx.conf.template")
PYTHON = L.PYTHON
ALLOWED_MODES = ("V5_ONLY", "CASCADE_ACTIVE", "FAST_PATH_V5")
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
CONFIG_KEYS = {"schema", "mode", "manifest", "ports", "front", "app", "gateway", "fast_path"}
OPTIONAL_KEYS = {"crs", "request_guard"}
CRS_KEYS = {"image", "image_id", "port", "blocking_paranoia", "anomaly_inbound", "anomaly_outbound"}
CRS_DIR = os.path.join(HERE, "crs")
PORT_KEYS = ("front_tls", "front_status", "gateway", "guard", "admin", "v5")
FAST_PATH_KEYS = {"policy_file", "policy_sha256", "application_contract_ref", "audit_sample_rate"}


class StackError(RuntimeError):
    pass


# ─────────────────────────────── small helpers ───────────────────────────────
def sha256_file(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def rel(path):
    return os.path.relpath(path, REPO) if os.path.abspath(path).startswith(REPO + os.sep) else path


def resolve(path):
    return path if os.path.isabs(path) else os.path.join(REPO, path)


def docker(*args, check=True):
    proc = subprocess.run(["docker", *map(str, args)], capture_output=True, text=True)
    if check and proc.returncode != 0:
        raise StackError(f"docker {args[0]} failed: {proc.stderr.strip()[:400]}")
    return proc.stdout.strip()


def port_in_use(port, host="127.0.0.1"):
    with socket.socket() as s:
        s.settimeout(0.2)
        return s.connect_ex((host, port)) == 0


def http_get(url, timeout=2.0):
    try:
        with OPENER.open(url, timeout=timeout) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except OSError:
        return None, b""


def proc_start_ticks(pid):
    """Kernel start time of a live process (field 22 of /proc/<pid>/stat), or None if it does not exist
    or has exited (a zombie waiting for its parent is not alive)."""
    try:
        with open(f"/proc/{pid}/stat", encoding="ascii", errors="replace") as fh:
            fields = fh.read().rsplit(")", 1)[1].split()
    except OSError:
        return None
    return None if fields[0] in ("Z", "X") else int(fields[19])


def reap(pid):
    """Collect the exit status of a child of this process (when `up` ran in-process)."""
    try:
        os.waitpid(pid, os.WNOHANG)
    except ChildProcessError:
        pass


def proc_pgid(pid):
    try:
        return os.getpgid(pid)
    except OSError:
        return None


def group_members(pgid):
    """Live pids whose process group is `pgid`."""
    members = []
    for name in os.listdir("/proc"):
        if name.isdigit():
            try:
                with open(f"/proc/{name}/stat", encoding="ascii", errors="replace") as fh:
                    fields = fh.read().rsplit(")", 1)[1].split()
            except OSError:
                continue
            if int(fields[2]) == pgid and fields[0] != "Z":
                members.append(int(name))
    return members


# ─────────────────────────────── configuration ───────────────────────────────
def load_config(path):
    with open(path, encoding="utf-8") as fh:
        cfg = json.load(fh)
    unknown = set(cfg) - CONFIG_KEYS - OPTIONAL_KEYS
    missing = CONFIG_KEYS - set(cfg)
    if unknown or missing:
        raise StackError(f"config keys: unknown {sorted(unknown)}, missing {sorted(missing)}")
    if cfg["schema"] != CONFIG_SCHEMA:
        raise StackError("config schema")
    if cfg["mode"] not in ALLOWED_MODES:
        raise StackError(f"mode {cfg['mode']!r}: this package runs {ALLOWED_MODES}; V4 is not part of it")
    fast = cfg["fast_path"]
    if fast is not None:
        if cfg["mode"] not in ("CASCADE_ACTIVE", "FAST_PATH_V5") or not isinstance(fast, dict) or set(fast) != FAST_PATH_KEYS:
            raise StackError("fast_path requires CASCADE_ACTIVE or FAST_PATH_V5 and the four pinned policy fields")
        if (not isinstance(fast["policy_file"], str) or not fast["policy_file"]
                or not isinstance(fast["policy_sha256"], str)
                or not isinstance(fast["application_contract_ref"], str)
                or not fast["application_contract_ref"].strip()
                or isinstance(fast["audit_sample_rate"], bool)
                or not isinstance(fast["audit_sample_rate"], (int, float))
                or not 0 <= fast["audit_sample_rate"] <= 1):
            raise StackError("fast_path fields are invalid")
        try:
            policy = FP.load_policy(resolve(fast["policy_file"]))
        except (OSError, FP.PolicyError) as exc:
            raise StackError(f"fast_path policy invalid: {type(exc).__name__}") from None
        if policy.sha256 != fast["policy_sha256"] or policy.status != "PROPOSED":
            raise StackError("fast_path policy digest/status differs from the pinned lab policy")
    if set(cfg["ports"]) != set(PORT_KEYS) or len(set(cfg["ports"].values())) != len(PORT_KEYS):
        raise StackError("ports: need distinct " + ", ".join(PORT_KEYS))
    if "crs" in cfg:
        if set(cfg["crs"]) != CRS_KEYS:
            raise StackError(f"crs keys must be {sorted(CRS_KEYS)}")
        if cfg["crs"]["port"] in cfg["ports"].values():
            raise StackError("crs port collides")
    if cfg.get("request_guard") is not None:
        g = cfg["request_guard"]
        if (cfg["mode"] != "FAST_PATH_V5" or fast is None or not isinstance(g, dict)
                or set(g) != {"policy_file", "policy_sha256", "application_contract_ref"}
                or g["application_contract_ref"] != fast["application_contract_ref"]):
            raise StackError("request_guard configuration or application binding invalid")
        import request_guard as RG
        try:
            RG.load(resolve(g["policy_file"]), g["policy_sha256"], g["application_contract_ref"])
        except (ValueError, OSError, TypeError):
            raise StackError("request_guard policy changed or invalid") from None
    return cfg


def check_manifest(cfg):
    path = resolve(cfg["manifest"]["path"])
    digest = sha256_file(path)
    if digest != cfg["manifest"]["sha256"]:
        raise StackError(f"manifest sha256 {digest} differs from the pinned {cfg['manifest']['sha256']}")
    with open(path, encoding="utf-8") as fh:
        manifest = json.load(fh)
    if cfg["mode"] == "CASCADE_ACTIVE" and not manifest.get("model2"):
        raise StackError("CASCADE_ACTIVE needs a manifest with Model 2")
    if cfg["mode"] == "FAST_PATH_V5" and manifest.get("model2") is not None:
        raise StackError("FAST_PATH_V5 forbids Model 2 in its manifest")
    if cfg["mode"] == "FAST_PATH_V5" and cfg["fast_path"] is None:
        raise StackError("FAST_PATH_V5 needs a pinned Fast Path policy")
    return path, manifest


def image_id(image):
    out = docker("image", "inspect", image, "--format", "{{.Id}}", check=False)
    return out or None


def render_nginx(cfg, ports, upstream_port=None):
    with open(NGINX_TEMPLATE, encoding="utf-8") as fh:
        template = fh.read()
    front = cfg["front"]
    values = {"WORKERS": str(front["workers"]), "GATEWAY_PORT": str(upstream_port or ports["gateway"]),
              "UPSTREAM_KEEPALIVE": str(front["upstream_keepalive"]), "TLS_PORT": str(ports["front_tls"]),
              "HTTP2": "on" if front["http2"] else "off", "SERVER_NAME": cfg["app"]["hostname"],
              "MAX_BODY": front["max_body"], "STATUS_PORT": str(ports["front_status"]),
              "UPSTREAM_TIMEOUT": front["upstream_timeout"]}
    used = set(re.findall(r"\$\{([A-Z0-9_]+)\}", template))
    if used != set(values):
        raise StackError(f"nginx template variables {sorted(used ^ set(values))}")
    return re.sub(r"\$\{([A-Z0-9_]+)\}", lambda m: values[m.group(1)], template)


def free_subnet():
    ids = docker("network", "ls", "-q").split()
    existing = json.loads(docker("network", "inspect", *ids)) if ids else []
    taken = [ipaddress.ip_network(c["Subnet"]) for n in existing
             for c in (n.get("IPAM", {}).get("Config") or []) if c.get("Subnet")]
    for i in range(160, 250):
        net = ipaddress.ip_network(f"172.30.{i}.0/24")
        if not any(net.overlaps(t) for t in taken if t.version == 4):
            return net
    raise StackError("no free 172.30.x.0/24 subnet")


# ─────────────────────────────── state ───────────────────────────────
class State:
    def __init__(self, work):
        self.work = os.path.abspath(work)
        self.path = os.path.join(self.work, STATE_FILE)
        self.doc = None

    def load(self):
        with open(self.path, encoding="utf-8") as fh:
            self.doc = json.load(fh)
        if self.doc.get("schema") != STATE_SCHEMA:
            raise StackError("state schema")
        return self.doc

    def save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.doc, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.replace(tmp, self.path)

    def add(self, component):
        self.doc["components"].append(component)
        self.save()


def spawn(state, name, argv, env=None, cwd=REPO):
    log_path = os.path.join(state.work, "logs", f"{name}.log")
    with open(log_path, "ab") as log:
        proc = subprocess.Popen(argv, cwd=cwd, stdout=log, stderr=subprocess.STDOUT, env=env,
                                start_new_session=True)
    state.add({"name": name, "kind": "process", "pid": proc.pid, "pgid": proc.pid,
               "start_ticks": proc_start_ticks(proc.pid), "argv": argv, "log": log_path})
    return proc


def wait_until(predicate, timeout, what, proc=None):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        if proc is not None and proc.poll() is not None:
            raise StackError(f"{what}: process exited with {proc.returncode}")
        time.sleep(0.1)
    raise StackError(f"{what}: not ready after {timeout:.0f} s")


# ─────────────────────────────── PKI ───────────────────────────────
def make_pki(pki_dir, hostname):
    """A lab CA and one server certificate. The private keys stay in the private work directory."""
    os.makedirs(pki_dir, mode=0o700, exist_ok=True)
    ca_key, ca_crt = os.path.join(pki_dir, "ca.key"), os.path.join(pki_dir, "ca.crt")
    key, csr, crt = (os.path.join(pki_dir, n) for n in ("server.key", "server.csr", "server.crt"))
    ext = os.path.join(pki_dir, "server.ext")
    if not os.path.exists(crt):
        run = lambda *a: subprocess.run(["openssl", *a], check=True, capture_output=True)  # noqa: E731
        run("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", ca_key)
        run("req", "-x509", "-new", "-key", ca_key, "-sha256", "-days", "30", "-subj",
            "/CN=Firewall-IA local lab CA (NOT TRUSTED)", "-out", ca_crt)
        run("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", key)
        run("req", "-new", "-key", key, "-subj", f"/CN={hostname}", "-out", csr)
        with open(ext, "w", encoding="ascii") as fh:
            fh.write(f"subjectAltName=DNS:{hostname},DNS:localhost,IP:127.0.0.1\n"
                     "extendedKeyUsage=serverAuth\nkeyUsage=digitalSignature\nbasicConstraints=CA:FALSE\n")
        run("x509", "-req", "-in", csr, "-CA", ca_crt, "-CAkey", ca_key, "-CAcreateserial", "-days", "30",
            "-sha256", "-extfile", ext, "-out", crt)
        for path in (ca_key, key):
            os.chmod(path, 0o600)
    der = ssl.PEM_cert_to_DER_cert(open(crt, encoding="ascii").read())
    return {"ca_cert": ca_crt, "server_cert": crt, "server_key": key,
            "server_cert_sha256": hashlib.sha256(der).hexdigest()}


def tls_context(ca_cert, alpn=("http/1.1",)):
    ctx = ssl.create_default_context(cafile=ca_cert)
    ctx.set_alpn_protocols(list(alpn))
    return ctx


# ─────────────────────────────── up ───────────────────────────────
def preflight(cfg, args):
    problems = []
    if cfg["fast_path"] is not None and args.firewall != "cascade":
        problems.append("fast_path needs the cascade firewall")
    for key in PORT_KEYS:
        if key == "v5" and args.v5.startswith("url:"):
            continue
        if port_in_use(cfg["ports"][key]):
            problems.append(f"port {key}={cfg['ports'][key]} in use (not ours: it is not stopped)")
    roles = ("front", "app") + (("crs",) if args.firewall == "crs" else ())
    if args.firewall == "crs":
        if "crs" not in cfg:
            raise StackError("--firewall crs needs a `crs` section in the config")
        if port_in_use(cfg["crs"]["port"]):
            problems.append(f"crs port {cfg['crs']['port']} in use (not ours: it is not stopped)")
    for role in roles:
        found = image_id(cfg[role]["image"])
        if found != cfg[role]["image_id"]:
            problems.append(f"{role} image {cfg[role]['image']} is {found}, pinned {cfg[role]['image_id']}")
    if args.v5 == "real" and args.firewall == "cascade":
        refusal = gpu_gate.refusal()
        if refusal:
            problems.append("real V5: " + refusal)
    if os.path.abspath(args.work).startswith(REPO + os.sep):
        problems.append("work directory must be outside the repository")
    if problems:
        raise StackError("; ".join(problems))


def start_app(state, cfg, args, run_id):
    app = cfg["app"]
    net = free_subnet()
    app_ip = str(net.network_address + 2)
    network = f"fwlab-stack-{run_id}"
    label = f"fwlab.stack.run={run_id}"
    docker("network", "create", "--internal", "--subnet", net, "--label", label, network)
    state.add({"name": "app-network", "kind": "network", "network": network, "label": label})
    evidence = os.path.join(state.work, "app")
    os.makedirs(evidence, exist_ok=True)
    os.chmod(evidence, 0o777)       # the container user writes its log here; private directory
    origins = f"https://{app['hostname']}:{cfg['ports']['front_tls']},https://localhost:{cfg['ports']['front_tls']}"
    name = f"fwlab-stack-{run_id}-app"
    docker("run", "-d", "--name", name, "--label", label, "--network", network, "--ip", app_ip,
           "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
           "--pids-limit", "128", "--memory", "256m", "--cpus", "1",
           "--tmpfs", "/tmp:rw,nosuid,noexec,size=64m", "--user", "1000:1000",
           "-v", f"{os.path.dirname(APP_SOURCE)}:/app:ro", "-v", f"{evidence}:/evidence:rw",
           "-e", f"FWLAB_SECRET_SEED={state.doc['seed']}", "-e", f"FWLAB_PORT={app['port']}",
           "-e", f"FWLAB_ALLOWED_ORIGINS={origins}", "-e", "FWLAB_COOKIE_SECURE=1",
           "-e", f"FWLAB_EFFECT_ROUTES={'1' if args.effect_routes else '0'}",
           "-e", f"FWLAB_LOG_TARGETS={'1' if args.log_targets else '0'}",
           "-e", "FWLAB_LOG=/evidence/notes-app.jsonl",
           "--entrypoint", "python3", cfg["app"]["image"], "/app/app.py")
    state.add({"name": "app", "kind": "container", "container": name, "label": label, "ip": app_ip,
               "port": app["port"], "network": network})
    wait_until(lambda: http_get(f"http://{app_ip}:{app['port']}/healthz", timeout=1)[0] == 200, 20, "app")
    routes = docker("exec", name, "cat", "/proc/net/route")
    if any(line.split()[1] == "00000000" for line in routes.splitlines()[1:] if line.strip()):
        raise StackError("app container has a default route: isolation broken")
    inside = docker("exec", name, "python3", "-c",
                    "import hashlib;print(hashlib.sha256(open('/app/app.py','rb').read()).hexdigest())")
    if inside != sha256_file(APP_SOURCE):
        raise StackError("app source inside the container differs")
    return app_ip


def start_raw_sink(state, cfg):
    """Transport checks: the upstream is a loopback process that keeps the exact bytes it receives."""
    port = cfg["app"]["port"]
    if port_in_use(port):
        raise StackError(f"raw sink port {port} in use")
    os.makedirs(os.path.join(state.work, "app"), exist_ok=True)
    proc = spawn(state, "raw-sink", [PYTHON, "-I", os.path.join(HERE, "raw_sink.py"), "--port", str(port),
                                     "--out", os.path.join(state.work, "app", "raw-sink.jsonl")])
    wait_until(lambda: port_in_use(port), 10, "raw sink", proc)
    return "127.0.0.1"


def start_v5(state, cfg, args, manifest_path):
    if args.v5.startswith("url:"):
        return args.v5[4:]
    port = cfg["ports"]["v5"]
    if args.v5 == "double":
        argv = [PYTHON, os.path.join(OPS, "service_doubles.py"), "--role", "v5", "--port", str(port),
                "--manifest", manifest_path]
        env = None
        timeout = 15
    else:
        import load_check as LK   # noqa: E402 — only for the real service environment
        argv = ["/usr/bin/python3.12", "-B", "-m", "uvicorn", "--app-dir", os.path.join(REPO, "control_plane"),
                "v5_classifier_api:app", "--host", "127.0.0.1", "--port", str(port)]
        env = {k: v for k, v in os.environ.items() if not k.startswith("FIREWALL_V5_")}
        env.update(LK.SERVICE_ENV)
        env.update(LK.v5_environment(manifest_path))
        timeout = 180
    proc = spawn(state, "v5-" + args.v5, argv, env=env)
    url = f"http://127.0.0.1:{port}"

    def loaded():
        status, body = http_get(url + "/health", timeout=1)
        return status == 200 and json.loads(body).get("model_loaded")
    wait_until(loaded, timeout, "V5 service", proc)
    return url


def gateway_document(cfg, manifest_path, app_ip, v5_url, gw_dir):
    ports, gw = cfg["ports"], cfg["gateway"]
    fast = cfg["fast_path"]
    doc = L.gateway_config(mode=cfg["mode"], manifest=manifest_path, listen_port=ports["gateway"],
                           guard_port=ports["guard"], sink_port=cfg["app"]["port"],
                           admin_port=ports["admin"], v4_url="http://127.0.0.1:9", v5_url=v5_url,
                           workdir=gw_dir, v5_timeout=gw["v5_timeout_seconds"],
                           v4_timeout=1.0, deadline=gw["decision_deadline_seconds"],
                           max_inflight=gw["max_inflight"], max_waiting=gw["max_waiting"],
                           body_size_limit=gw["body_size_limit"],
                           fast_path_policy=resolve(fast["policy_file"]) if fast else None,
                           fast_path_sha256=fast["policy_sha256"] if fast else None,
                           sample_rate=fast["audit_sample_rate"] if fast else 0.0)
    if cfg.get("request_guard") is not None:
        doc["cascade_gateway"]["request_guard"] = dict(cfg["request_guard"], policy_file=resolve(cfg["request_guard"]["policy_file"]))
    doc["cascade_gateway"]["framing"]["egress_guard"]["upstream_host"] = app_ip
    if fast:
        doc["cascade_gateway"]["fast_path"]["application_contract_ref"] = fast["application_contract_ref"]
    return doc


def start_gateway(state, cfg, manifest_path, app_ip, v5_url):
    gw_dir = os.path.join(state.work, "gateway")
    os.makedirs(gw_dir, exist_ok=True)
    path = os.path.join(gw_dir, "gateway.yaml")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(gateway_document(cfg, manifest_path, app_ip, v5_url, gw_dir), fh, indent=2)
    check = subprocess.run([PYTHON, os.path.join(OPS, "launch.py"), "--config", path, "--check"],
                           cwd=REPO, capture_output=True, text=True)
    if check.returncode != 0:
        raise StackError("gateway --check: " + check.stdout[-800:])
    proc = spawn(state, "gateway", [PYTHON, os.path.join(OPS, "launch.py"), "--config", path])
    admin = cfg["ports"]["admin"]
    wait_until(lambda: http_get(f"http://127.0.0.1:{admin}/readyz", timeout=1)[0] == 200, 60,
               "gateway readiness", proc)
    return path


def start_crs(state, cfg, app_ip, run_id):
    """ModSecurity + OWASP CRS in front of the same application, as the COMPARATOR arm. The image's own
    configuration, except: loopback-only listener without TLS (the same front terminates TLS for both
    arms) and no /healthz or /metrics answered by the WAF itself. Paranoia and anomaly thresholds come
    from the configuration and are recorded; they are fixed before any run, never tuned on results."""
    crs = cfg["crs"]
    logs = os.path.join(state.work, "crs", "logs")
    os.makedirs(logs, exist_ok=True)
    os.chmod(logs, 0o777)                      # the image runs as its own unprivileged user
    name = f"fwlab-stack-{run_id}-crs"
    label = f"fwlab.stack.run={run_id}"
    env = {"BACKEND": f"http://{app_ip}:{cfg['app']['port']}", "PORT": str(crs["port"]),
           "SERVER_NAME": cfg["app"]["hostname"], "PROXY_HOST_HEADER": "$http_host",
           "BLOCKING_PARANOIA": str(crs["blocking_paranoia"]), "ANOMALY_INBOUND": str(crs["anomaly_inbound"]),
           "ANOMALY_OUTBOUND": str(crs["anomaly_outbound"]), "MODSEC_AUDIT_ENGINE": "RelevantOnly",
           "MODSEC_AUDIT_LOG": "/fwlab-logs/modsec-audit.jsonl", "MODSEC_AUDIT_LOG_FORMAT": "JSON",
           "MODSEC_AUDIT_LOG_PARTS": "ABHZ", "ACCESSLOG": "/fwlab-logs/crs-access.log",
           "ERRORLOG": "/fwlab-logs/crs-error.log", "NGINX_WORKER_PROCESSES": "2"}
    # --no-healthcheck: the image probes https://localhost:${SSL_PORT}/healthz, which on the host network
    # is the stack's own TLS front; it would inject foreign requests into the measured logs.
    argv = ["run", "-d", "--name", name, "--label", label, "--network", "host", "--no-healthcheck",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges", "--pids-limit", "128", "--memory", "512m",
            "-v", f"{os.path.join(CRS_DIR, 'default.conf.template')}:/etc/nginx/templates/conf.d/default.conf.template:ro",
            "-v", f"{os.path.join(CRS_DIR, 'location_common.conf.template')}:/etc/nginx/templates/includes/location_common.conf.template:ro",
            "-v", f"{logs}:/fwlab-logs:rw"]
    for k, v in env.items():
        argv += ["-e", f"{k}={v}"]
    docker(*argv, crs["image"])
    state.add({"name": "crs", "kind": "container", "container": name, "label": label})
    wait_until(lambda: port_in_use(crs["port"]), 30, "CRS")
    effective = docker("exec", name, "sh", "-c",
                       "grep -h -o 'tx.blocking_paranoia_level=[0-9]*\\|tx.inbound_anomaly_score_threshold=[0-9]*\\|"
                       "tx.outbound_anomaly_score_threshold=[0-9]*' /etc/modsecurity.d/owasp-crs/crs-setup.conf; "
                       "grep -m1 -o 'ver\\.[0-9.]*' /opt/owasp-crs/crs-setup.conf; grep -h '^SecRuleEngine' "
                       "/etc/modsecurity.d/modsecurity.conf; grep -h 'listen' /etc/nginx/conf.d/default.conf",
                       check=False)
    return {"image": crs["image"], "image_id": crs["image_id"], "env": env,
            "effective": sorted({x.strip() for x in effective.split("\n") if x.strip() and not x.strip().startswith("#")}),
            "templates_sha256": {n: sha256_file(os.path.join(CRS_DIR, n))
                                 for n in ("default.conf.template", "location_common.conf.template")},
            "audit_log": os.path.join(logs, "modsec-audit.jsonl")}


def start_front(state, cfg, run_id, pki, upstream_port=None):
    front_dir = os.path.join(state.work, "front")
    logs = os.path.join(front_dir, "logs")
    os.makedirs(logs, exist_ok=True)
    conf = os.path.join(front_dir, "nginx.conf")
    with open(conf, "w", encoding="utf-8") as fh:
        fh.write(render_nginx(cfg, cfg["ports"], upstream_port))
    pki_mount = os.path.join(front_dir, "pki")
    os.makedirs(pki_mount, mode=0o700, exist_ok=True)
    for src, dst in ((pki["server_cert"], "server.crt"), (pki["server_key"], "server.key")):
        with open(src, "rb") as a, open(os.path.join(pki_mount, dst), "wb") as b:
            b.write(a.read())
        os.chmod(os.path.join(pki_mount, dst), 0o600)
    name = f"fwlab-stack-{run_id}-front"
    label = f"fwlab.stack.run={run_id}"
    uid = f"{os.getuid()}:{os.getgid()}"
    docker("run", "-d", "--name", name, "--label", label, "--network", "host", "--read-only",
           "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "64",
           "--memory", "128m", "--user", uid, "--tmpfs", "/tmp:rw,nosuid,noexec,size=32m",
           "-v", f"{conf}:/etc/fwlab/nginx.conf:ro", "-v", f"{pki_mount}:/pki:ro", "-v", f"{logs}:/logs:rw",
           "--entrypoint", "nginx", cfg["front"]["image"], "-c", "/etc/fwlab/nginx.conf", "-g", "daemon off;")
    state.add({"name": "front", "kind": "container", "container": name, "label": label})
    status_port = cfg["ports"]["front_status"]
    wait_until(lambda: http_get(f"http://127.0.0.1:{status_port}/__front/ready", timeout=1)[0] == 200, 20,
               "front")
    ctx = tls_context(pki["ca_cert"], ("h2", "http/1.1"))
    with socket.create_connection(("127.0.0.1", cfg["ports"]["front_tls"]), timeout=3) as raw:
        with ctx.wrap_socket(raw, server_hostname=cfg["app"]["hostname"]) as tls:
            negotiated = tls.selected_alpn_protocol()
            version = tls.version()
    expect = "h2" if cfg["front"]["http2"] else "http/1.1"
    if negotiated != expect:
        raise StackError(f"front ALPN {negotiated!r}, expected {expect!r}")
    return {"conf": conf, "conf_sha256": sha256_file(conf), "alpn": negotiated, "tls_version": version}


def up(args):
    cfg = load_config(args.config)
    manifest_path, manifest = check_manifest(cfg)
    preflight(cfg, args)
    state = State(args.work)
    if os.path.exists(state.path):
        raise StackError(f"{state.path} exists: run `down` and use a new work directory")
    os.makedirs(os.path.join(state.work, "logs"), exist_ok=True)
    os.chmod(state.work, 0o700)
    run_id = time.strftime("%Y%m%dT%H%M%S") + "-" + secrets.token_hex(3)
    state.doc = {"schema": STATE_SCHEMA, "run_id": run_id, "created_utc": time.time(),
                 "seed": secrets.token_hex(32), "config_path": os.path.abspath(args.config),
                 "config_sha256": sha256_file(args.config), "mode": cfg["mode"], "v5": args.v5,
                 "effect_routes": args.effect_routes, "upstream": args.upstream, "firewall": args.firewall,
                 "components": [],
                 "ready": False}
    state.save()
    try:
        pki = make_pki(os.path.join(state.work, "pki"), cfg["app"]["hostname"])
        if args.upstream == "app":
            app_ip = start_app(state, cfg, args, run_id)
        else:
            app_ip = start_raw_sink(state, cfg)
        crs = None
        if args.firewall == "cascade":
            v5_url = start_v5(state, cfg, args, manifest_path)
            gateway_config = start_gateway(state, cfg, manifest_path, app_ip, v5_url)
            front = start_front(state, cfg, run_id, pki)
        else:
            v5_url = gateway_config = None
            crs = start_crs(state, cfg, app_ip, run_id)
            front = start_front(state, cfg, run_id, pki, upstream_port=cfg["crs"]["port"])
    except BaseException:
        state.save()
        print("up failed; stopping what was started", file=sys.stderr)
        down_state(state)
        raise
    ports = cfg["ports"]
    state.doc.update(ready=True, endpoints={
        "front_tls": f"https://{cfg['app']['hostname']}:{ports['front_tls']}",
        "front_status": f"http://127.0.0.1:{ports['front_status']}",
        "gateway_plain": f"http://127.0.0.1:{ports['gateway']}",
        "gateway_admin": f"http://127.0.0.1:{ports['admin']}",
        "v5": v5_url, "app_direct": f"http://{app_ip}:{cfg['app']['port']}",
        "crs": f"http://127.0.0.1:{cfg['crs']['port']}" if crs else None},
        firewall=args.firewall, crs=crs,
        ports=ports, hostname=cfg["app"]["hostname"], pki=pki, app_ip=app_ip,
        gateway_config=gateway_config, gateway_decisions=os.path.join(state.work, "gateway", "decisions.jsonl"),
        app_log=os.path.join(state.work, "app", "notes-app.jsonl" if args.upstream == "app" else "raw-sink.jsonl"),
        front_access_log=os.path.join(state.work, "front", "logs", "front-access.jsonl"),
        identity=identity(cfg, manifest_path, manifest, front, args, crs))
    state.save()
    print(json.dumps({"ready": True, "work": state.work, "endpoints": state.doc["endpoints"],
                      "mode": cfg["mode"], "v5": args.v5}, indent=2))
    return 0


def identity(cfg, manifest_path, manifest, front, args, crs=None):
    """What this stack is, payload-free: it goes into every evidence directory of a check."""
    return {"schema": "firewall-local-stack-identity/v1", "mode": cfg["mode"],
            "manifest": {"path": rel(manifest_path), "sha256": sha256_file(manifest_path),
                         "manifest_id": manifest.get("manifest_id"), "status": manifest.get("status")},
            "firewall": args.firewall,
            "crs": {k: v for k, v in crs.items() if k != "audit_log"} if crs else None,
            "fast_path": cfg["fast_path"], "v4": "not started", "v5": args.v5.split(":", 1)[0] if args.firewall == "cascade" else None,
            "upstream": args.upstream, "effect_routes": args.effect_routes,
            "front": {"image": cfg["front"]["image"], "image_id": cfg["front"]["image_id"],
                      "template_sha256": sha256_file(NGINX_TEMPLATE), "conf_sha256": front["conf_sha256"],
                      "alpn": front["alpn"], "tls_version": front["tls_version"]},
            "app": {"image": cfg["app"]["image"], "image_id": cfg["app"]["image_id"],
                    "source": rel(APP_SOURCE), "source_sha256": sha256_file(APP_SOURCE)},
            "stack_source_sha256": sha256_file(os.path.abspath(__file__))}


# ─────────────────────────────── down / status / check-clean ───────────────────────────────
def _ours(component):
    """A recorded process that is still the one we started (same pid AND same kernel start time)."""
    ticks = proc_start_ticks(component["pid"])
    return ticks is not None and ticks == component["start_ticks"]


def stop_process(component, grace=10.0):
    if not _ours(component):
        return "gone"
    pgid = component["pgid"]
    if proc_pgid(component["pid"]) != pgid:
        return "pgid_changed_not_signalled"
    os.killpg(pgid, signal.SIGTERM)
    deadline = time.monotonic() + grace
    while time.monotonic() < deadline:
        reap(component["pid"])
        if not group_members(pgid):
            return "terminated"
        time.sleep(0.1)
    os.killpg(pgid, signal.SIGKILL)
    time.sleep(0.3)
    reap(component["pid"])
    return "killed"


def stop_container(component):
    labels = docker("inspect", component["container"], "--format",
                    "{{json .Config.Labels}}", check=False)
    if not labels:
        return "gone"
    key, _, value = component["label"].partition("=")
    if json.loads(labels).get(key) != value:
        return "label_mismatch_not_removed"
    logs = subprocess.run(["docker", "logs", component["container"]], capture_output=True, text=True)
    removed = subprocess.run(["docker", "rm", "-f", component["container"]], capture_output=True).returncode == 0
    return ("removed" if removed else "rm_failed"), logs


def down_state(state):
    results = {}
    for component in reversed(state.doc["components"]):
        name = component["name"]
        if component["kind"] == "process":
            results[name] = stop_process(component)
        elif component["kind"] == "container":
            outcome = stop_container(component)
            if isinstance(outcome, tuple):
                outcome, logs = outcome
                with open(os.path.join(state.work, "logs", f"{name}.console.log"), "w", encoding="utf-8") as fh:
                    fh.write(logs.stdout + logs.stderr)
            results[name] = outcome
        elif component["kind"] == "network":
            proc = subprocess.run(["docker", "network", "rm", component["network"]], capture_output=True, text=True)
            results[name] = "removed" if proc.returncode == 0 else ("gone" if "not found" in proc.stderr else "rm_failed")
    state.doc["stopped_utc"] = time.time()
    state.doc["ready"] = False
    state.doc["down"] = results
    state.save()
    return results


def down(args):
    state = State(args.work)
    state.load()
    results = down_state(state)
    print(json.dumps(results, indent=2, sort_keys=True))
    return 0 if all(v in ("terminated", "killed", "removed", "gone") for v in results.values()) else 1


def clean_report(state):
    doc = state.doc
    leftovers = []
    for c in doc["components"]:
        if c["kind"] == "process":
            if _ours(c):
                leftovers.append(f"process {c['name']} pid {c['pid']} alive")
            members = [p for p in group_members(c["pgid"]) if proc_start_ticks(p) is not None]
            if members:
                leftovers.append(f"process group of {c['name']} has {len(members)} members")
        elif c["kind"] == "container":
            if docker("ps", "-a", "-q", "--filter", f"name=^{c['container']}$", check=False):
                leftovers.append(f"container {c['container']} exists")
        elif c["kind"] == "network":
            if docker("network", "ls", "-q", "--filter", f"name=^{c['network']}$", check=False):
                leftovers.append(f"network {c['network']} exists")
    labelled = docker("ps", "-a", "-q", "--filter", f"label=fwlab.stack.run={doc['run_id']}", check=False)
    if labelled:
        leftovers.append(f"{len(labelled.split())} labelled containers")
    for key, port in (doc.get("ports") or {}).items():
        if key == "v5" and str(doc.get("v5", "")).startswith("url:"):
            continue
        if port_in_use(port):
            leftovers.append(f"port {key}={port} listening")
    return {"schema": "firewall-local-stack-clean/v1", "run_id": doc["run_id"], "checked_utc": time.time(),
            "clean": not leftovers, "leftovers": leftovers}


def check_clean(args):
    state = State(args.work)
    state.load()
    report = clean_report(state)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["clean"] else 1


def status(args):
    state = State(args.work)
    doc = state.load()
    out = {"run_id": doc["run_id"], "ready": doc["ready"], "mode": doc["mode"], "v5": doc["v5"], "components": {}}
    for c in doc["components"]:
        if c["kind"] == "process":
            out["components"][c["name"]] = "alive" if _ours(c) else "not running"
        elif c["kind"] == "container":
            out["components"][c["name"]] = docker("inspect", c["container"], "--format", "{{.State.Status}}",
                                                  check=False) or "absent"
    if doc.get("endpoints"):
        if doc.get("firewall", "cascade") == "cascade":
            out["gateway_readyz"] = http_get(doc["endpoints"]["gateway_admin"] + "/readyz", timeout=1)[0]
        out["front_ready"] = http_get(doc["endpoints"]["front_status"] + "/__front/ready", timeout=1)[0]
        out["endpoints"] = doc["endpoints"]
    print(json.dumps(out, indent=2, sort_keys=True))
    return 0


def pin(args):
    """A new stack configuration for a delivered candidate manifest: path and SHA-256 pinned, mode chosen
    explicitly, everything else copied from the base configuration. Refuses to overwrite."""
    import cascade_manifest as CM   # noqa: E402 — validates the manifest the way the gateway reads it
    cfg = load_config(args.config)
    path = os.path.abspath(args.manifest)
    try:
        manifest = CM.load_manifest(path)
    except CM.ManifestError as exc:
        raise StackError(f"manifest refused: {exc}")
    if args.mode == "CASCADE_ACTIVE" and manifest.model2 is None:
        raise StackError("CASCADE_ACTIVE needs a manifest with Model 2")
    if args.mode == "FAST_PATH_V5" and (manifest.model2 is not None or cfg["fast_path"] is None):
        raise StackError("FAST_PATH_V5 needs a model2-null manifest and a pinned Fast Path policy")
    cfg.update(mode=args.mode, manifest={"path": rel(path), "sha256": sha256_file(path)})
    with open(args.out, "x", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=2)
        fh.write("\n")
    print(json.dumps({"written": args.out, "manifest_id": manifest.manifest_id, "status": manifest.status,
                      "mode": args.mode, "sha256": cfg["manifest"]["sha256"]}, indent=2))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    p_up = sub.add_parser("up")
    p_up.add_argument("--config", required=True)
    p_up.add_argument("--work", required=True)
    p_up.add_argument("--v5", default="double", help="double (default) | real | url:<http://...>")
    p_up.add_argument("--firewall", choices=("cascade", "crs"), default="cascade",
                      help="cascade: the Firewall-IA gateway (default); crs: ModSecurity + OWASP CRS comparator")
    p_up.add_argument("--upstream", choices=("app", "raw-sink"), default="app",
                      help="app: fwlab-notes in Docker (default); raw-sink: exact-bytes receiver on loopback")
    p_up.add_argument("--effect-routes", action="store_true",
                      help="mount the deliberately vulnerable effect routes of the app (isolated network)")
    p_up.add_argument("--log-targets", action="store_true",
                      help="app log keeps raw targets (synthetic lab traffic only)")
    for name in ("down", "status", "check-clean"):
        sub.add_parser(name).add_argument("--work", required=True)
    p_pin = sub.add_parser("pin", help="write a new config pinning a delivered candidate manifest")
    p_pin.add_argument("--config", required=True)
    p_pin.add_argument("--manifest", required=True)
    p_pin.add_argument("--mode", required=True, choices=ALLOWED_MODES)
    p_pin.add_argument("--out", required=True)
    args = parser.parse_args(argv)
    if args.command == "up" and args.v5 not in ("double", "real") and not args.v5.startswith("url:"):
        parser.error("--v5 must be double, real or url:<url>")
    try:
        return {"up": up, "down": down, "status": status, "check-clean": check_clean,
                "pin": pin}[args.command](args)
    except StackError as exc:
        print(f"stack: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
