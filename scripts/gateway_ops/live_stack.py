"""
A complete local gateway stack for live checks: real mitmdump + addon, real canonical workers, real
Model 2 worker on CPU, an independent sink process, and V4/V5 services that are either doubles or the
real ones (`v5_url`/`v4_url`, for the GPU hand-off run).

Every process is a child of this one, on free loopback ports, logging under `workdir`. Nothing here
touches the GPU unless real service URLs are passed in.
"""
import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
PYTHON = os.path.join(REPO, ".venv-dataplane", "bin", "python")
ANALYZER_PYTHON = os.path.join(REPO, ".venv-analyzer", "bin", "python")
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def http_get(url, timeout=2.0):
    try:
        with OPENER.open(url, timeout=timeout) as resp:
            return resp.status, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except OSError:
        return None, b""


def http_post_json(url, payload, timeout=2.0):
    req = urllib.request.Request(url, data=json.dumps(payload).encode("utf-8"),
                                 headers={"Content-Type": "application/json"}, method="POST")
    with OPENER.open(req, timeout=timeout) as resp:
        return resp.status


def worker_bounds(python, timeout, startup=20.0, backoff=0.2):
    return {"python": python, "timeout_seconds": timeout, "startup_timeout_seconds": startup,
            "restart_backoff_seconds": backoff, "max_consecutive_failures": 3}


def manifest_body_limit(manifest):
    """The body bound follows the candidate's token budget. It is never a value of this file."""
    try:
        with open(manifest, encoding="utf-8") as fh:
            return json.load(fh)["canonical"]["max_decoded_body"]
    except (OSError, ValueError, KeyError, TypeError):
        return 1           # a manifest that cannot be read is refused later, for that reason


def gateway_config(*, mode, manifest, listen_port, guard_port, sink_port, admin_port, v4_url,
                   v5_url, workdir, deployment_profile="lab", fast_path_policy=None, fast_path_sha256=None,
                   sample_rate=1.0, v4_timeout=1.0, v5_timeout=1.0, deadline=3.0, max_inflight=4,
                   max_waiting=8, body_size_limit="64k", max_received_body=None, worker_backoff=0.2,
                   probe_interval=0.2, observe_max_pending=16, audit_queue_size=16,
                   audit_timeout=1.5, audit_per_second=1000.0, audit_burst=1000,
                   audit_yield_inflight=1000, audit_max_age=60.0):
    activation = "experimental_fixture" if fast_path_policy else "disabled"
    return {"cascade_gateway": {
        "schema": "firewall-cascade-gateway-config/v2", "mode": mode,
        "deployment_profile": deployment_profile, "manifest": manifest,
        "listen": {"host": "127.0.0.1", "port": listen_port},
        "v4": {"url": v4_url, "timeout_seconds": v4_timeout},
        "v5": {"url": v5_url, "timeout_seconds": v5_timeout},
        "model2": worker_bounds(ANALYZER_PYTHON, 0.5, backoff=worker_backoff),
        "canonical": {"worker": worker_bounds(PYTHON, 0.5, backoff=worker_backoff), "workers": 2,
                      "max_received_body": max_received_body or manifest_body_limit(manifest),
                      "max_text_bytes": 262144},
        "admission": {"max_inflight": max_inflight, "max_waiting": max_waiting,
                      "max_wait_seconds": 2.0, "decision_deadline_seconds": deadline,
                      "observe_max_pending": observe_max_pending},
        "framing": {"contract": "gateway-framing/v1", "body_size_limit": body_size_limit,
                    "verified_evidence": bool(fast_path_policy), "owner_ruling_ref": None,
                    "egress_guard": {"listen_port": guard_port, "upstream_host": "127.0.0.1",
                                     "upstream_port": sink_port, "ticket_ttl_seconds": 5.0,
                                     "max_tickets": 256, "idle_timeout_seconds": 30.0}},
        "fast_path": {"activation": activation, "policy_file": fast_path_policy,
                      "policy_sha256": fast_path_sha256, "application_contract_ref": None,
                      "audit": {"sample_rate": sample_rate, "sample_salt": "live-check",
                                "queue_size": audit_queue_size, "max_queue_bytes": 1048576,
                                "workers": 1, "timeout_seconds": audit_timeout, "max_abandoned": 2,
                                "shutdown_drain_seconds": 2.0,
                                "max_audits_per_second": audit_per_second, "burst": audit_burst,
                                "yield_when_v5_inflight": audit_yield_inflight,
                                "max_queue_age_seconds": audit_max_age}},
        "observability": {"decision_log": os.path.join(workdir, "decisions.jsonl"),
                          "max_log_bytes": 16 * 1024 * 1024, "max_log_files": 2,
                          "log_queue_size": 4096, "admin_port": admin_port,
                          "log_wire_sha256": deployment_profile == "lab"},
        "rollback_file": os.path.join(workdir, "RETURN_TO_V4"),
        "probe_interval_seconds": probe_interval}}


class Stack:
    def __init__(self, workdir, *, mode, manifest, v5_url=None, v4_url=None,
                 config_overrides=None, mitmdump_extra=()):
        self.workdir = workdir
        os.makedirs(workdir, exist_ok=True)
        self.mode = mode
        self.manifest = manifest
        self.procs = []
        self.real_v5 = v5_url is not None
        self.listen_port = free_port()
        self.guard_port = free_port()
        self.sink_port = free_port()
        self.admin_port = free_port()
        self.v5_url = v5_url or f"http://127.0.0.1:{free_port()}"
        self.v4_url = v4_url or f"http://127.0.0.1:{free_port()}"
        self.real_v4 = v4_url is not None
        self.sink_path = os.path.join(workdir, "sink.jsonl")
        self.config_overrides = config_overrides or {}
        self.mitmdump_extra = tuple(mitmdump_extra)
        self.gateway_proc = None

    # ── processes ───────────────────────────────────────────────────────
    def _spawn(self, name, argv, env=None):
        log = open(os.path.join(self.workdir, f"{name}.log"), "ab")
        proc = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, env=env,
                                start_new_session=True)
        log.close()
        self.procs.append(proc)
        return proc

    def start_doubles(self):
        doubles = os.path.join(HERE, "service_doubles.py")
        if not self.real_v5:
            self._spawn("v5_double", [PYTHON, doubles, "--role", "v5", "--port",
                                      self.v5_url.rsplit(":", 1)[1], "--manifest", self.manifest])
        if not self.real_v4:
            self._spawn("v4_double", [PYTHON, doubles, "--role", "v4", "--port",
                                      self.v4_url.rsplit(":", 1)[1]])

    def start_sink(self):
        self._spawn("sink", [PYTHON, "-I", os.path.join(HERE, "independent_sink.py"), "--port",
                             str(self.sink_port), "--out", self.sink_path])

    def write_config(self):
        kwargs = dict(mode=self.mode, manifest=self.manifest, listen_port=self.listen_port,
                      guard_port=self.guard_port, sink_port=self.sink_port,
                      admin_port=self.admin_port, v4_url=self.v4_url, v5_url=self.v5_url,
                      workdir=self.workdir)
        kwargs.update(self.config_overrides)
        path = os.path.join(self.workdir, "gateway.yaml")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(gateway_config(**kwargs), fh, indent=2)   # JSON is valid YAML
        return path

    def start_gateway(self):
        config = self.write_config()
        argv = [PYTHON, os.path.join(HERE, "launch.py"), "--config", config, *self.mitmdump_extra]
        self.gateway_proc = self._spawn("gateway", argv)

    def start(self):
        try:
            self.start_sink()
            self.start_doubles()
            self.wait_port(self.sink_port)
            self.start_gateway()
            self.wait_port(self.listen_port)
        except Exception:
            self.stop()
            raise

    @staticmethod
    def wait_port(port, timeout=15.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with socket.socket() as s:
                s.settimeout(0.2)
                if s.connect_ex(("127.0.0.1", port)) == 0:
                    return True
            time.sleep(0.05)
        raise TimeoutError(f"port {port} not listening")

    def wait_ready(self, timeout=20.0, want=True, require_cascade=False):
        """`require_cascade`: in OBSERVE /readyz follows V4, which decides, so a check that needs the
        observation must also wait for the cascade to have no open problem."""
        deadline = time.monotonic() + timeout
        body = b""
        while time.monotonic() < deadline:
            status, body = http_get(f"http://127.0.0.1:{self.admin_port}/readyz", timeout=1.0)
            if (status == 200) == want and status is not None:
                detail = json.loads(body)
                if not require_cascade or not detail["cascade_problems"]:
                    return detail
            time.sleep(0.05)
        raise TimeoutError(f"readiness never became {want}: {body[:400]!r}")

    def restart_sink(self):
        self.start_sink()
        self.wait_port(self.sink_port)

    def stop_gateway(self, sig=signal.SIGTERM):
        proc = self.gateway_proc
        if proc is None:
            return None
        proc.send_signal(sig)
        try:
            return proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            return proc.wait(timeout=5)

    def stop(self):
        self.stop_gateway()
        for proc in self.procs:
            if proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=3)

    # ── controls and views ──────────────────────────────────────────────
    def control(self, role, behavior, **settings):
        url = self.v5_url if role == "v5" else self.v4_url
        http_post_json(f"{url}/__control", {"behavior": behavior, **settings})

    def calls(self, role):
        url = self.v5_url if role == "v5" else self.v4_url
        status, body = http_get(f"{url}/__stats")
        return json.loads(body)["calls"] if status == 200 else None

    def admin(self, path):
        return http_get(f"http://127.0.0.1:{self.admin_port}{path}")

    def status(self):
        status, body = self.admin("/status")
        return json.loads(body) if status == 200 else None

    def metrics(self):
        return self.admin("/metrics")[1].decode("utf-8")

    def records(self, kind=None):
        path = os.path.join(self.workdir, "decisions.jsonl")
        if not os.path.exists(path):
            return []
        with open(path, encoding="utf-8") as fh:
            rows = [json.loads(line) for line in fh if line.strip()]
        return [r for r in rows if kind is None or r.get("kind") == kind]

    def sink_records(self):
        if not os.path.exists(self.sink_path):
            return []
        with open(self.sink_path, encoding="utf-8") as fh:
            return [json.loads(line) for line in fh if line.strip()]

    def rollback(self, active):
        path = os.path.join(self.workdir, "RETURN_TO_V4")
        if active:
            open(path, "w").close()
        elif os.path.exists(path):
            os.unlink(path)

    # ── raw client ──────────────────────────────────────────────────────
    def send(self, segments, *, port=None, pause=0.02, responses=1, timeout=4.0):
        """Send raw segments, one write each, and read `responses` complete responses. Returns the
        list of HTTP status codes (None for a connection closed without a response)."""
        statuses = []
        with socket.create_connection(("127.0.0.1", port or self.listen_port), timeout=timeout) as s:
            for i, segment in enumerate(segments):
                if i:
                    time.sleep(pause)
                try:
                    s.sendall(segment)
                except OSError:
                    break
            buf = b""
            for _ in range(responses):
                status, buf = _read_response(s, buf)
                statuses.append(status)
                if status is None:
                    break
        return statuses


def _read_response(sock, buf):
    """(status, what follows). A connection that ends inside the body is no response: None."""
    try:
        while b"\r\n\r\n" not in buf:
            data = sock.recv(65536)
            if not data:
                return None, b""
            buf += data
        head, _, rest = buf.partition(b"\r\n\r\n")
        status = int(head.split(b" ", 2)[1])
        length = 0
        for line in head.split(b"\r\n")[1:]:
            name, _, value = line.partition(b":")
            if name.lower() == b"content-length":
                length = int(value)
        while len(rest) < length:
            data = sock.recv(65536)
            if not data:
                return None, b""
            rest += data
        return status, rest[length:]
    except (OSError, ValueError, IndexError):
        return None, b""
