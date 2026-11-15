"""
Run each sec-challenges/Web application in isolation behind the SAME TLS/HTTP-2 front and the SAME
cascade gateway (or the CRS comparator) as the fwlab-notes stack. LAB ONLY, not a deployment.

    client ──TLS h1/h2──> front (nginx, Docker, host loopback)
       ├─ arm direct   : front ─────────────────────────────> challenge app (Docker, internal net, no route out)
       ├─ arm v5only   : front ─> gateway (V5_ONLY)      ─guard─> challenge app
       ├─ arm guarded  : front ─> gateway (CASCADE_ACTIVE, Model 2 GUARDED_ENFORCE) ─guard─> challenge app
       └─ arm crs      : front ─> ModSecurity + OWASP CRS ─────> challenge app
                                                                 (+ MySQL sidecar for An0nB0ard)

This package does NOT modify the applications or their vulnerabilities. It builds an image from each
application's own tree (its own Dockerfile where it ships one, an adapter Dockerfile that only installs
the pinned requirements and runs the unmodified entry file otherwise) and runs it with the same
isolation and the same front/gateway/CRS machinery as scripts/local_stack/stack.py, whose leaf helpers
it imports unchanged. It never edits stack.py or the fwlab-notes application.

    PY=.venv-dataplane/bin/python
    $PY scripts/local_stack/challenges/challenge_stack.py build   --app An0nB0ard
    $PY scripts/local_stack/challenges/challenge_stack.py config  --app An0nB0ard --arm guarded --out <cfg.json>
    $PY scripts/local_stack/challenges/challenge_stack.py up       --app An0nB0ard --arm guarded --config <cfg.json> --work <private dir> --v5 double
    $PY scripts/local_stack/challenges/challenge_stack.py status      --work <private dir>
    $PY scripts/local_stack/challenges/challenge_stack.py down        --work <private dir>
    $PY scripts/local_stack/challenges/challenge_stack.py check-clean  --work <private dir>

Defaults: V5 DOUBLE (no model, no GPU) — enough to verify integration and ATTRIBUTION (the double BLOCKs
any request containing the word `evil` and ALLOWs everything else). A real V5.1 needs `--v5 real` and the
GPU hand-off; quality is never measured with the double. `<work>` must be outside the repository.
"""
import argparse
import json
import os
import subprocess
import sys
import time
import secrets

HERE = os.path.dirname(os.path.abspath(__file__))
LOCAL_STACK = os.path.dirname(HERE)
REPO = os.path.dirname(os.path.dirname(LOCAL_STACK))
sys.path[:0] = [HERE, LOCAL_STACK, os.path.join(REPO, "scripts", "gateway_ops"),
                os.path.join(REPO, "data_plane")]

import stack as S              # noqa: E402  — reuse the stack's leaf helpers unchanged
import adapters                # noqa: E402
import static_contract         # noqa: E402

DIRECT_TEMPLATE = os.path.join(HERE, "front", "nginx-direct.conf.template")

# V5.1 + Model 2 (GUARDED_ENFORCE) manifest prepared by Codex. The v5only and guarded arms pin the SAME
# manifest and differ only by mode, so the two firewall arms are the exact V5-only / V5+Model2 contrast.
DEFAULT_MANIFEST = os.path.join(REPO, "reports", "v5", "model2-guarded-2026-11-05",
                                "manifest.EXPERIMENTAL.json")

FASTV5_MANIFEST = os.path.join(REPO, "reports", "v5", "fastv5-2026-11-11", "manifest.EXPERIMENTAL.json")

ARMS = {
    "direct":  {"firewall": "none",    "mode": "V5_ONLY"},
    "v5only":  {"firewall": "cascade", "mode": "V5_ONLY"},
    "fastv5":  {"firewall": "cascade", "mode": "FAST_PATH_V5"},
    "fastv5_guard": {"firewall": "cascade", "mode": "FAST_PATH_V5"},
    "guarded": {"firewall": "cascade", "mode": "CASCADE_ACTIVE"},
    "crs":     {"firewall": "crs",     "mode": "V5_ONLY"},
}

# Shared, fixed front/gateway/CRS/port blocks — identical to scripts/local_stack/stack.example.json so
# every challenge arm shares the exact client-facing surface of the fwlab-notes arms.
BASE_PORTS = {"front_tls": 8443, "front_status": 8444, "gateway": 8080, "guard": 8081,
              "admin": 8090, "v5": 8001}
BASE_FRONT = {"image": "nginx:1.25-alpine", "http2": True, "workers": 2, "max_body": "64k",
              "upstream_keepalive": 16, "upstream_timeout": "10s"}
BASE_GATEWAY = {"body_size_limit": "16m", "v5_timeout_seconds": 3.0, "decision_deadline_seconds": 5.0,
                "max_inflight": 8, "max_waiting": 16}
BASE_CRS = {"image": "owasp/modsecurity-crs:4.25.2-nginx-alpine-202610180210-lts", "port": 8460,
            "blocking_paranoia": 1, "anomaly_inbound": 5, "anomaly_outbound": 4}


# ───────────────────────────── applications repo ─────────────────────────────
def resolve_apps_root(args):
    return os.path.abspath(getattr(args, "apps_root", None)
                           or os.environ.get("FWLAB_APPS_ROOT") or adapters.DEFAULT_APPS_ROOT)


def apps_commit(apps_root):
    proc = subprocess.run(["git", "-C", apps_root, "rev-parse", "HEAD"], capture_output=True, text=True)
    return proc.stdout.strip() if proc.returncode == 0 else None


def check_apps_commit(apps_root, allow_drift):
    commit = apps_commit(apps_root)
    if commit is None:
        raise S.StackError(f"applications repo {apps_root} is not a git checkout")
    if commit != adapters.PINNED_APPS_COMMIT and not allow_drift:
        raise S.StackError(f"applications repo at {commit}, pinned {adapters.PINNED_APPS_COMMIT} "
                           "(use --allow-commit-drift to override and record the drift)")
    return commit


# ───────────────────────────── build & config ─────────────────────────────
def build(args):
    apps_root = resolve_apps_root(args)
    commit = check_apps_commit(apps_root, args.allow_commit_drift)
    names = [args.app] if args.app else list(adapters.APP_NAMES)
    images, pulled = {}, {}
    for name in names:
        ad = adapters.ADAPTERS[name]
        ctx = adapters.context_dir(apps_root, ad)
        cmd = ["build", "-t", ad["image"]]
        if ad["build"]["dockerfile"]:
            cmd += ["-f", ad["build"]["dockerfile"]]
        cmd += [ctx]
        print(f"building {ad['image']} from {S.rel(ctx) if ctx.startswith(REPO) else ctx} ...",
              file=sys.stderr)
        S.docker(*cmd)
        images[name] = S.image_id(ad["image"])
        for sc in ad["sidecars"]:
            if not S.image_id(sc["image"]):
                print(f"pulling sidecar image {sc['image']} ...", file=sys.stderr)
                S.docker("pull", sc["image"])
            pulled[sc["image"]] = S.image_id(sc["image"])
    print(json.dumps({"apps_root": apps_root, "apps_commit": commit, "pinned_commit": adapters.PINNED_APPS_COMMIT,
                      "commit_matches_pin": commit == adapters.PINNED_APPS_COMMIT,
                      "images": images, "sidecar_images": pulled}, indent=2, sort_keys=True))
    return 0


def config(args):
    ad = adapters.ADAPTERS[args.app]
    iid = S.image_id(ad["image"])
    if not iid:
        raise S.StackError(f"image {ad['image']} not built; run `build --app {args.app}` first")
    arm = ARMS[args.arm]
    if args.arm in ("fastv5", "fastv5_guard"):
        args.fast_path = True
    if args.fast_path and args.arm not in ("guarded", "fastv5", "fastv5_guard"):
        raise S.StackError("--fast-path is only valid with --arm guarded or fastv5")
    if not 0 <= args.audit_sample_rate <= 1 or (not args.fast_path and args.audit_sample_rate != 0):
        raise S.StackError("--audit-sample-rate must be 0..1 and requires --fast-path")
    manifest_path = os.path.abspath(args.manifest) if args.manifest else (FASTV5_MANIFEST if args.arm in ("fastv5", "fastv5_guard") else DEFAULT_MANIFEST)
    if not os.path.exists(manifest_path):
        raise S.StackError(f"manifest not found: {manifest_path}")
    front_id = S.image_id(BASE_FRONT["image"])
    crs_id = S.image_id(BASE_CRS["image"])
    if not front_id:
        raise S.StackError(f"front image {BASE_FRONT['image']} not present")
    cfg = {
        "schema": S.CONFIG_SCHEMA, "mode": arm["mode"],
        "manifest": {"path": S.rel(manifest_path), "sha256": S.sha256_file(manifest_path)},
        "ports": dict(BASE_PORTS),
        "front": dict(BASE_FRONT, image_id=front_id),
        "app": {"image": ad["image"], "image_id": iid, "port": ad["internal_port"],
                "hostname": ad["hostname"]},
        "gateway": dict(BASE_GATEWAY), "fast_path": None,
        "crs": dict(BASE_CRS, image_id=crs_id) if crs_id else None,
    }
    if cfg["crs"] is None:
        del cfg["crs"]
    if args.fast_path:
        asset = adapters.FAST_PATH_STATIC[args.app]
        asset_on_disk = os.path.join(adapters.web_dir(adapters.DEFAULT_APPS_ROOT),
                                     ad["source_subdir"], asset.lstrip("/"))
        # The commit check in `up` binds the app source; the policy itself binds
        # the hostname and exact asset path, with no query or other header.
        if not os.path.isfile(asset_on_disk):
            # Some apps put the runtime source under a `challenge/` directory.
            asset_on_disk = os.path.join(adapters.web_dir(adapters.DEFAULT_APPS_ROOT),
                                         ad["source_subdir"], "challenge", asset.lstrip("/"))
        if not os.path.isfile(asset_on_disk):
            raise S.StackError(f"Fast Path asset absent at pinned app commit: {asset}")
        policy_doc = {
            "schema": S.FP.POLICY_SCHEMA,
            "policy_id": f"sec-challenges-{args.app}-static-v1",
            "status": "PROPOSED", "canonical_contract": S.FP.CANONICAL_CONTRACT_ID,
            "http_versions": ["HTTP/1.1"],
            "rules": [{"id": "exact-static-asset", "methods": ["GET"],
                       "path": asset.strip("/").split("/"), "query": {},
                       "required_query": [],
                       "headers": {"host": {"type": "enum", "values": [ad["hostname"]]}}}],
        }
        if args.arm in ("fastv5", "fastv5_guard"):
            policy_doc = static_contract.policy(args.app)
        policy = S.FP.parse_policy(policy_doc)
        policy_path = args.out + ".fast-path.json"
        with open(policy_path, "x", encoding="utf-8") as fh:
            json.dump(policy_doc, fh, indent=2)
            fh.write("\n")
        cfg["fast_path"] = {"policy_file": S.rel(os.path.abspath(policy_path)),
                            "policy_sha256": policy.sha256,
                            "application_contract_ref":
                                f"sec-challenges@{adapters.PINNED_APPS_COMMIT}:Web/{args.app}:{asset}",
                            "audit_sample_rate": args.audit_sample_rate}
        if args.arm in ("fastv5", "fastv5_guard"):
            cfg["fast_path"]["application_contract_ref"] = static_contract.contract_ref(args.app, image_id=iid)
    if args.arm == "fastv5_guard" and args.app == "Inf3ct":
        ref = cfg["fast_path"]["application_contract_ref"]
        guard_doc = {"schema": "request-header-sink-guard/v2", "policy_id": "inf3ct-header-jinja-v2",
                     "application_contract_ref": ref, "methods": ["POST"], "sink": "jinja_template_headers"}
        gp = args.out + ".request-guard.json"
        with open(gp, "x", encoding="utf-8") as gh:
            json.dump(guard_doc, gh, indent=2); gh.write("\n")
        cfg["request_guard"] = {"policy_file": S.rel(os.path.abspath(gp)),
                                "policy_sha256": S.sha256_file(gp), "application_contract_ref": ref}
    with open(args.out, "x", encoding="utf-8") as fh:
        json.dump(cfg, fh, indent=2)
        fh.write("\n")
    v5 = "real" if args.arm in ("v5only", "fastv5", "fastv5_guard", "guarded") else "double"
    up_cmd = (f"challenge_stack.py up --app {args.app} --arm {args.arm} --config {args.out} "
              f"--work <private dir> --v5 double   # integration/attribution with the double")
    print(json.dumps({"written": args.out, "app": args.app, "arm": args.arm,
                      "firewall": arm["firewall"], "mode": arm["mode"],
                      "fast_path": cfg["fast_path"],
                      "manifest_sha256": cfg["manifest"]["sha256"],
                      "quality_run_needs": f"--v5 real + GPU hand-off (arm {args.arm})" if v5 == "real"
                      else "no model (direct/crs arm)", "next": up_cmd}, indent=2))
    return 0


# ───────────────────────────── application launch ─────────────────────────────
def _mysql_ready(container):
    proc = subprocess.run(["docker", "exec", container, "mysqladmin", "ping", "-h", "127.0.0.1",
                           "--silent"], capture_output=True)
    return proc.returncode == 0


def start_challenge_app(state, cfg, ad, args, run_id, apps_root):
    net = S.free_subnet()
    network = f"fwlab-chal-{run_id}"
    label = f"fwlab.stack.run={run_id}"
    S.docker("network", "create", "--internal", "--subnet", str(net), "--label", label, network)
    state.add({"name": "app-network", "kind": "network", "network": network, "label": label})
    web = adapters.web_dir(apps_root)

    db_host = None
    for sc in ad["sidecars"]:
        sc_ip = str(net.network_address + sc["ip_offset"])
        sc_name = f"fwlab-chal-{run_id}-{sc['name']}"
        argv = ["run", "-d", "--name", sc_name, "--label", label, "--network", network, "--ip", sc_ip]
        argv += sc["run_opts"]
        for k, v in sc["env"].items():
            argv += ["-e", f"{k}={v}"]
        for src, dst in sc["mounts"]:
            argv += ["-v", f"{os.path.join(web, src)}:{dst}"]
        argv += [sc["image"]]
        S.docker(*argv)
        state.add({"name": sc["name"], "kind": "container", "container": sc_name, "label": label,
                   "ip": sc_ip, "network": network})
        if sc["ready"]["kind"] == "mysql_ping":
            S.wait_until(lambda n=sc_name: _mysql_ready(n), 120, f"sidecar {sc['name']} (mysql)")
        db_host = sc_name       # user-defined network: reachable by container name via embedded DNS

    app_ip = str(net.network_address + 10)
    app_name = f"fwlab-chal-{run_id}-app"
    # Only the literal token {db_host} is substituted; other values may contain braces (e.g. the FLAG).
    env = {k: v.replace("{db_host}", db_host or "") for k, v in ad["env"].items()}
    argv = ["run", "-d", "--name", app_name, "--label", label, "--network", network, "--ip", app_ip]
    argv += ad["run_opts"]
    for k, v in env.items():
        argv += ["-e", f"{k}={v}"]
    argv += [cfg["app"]["image"]]
    S.docker(*argv)
    state.add({"name": "app", "kind": "container", "container": app_name, "label": label, "ip": app_ip,
               "port": ad["internal_port"], "network": network})

    port = ad["internal_port"]
    ready = ad["ready_path"]
    S.wait_until(lambda: S.http_get(f"http://{app_ip}:{port}{ready}", timeout=1)[0] == 200, 60,
                 f"challenge app {args.app}")
    routes = S.docker("exec", app_name, "cat", "/proc/net/route")
    if any(line.split()[1] == "00000000" for line in routes.splitlines()[1:] if line.strip()):
        raise S.StackError("app container has a default route: isolation broken")
    return app_ip, db_host


def render_direct_front(cfg, upstream):
    with open(DIRECT_TEMPLATE, encoding="utf-8") as fh:
        template = fh.read()
    front, ports = cfg["front"], cfg["ports"]
    values = {"WORKERS": str(front["workers"]), "UPSTREAM": upstream,
              "UPSTREAM_KEEPALIVE": str(front["upstream_keepalive"]), "TLS_PORT": str(ports["front_tls"]),
              "HTTP2": "on" if front["http2"] else "off", "SERVER_NAME": cfg["app"]["hostname"],
              "MAX_BODY": front["max_body"], "STATUS_PORT": str(ports["front_status"]),
              "UPSTREAM_TIMEOUT": front["upstream_timeout"]}
    import re
    used = set(re.findall(r"\$\{([A-Z0-9_]+)\}", template))
    if used != set(values):
        raise S.StackError(f"direct front template variables {sorted(used ^ set(values))}")
    return re.sub(r"\$\{([A-Z0-9_]+)\}", lambda m: values[m.group(1)], template)


def start_front_direct(state, cfg, run_id, pki, app_ip, app_port):
    import socket
    front_dir = os.path.join(state.work, "front")
    logs = os.path.join(front_dir, "logs")
    os.makedirs(logs, exist_ok=True)
    conf = os.path.join(front_dir, "nginx.conf")
    with open(conf, "w", encoding="utf-8") as fh:
        fh.write(render_direct_front(cfg, f"{app_ip}:{app_port}"))
    pki_mount = os.path.join(front_dir, "pki")
    os.makedirs(pki_mount, mode=0o700, exist_ok=True)
    for src, dst in ((pki["server_cert"], "server.crt"), (pki["server_key"], "server.key")):
        with open(src, "rb") as a, open(os.path.join(pki_mount, dst), "wb") as b:
            b.write(a.read())
        os.chmod(os.path.join(pki_mount, dst), 0o600)
    name = f"fwlab-chal-{run_id}-front"
    label = f"fwlab.stack.run={run_id}"
    uid = f"{os.getuid()}:{os.getgid()}"
    S.docker("run", "-d", "--name", name, "--label", label, "--network", "host", "--read-only",
             "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "64",
             "--memory", "128m", "--user", uid, "--tmpfs", "/tmp:rw,nosuid,noexec,size=32m",
             "-v", f"{conf}:/etc/fwlab/nginx.conf:ro", "-v", f"{pki_mount}:/pki:ro", "-v", f"{logs}:/logs:rw",
             "--entrypoint", "nginx", cfg["front"]["image"], "-c", "/etc/fwlab/nginx.conf", "-g", "daemon off;")
    state.add({"name": "front", "kind": "container", "container": name, "label": label})
    status_port = cfg["ports"]["front_status"]
    S.wait_until(lambda: S.http_get(f"http://127.0.0.1:{status_port}/__front/ready", timeout=1)[0] == 200,
                 20, "front")
    ctx = S.tls_context(pki["ca_cert"], ("h2", "http/1.1"))
    with socket.create_connection(("127.0.0.1", cfg["ports"]["front_tls"]), timeout=3) as raw:
        with ctx.wrap_socket(raw, server_hostname=cfg["app"]["hostname"]) as tls:
            negotiated = tls.selected_alpn_protocol()
            version = tls.version()
    expect = "h2" if cfg["front"]["http2"] else "http/1.1"
    if negotiated != expect:
        raise S.StackError(f"front ALPN {negotiated!r}, expected {expect!r}")
    return {"conf": conf, "conf_sha256": S.sha256_file(conf), "alpn": negotiated, "tls_version": version}


# ───────────────────────────── preflight / identity ─────────────────────────────
def preflight(cfg, args, apps_root):
    S.preflight(cfg, args)                     # ports, front/app/crs image pins, gpu gate, work dir
    for name, ad in [(args.app, adapters.ADAPTERS[args.app])]:
        for sc in ad["sidecars"]:
            if not S.image_id(sc["image"]):
                raise S.StackError(f"sidecar image {sc['image']} not present; run `build --app {name}`")
    check_apps_commit(apps_root, args.allow_commit_drift)


def challenge_identity(cfg, ad, args, apps_root, commit, manifest_path, manifest, front):
    df = ad["build"]["dockerfile"]
    return {"schema": "firewall-challenge-stack-identity/v1", "app": args.app, "arm": args.arm,
            "firewall": args.firewall, "mode": cfg["mode"], "v5": args.v5 if args.firewall == "cascade" else None,
            "fast_path": cfg["fast_path"],
            "applications_repo": {"root": apps_root, "commit": commit,
                                  "pinned_commit": adapters.PINNED_APPS_COMMIT,
                                  "commit_matches_pin": commit == adapters.PINNED_APPS_COMMIT,
                                  "source_subdir": os.path.join(adapters.WEB_SUBDIR, ad["source_subdir"])},
            "manifest": {"path": S.rel(manifest_path), "sha256": S.sha256_file(manifest_path),
                         "manifest_id": manifest.get("manifest_id"), "status": manifest.get("status")},
            "app_image": {"image": cfg["app"]["image"], "image_id": cfg["app"]["image_id"],
                          "internal_port": ad["internal_port"], "hostname": ad["hostname"],
                          "adapter_dockerfile": S.rel(df) if df else "application's own Dockerfile"},
            "sidecars": [{"name": sc["name"], "image": sc["image"], "image_id": S.image_id(sc["image"])}
                         for sc in ad["sidecars"]],
            "crs": None if args.firewall != "crs" else {"image": cfg["crs"]["image"]},
            "front": {"image": cfg["front"]["image"], "image_id": cfg["front"]["image_id"],
                      "arm_template": "nginx-direct.conf.template" if args.firewall == "none"
                      else "stack front (gateway upstream)", "conf_sha256": front["conf_sha256"],
                      "alpn": front["alpn"], "tls_version": front["tls_version"]},
            "adapters_source_sha256": S.sha256_file(adapters.__file__),
            "challenge_stack_source_sha256": S.sha256_file(os.path.abspath(__file__)),
            "vuln_class": ad["vuln_class"], "effect_observable": ad["effect_observable"]}


# ───────────────────────────── up ─────────────────────────────
def up(args):
    ad = adapters.ADAPTERS[args.app]
    arm = ARMS[args.arm]
    args.firewall = arm["firewall"]
    apps_root = resolve_apps_root(args)
    cfg = S.load_config(args.config)
    if cfg["app"]["image"] != ad["image"]:
        raise S.StackError(f"config app image {cfg['app']['image']} != adapter image {ad['image']} "
                           f"for {args.app}")
    if cfg["mode"] != arm["mode"]:
        raise S.StackError(f"config mode {cfg['mode']} != arm {args.arm} mode {arm['mode']}")
    if cfg["fast_path"] is not None:
        expected = f"sec-challenges@{adapters.PINNED_APPS_COMMIT}:Web/{args.app}:{adapters.FAST_PATH_STATIC[args.app]}"
        if args.arm in ("fastv5", "fastv5_guard"):
            expected = static_contract.contract_ref(args.app, apps_root, cfg["app"]["image_id"])
            loaded_policy = S.FP.load_policy(S.resolve(cfg["fast_path"]["policy_file"]))
            expected_policy = S.FP.parse_policy(static_contract.policy(args.app, apps_root))
            if loaded_policy.sha256 != expected_policy.sha256:
                raise S.StackError("Fast Path policy differs from audited static contract")
        if args.arm not in ("guarded", "fastv5", "fastv5_guard") or cfg["fast_path"]["application_contract_ref"] != expected:
            raise S.StackError("Fast Path contract does not match the pinned application")
    if args.app != "Inf3ct" and cfg.get("request_guard") is not None:
        raise S.StackError("request guard only contracted for Inf3ct")
    if args.arm != "fastv5_guard" and cfg.get("request_guard") is not None:
        raise S.StackError("request guard must be explicit in the arm name")
    if args.arm == "fastv5_guard" and args.app == "Inf3ct" and cfg.get("request_guard") is None:
        raise S.StackError("Inf3ct fastv5_guard requires its pinned header guard")
    if args.arm == "fastv5_guard" and args.app == "Inf3ct":
        import request_guard as RG
        gp = cfg["request_guard"]
        guard_policy = RG.load(S.resolve(gp["policy_file"]),gp["policy_sha256"],gp["application_contract_ref"])
        if guard_policy.schema != RG.SCHEMA:
            raise S.StackError("candidate requires current header sink guard; regenerate config")
    manifest_path, manifest = S.check_manifest(cfg)
    preflight(cfg, args, apps_root)
    commit = apps_commit(apps_root)

    state = S.State(args.work)
    if os.path.exists(state.path):
        raise S.StackError(f"{state.path} exists: run `down` and use a new work directory")
    os.makedirs(os.path.join(state.work, "logs"), exist_ok=True)
    os.chmod(state.work, 0o700)
    run_id = time.strftime("%Y%m%dT%H%M%S") + "-" + secrets.token_hex(3)
    state.doc = {"schema": S.STATE_SCHEMA, "run_id": run_id, "created_utc": time.time(),
                 "seed": secrets.token_hex(32), "config_path": os.path.abspath(args.config),
                 "config_sha256": S.sha256_file(args.config), "mode": cfg["mode"], "v5": args.v5,
                 "firewall": args.firewall, "upstream": f"challenge:{args.app}", "arm": args.arm,
                 "app": args.app, "apps_root": apps_root, "apps_commit": commit,
                 "components": [], "ready": False}
    state.save()
    try:
        pki = S.make_pki(os.path.join(state.work, "pki"), cfg["app"]["hostname"])
        app_ip, db_host = start_challenge_app(state, cfg, ad, args, run_id, apps_root)
        crs = None
        if args.firewall == "cascade":
            v5_url = S.start_v5(state, cfg, args, manifest_path)
            gateway_config = S.start_gateway(state, cfg, manifest_path, app_ip, v5_url)
            front = S.start_front(state, cfg, run_id, pki)
        elif args.firewall == "crs":
            v5_url = gateway_config = None
            crs = S.start_crs(state, cfg, app_ip, run_id)
            front = S.start_front(state, cfg, run_id, pki, upstream_port=cfg["crs"]["port"])
        else:   # direct
            v5_url = gateway_config = None
            front = start_front_direct(state, cfg, run_id, pki, app_ip, ad["internal_port"])
    except BaseException:
        state.save()
        print("up failed; stopping what was started", file=sys.stderr)
        S.down_state(state)
        raise

    ports = cfg["ports"]
    identity = challenge_identity(cfg, ad, args, apps_root, commit, manifest_path, manifest, front)
    with open(os.path.join(state.work, "challenge-identity.json"), "w", encoding="utf-8") as fh:
        json.dump(identity, fh, indent=2, sort_keys=True)
    state.doc.update(ready=True, firewall=args.firewall, crs=crs, ports=ports,
                     hostname=cfg["app"]["hostname"], pki=pki, app_ip=app_ip, db_host=db_host,
                     gateway_config=gateway_config,
                     gateway_decisions=os.path.join(state.work, "gateway", "decisions.jsonl") if gateway_config else None,
                     app_console_log=os.path.join(state.work, "logs", "app.console.log"),
                     front_access_log=os.path.join(state.work, "front", "logs", "front-access.jsonl"),
                     identity=identity, endpoints={
                         "front_tls": f"https://{cfg['app']['hostname']}:{ports['front_tls']}",
                         "front_status": f"http://127.0.0.1:{ports['front_status']}",
                         "gateway_plain": f"http://127.0.0.1:{ports['gateway']}" if gateway_config else None,
                         "gateway_admin": f"http://127.0.0.1:{ports['admin']}" if gateway_config else None,
                         "v5": v5_url, "app_direct": f"http://{app_ip}:{ad['internal_port']}",
                         "crs": f"http://127.0.0.1:{cfg['crs']['port']}" if crs else None})
    state.save()
    print(json.dumps({"ready": True, "app": args.app, "arm": args.arm, "firewall": args.firewall,
                      "work": state.work, "apps_commit": commit,
                      "commit_matches_pin": commit == adapters.PINNED_APPS_COMMIT,
                      "endpoints": state.doc["endpoints"]}, indent=2))
    return 0


# ───────────────────────────── main ─────────────────────────────
def add_apps_root(p):
    p.add_argument("--apps-root", default=None,
                   help="applications repo root (default: $FWLAB_APPS_ROOT or the pinned path)")
    p.add_argument("--allow-commit-drift", action="store_true",
                   help="allow the applications repo to differ from the pinned commit (recorded)")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    p_build = sub.add_parser("build", help="build the application image(s) and pull sidecar images")
    p_build.add_argument("--app", choices=adapters.APP_NAMES, default=None, help="default: all six")
    add_apps_root(p_build)

    p_cfg = sub.add_parser("config", help="write a stack config for one application and arm")
    p_cfg.add_argument("--app", choices=adapters.APP_NAMES, required=True)
    p_cfg.add_argument("--arm", choices=tuple(ARMS), required=True)
    p_cfg.add_argument("--manifest", default=None, help=f"default: {S.rel(DEFAULT_MANIFEST)}")
    p_cfg.add_argument("--fast-path", action="store_true",
                       help="enable a lab-only exact static-resource FAST_ALLOW policy")
    p_cfg.add_argument("--audit-sample-rate", type=float, default=0.0,
                       help="Fast Path V5 audit sampling, fixed in the pinned config (default: 0)")
    p_cfg.add_argument("--out", required=True)

    p_up = sub.add_parser("up")
    p_up.add_argument("--app", choices=adapters.APP_NAMES, required=True)
    p_up.add_argument("--arm", choices=tuple(ARMS), required=True)
    p_up.add_argument("--config", required=True)
    p_up.add_argument("--work", required=True)
    p_up.add_argument("--v5", default="double", help="double (default) | real | url:<http://...>")
    p_up.add_argument("--effect-routes", action="store_true", help="accepted for parity; unused (the "
                      "challenge apps are themselves the vulnerable surface)")
    p_up.add_argument("--log-targets", action="store_true", help="accepted for parity; unused")
    p_up.add_argument("--upstream", default="app", help=argparse.SUPPRESS)
    add_apps_root(p_up)

    for name in ("down", "status", "check-clean"):
        sub.add_parser(name).add_argument("--work", required=True)

    args = parser.parse_args(argv)
    if args.command == "up" and args.v5 not in ("double", "real") and not args.v5.startswith("url:"):
        parser.error("--v5 must be double, real or url:<url>")
    try:
        if args.command == "build":
            return build(args)
        if args.command == "config":
            return config(args)
        if args.command == "up":
            return up(args)
        if args.command == "down":
            return S.down(args)
        if args.command == "status":
            return S.status(args)
        if args.command == "check-clean":
            return S.check_clean(args)
    except S.StackError as exc:
        print(f"challenge-stack: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
