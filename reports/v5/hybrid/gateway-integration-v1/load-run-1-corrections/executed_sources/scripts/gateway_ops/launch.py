"""
Validate a cascade gateway configuration and start mitmdump with it.

    .venv-dataplane/bin/python scripts/gateway_ops/launch.py --config <gateway.yaml> --check
    .venv-dataplane/bin/python scripts/gateway_ops/launch.py --config <gateway.yaml> --print
    .venv-dataplane/bin/python scripts/gateway_ops/launch.py --config <gateway.yaml>

`--check` validates offline and exits: strict configuration, manifest, Model 2 artifact and policy
bytes, Fast Path activation, enablement for the mode and profile, and that the worker interpreters
exist. It does not contact V5 and starts nothing, so it is safe while the GPU belongs to someone else.

The mitmproxy options come from `gateway_framing.launch_options`, the same table
`profile_problems` checks, so the gateway cannot be started outside the tested profile by this
launcher. Proxy variables are removed from the environment: the gateway calls local services and must
never reach them through itself.
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(REPO, "data_plane"))

import cascade as C               # noqa: E402
import cascade_manifest as CM     # noqa: E402
import gateway_framing as GF      # noqa: E402

MITMDUMP = os.path.join(REPO, ".venv-dataplane", "bin", "mitmdump")
ADDON = os.path.join(REPO, "data_plane", "cascade_addon.py")
CONFIG_ENV = "FIREWALL_CASCADE_CONFIG"
_PROXY_VARS = ("http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY",
               "no_proxy", "NO_PROXY")


def mitmdump_argv(cfg, extra=()) -> list:
    egress = cfg.framing.egress
    if cfg.mode in CM.AUTHORITATIVE_MODES:
        target = f"reverse:http://127.0.0.1:{egress.listen_port}"
    else:
        # V4_ONLY and OBSERVE reach the upstream directly: no cascade component is in V4's path.
        target = f"reverse:http://{egress.upstream_host}:{egress.upstream_port}"
    argv = [MITMDUMP, "-s", ADDON, "--listen-host", cfg.listen_host, "-p", str(cfg.listen_port),
            "--mode", target]
    for name, value in GF.launch_options(body_size_limit=cfg.framing.body_size_limit).items():
        argv += ["--set", f"{name}={value}"]
    return argv + list(extra)


def check(cfg) -> dict:
    """Offline validation. Raises ManifestError; returns what was validated."""
    report = {"mode": cfg.mode, "deployment_profile": cfg.deployment_profile,
              "framing_contract": cfg.framing.contract, "manifest": None, "problems": []}
    if cfg.framing.contract != GF.CONTRACT_ID:
        report["problems"].append("framing_contract_unsupported")
    if cfg.mode == C.V4_ONLY:
        return report
    try:
        manifest = CM.load_manifest(cfg.manifest_path)
        policy = CM.resolve_fast_path_policy(cfg.fast_path)
    except CM.ManifestError as exc:
        report["problems"].append("manifest_unusable")
        report["detail"] = str(exc)
        return report
    report["manifest"] = {"manifest_id": manifest.manifest_id, "status": manifest.status,
                          "sha256": manifest.sha256,
                          "token_budget_B": manifest.canonical.token_budget_B,
                          "model2_policy_status": manifest.model2.policy_status
                          if manifest.model2 else None}
    report["fast_path"] = {"activation": cfg.fast_path.activation,
                           "policy_status": policy.status if policy else None}
    report["problems"].extend(CM.validate_consistency(cfg, manifest))
    for name, python in (("canonical", cfg.canonical.bounds.python), ("model2", cfg.model2.python)):
        if not os.access(python, os.X_OK):
            report["problems"].append(f"{name}_python_missing")
    return report


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--print", action="store_true", dest="print_argv")
    args, extra = parser.parse_known_args(argv)

    cfg = CM.load_gateway_config(args.config)
    report = check(cfg)
    if args.check:
        print(json.dumps(report, indent=2, sort_keys=True))
        return 1 if report["problems"] else 0
    if report["problems"]:
        print(json.dumps(report, indent=2, sort_keys=True), file=sys.stderr)
        # OBSERVE reports and goes on: V4 must keep serving, and only the observation is lost.
        if cfg.mode != C.CASCADE_OBSERVE:
            return 1
    command = mitmdump_argv(cfg, extra)
    if args.print_argv:
        print(" ".join(command))
        return 0
    env = {k: v for k, v in os.environ.items() if k not in _PROXY_VARS}
    env[CONFIG_ENV] = os.path.abspath(args.config)
    os.execve(command[0], command, env)


if __name__ == "__main__":
    sys.exit(main())
