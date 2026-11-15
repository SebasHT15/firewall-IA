"""
What a candidate's V5 says about plain benign routes, with its reason. A post-hoc diagnostic.

    .venv-dataplane/bin/python scripts/gateway_ops/v5_route_probe.py --manifest <v2 manifest> \
        --out <new file> --work <private directory>

It exists because an audit showed a candidate blocking a health route. The routes were written after that
was seen, so this describes the extent of one observation. It is not an evaluation and it estimates no
rate. It asks the V5 API directly and sends nothing to any application. The cases come from no dataset
and must not be fed back to training and then read as independent.
"""
import argparse
import collections
import json
import os
import sys
import types
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import candidate_walkthrough as W  # noqa: E402
import gpu_gate                    # noqa: E402
import live_stack as L             # noqa: E402

FIXTURE = ("/healthz", "/status?page=1")
HEALTH_NAMES = ("/health", "/healthcheck", "/ready", "/readyz", "/live", "/livez", "/ping", "/status",
                "/metrics", "/version")
LAB_APP_SURFACE = ("/", "/products", "/products?category=books&page=2", "/products/3", "/search?q=lamp",
                   "/login", "/profile", "/cart", "/static/app.css", "/api/products", "/api/products/3",
                   "/api/me")


def canonical_get(target):
    return f"GET {target} HTTP/1.1\n"


def classify(url, text):
    request = urllib.request.Request(url + "/classify", method="POST",
                                     data=json.dumps({"canonical_request": text}).encode("utf-8"),
                                     headers={"Content-Type": "application/json"})
    with L.OPENER.open(request, timeout=10.0) as response:
        return json.loads(response.read())


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--work", required=True)
    args = parser.parse_args(argv)
    problem = gpu_gate.refusal()
    if problem:
        print(f"REFUSED: {problem}", flush=True)
        return 4
    os.makedirs(args.work, exist_ok=True)
    groups = (("fast_path_fixture", FIXTURE), ("health_names", HEALTH_NAMES),
              ("lab_app_surface_read_from_its_code", LAB_APP_SURFACE))
    service = W.V5Service(types.SimpleNamespace(doubles=False, manifest=args.manifest, work=args.work))
    service.start()
    rows = []
    try:
        service.wait()
        for group, targets in groups:
            for target in targets:
                answer = classify(service.url, canonical_get(target))
                rows.append({"group": group, "target": target,
                             **{k: answer.get(k) for k in ("status", "decision", "reason", "invalid_reason")}})
                print(rows[-1], flush=True)
    finally:
        service.stop()
    document = {"schema": "firewall-v5-route-probe/v1", "manifest": args.manifest,
                "status": "POST_HOC_DIAGNOSTIC_NOT_AN_EVALUATION",
                "note": "Written after an audit showed a blocked health route. Describes extent, estimates no "
                        "rate. Direct API, no application contacted.",
                "decisions": dict(collections.Counter(f"{r['group']}:{r['decision']}" for r in rows)),
                "rows": rows}
    with open(args.out, "x", encoding="utf-8") as fh:
        json.dump(document, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
