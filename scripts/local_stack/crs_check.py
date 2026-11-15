"""
ModSecurity + OWASP CRS comparator arm: reproducibility and attribution. NOT AN EVALUATION.

    .venv-dataplane/bin/python -B scripts/local_stack/crs_check.py --config scripts/local_stack/stack.example.json --out <new evidence dir> --work <new private dir>

Starts the stack with `--firewall crs --effect-routes`: the same TLS/HTTP2 front and the same application
as the cascade arm, with CRS (image, paranoia level and anomaly thresholds pinned in the config) in place
of the gateway. It runs the scenarios of app_check.py (sessions/CSRF, JWT API, effect smoke) through
`direct`, `tls_h1` and `tls_h2`, and records, per request, which layer answered and, for a CRS block, the
rule ids of its audit log.

What CRS blocks is RECORDED, not expected: these requests were authored in this repository for the
mechanism checks, so they are known DEV examples and say nothing about CRS's rates. A row passes when
its attribution is complete and consistent (a CRS block has exactly one interrupted audit entry and no
application line; an application answer has its marker). Requests CRS forwards must get the same
application answer as on the direct path. The effect oracle is recorded for every forwarded effect
request.
"""
import argparse
import json
import os
import sys
import time
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import app_check as A            # noqa: E402
import stack as S                # noqa: E402

PATHS = ("direct", "tls_h1", "tls_h2")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--work", required=True)
    args = parser.parse_args(argv)
    if os.path.exists(args.out) or os.path.exists(args.work):
        sys.exit("refusing to reuse --out or --work")
    os.makedirs(args.out)
    stack_work = os.path.join(args.work, "stack")
    if S.main(["up", "--config", args.config, "--work", stack_work, "--firewall", "crs", "--effect-routes"]) != 0:
        return 2
    try:
        state = S.State(stack_work).load()
        state["ports_app"] = state["endpoints"]["app_direct"].rsplit(":", 1)[1]
        lab = A.Lab(state["seed"])
        rows = []
        for path in PATHS:
            rows.extend(A.run_path(path, state, None, lab, True, observe_only=True))
        identity = state["identity"]
    finally:
        S.main(["down", "--work", stack_work])
    st = S.State(stack_work)
    st.load()
    clean = S.clean_report(st)
    # Direct rows keep their expectations (the application alone); effect oracles on direct rows too.
    for row in rows:
        if row["path"] == "direct" and row["step"] in A.EFFECT_EXPECT:
            effect = row.get("effect")
            row["passed"] &= effect is not None and any(effect.values()) == A.EFFECT_EXPECT[row["step"]]
    problems = A.cross_path(rows)
    failed = [r for r in rows if not r["passed"]]
    blocked = {}
    for r in rows:
        if r["observed"][1] == "firewall":
            blocked.setdefault(r["step"], {})[r["path"]] = r["waf_rules"]
    summary = {p: {"requests": sum(r["path"] == p for r in rows),
                   "by_layer": dict(Counter(r["observed"][1] for r in rows if r["path"] == p))} for p in PATHS}
    effects = {r["step"] + "@" + r["path"]: ("blocked_by_crs" if r["observed"][1] == "firewall" else r.get("effect"))
               for r in rows if r["step"] in A.EFFECT_EXPECT}
    passed = not failed and not problems and clean["clean"]
    doc = {"schema": "firewall-local-stack-crs-check/v1", "created_utc": time.time(),
           "kind": "COMPARATOR_MECHANISM_CHECK", "evaluation": "NONE: authored DEV mechanism requests",
           "identity": identity, "passed": passed, "summary": summary, "crs_blocked_steps": blocked,
           "effects": effects, "cross_path_problems": problems,
           "failed_steps": [{"path": r["path"], "step": r["step"], "observed": r["observed"],
                             "marker_consistent": r["marker_consistent"]} for r in failed],
           "rows": rows, "clean_after": clean}
    with open(os.path.join(args.out, "CRS_CHECK.json"), "x", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=2, sort_keys=True)
        fh.write("\n")
    print(json.dumps({"passed": passed, "summary": summary, "crs_blocked_steps": blocked,
                      "cross_path_problems": problems, "failed": doc["failed_steps"], "clean": clean["clean"]},
                     indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
