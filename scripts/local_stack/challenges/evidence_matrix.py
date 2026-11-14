"""
Build the evidence matrix (Markdown) from the per-run smoke JSONs of the challenge-app integration.

    .venv-dataplane/bin/python scripts/local_stack/challenges/evidence_matrix.py \
        --evidence reports/v5/challenge-apps-integration-2026-11-05/evidence \
        --out reports/v5/challenge-apps-integration-2026-11-05/MATRIX.md

It reports, from the sealed smoke results only (no new runs): the 6x4 app x arm pass/fail matrix, the
failing checks with their cause, and a separate table of large (>64 KiB) responses with their size and
whether the cascade gateway capped them at 502. It changes nothing in the stack.
"""
import argparse
import glob
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [HERE]
import adapters  # noqa: E402

ARMS = ("direct", "v5only", "guarded", "crs")


def load(evidence):
    runs = {}
    for f in sorted(glob.glob(os.path.join(evidence, "*", "smoke-*.json"))):
        d = json.load(open(f))
        runs[(d["app"], d["arm"])] = d
    return runs


def cell(d):
    if d is None:
        return "—"
    p = sum(1 for c in d["checks"] if c["pass"])
    mark = "✅" if d["pass"] else "❌"
    return f"{mark} {p}/{len(d['checks'])}"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--evidence", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--gateway-limit", choices=("64k", "16m"), default="64k")
    args = ap.parse_args(argv)
    runs = load(args.evidence)

    lines = [f"# Evidence matrix — challenge-app integration (V5 double, gateway {args.gateway_limit})", "",
             "Generated from the sealed smoke JSONs by "
             "`scripts/local_stack/challenges/evidence_matrix.py`. V5 DOUBLE only "
             "(BLOCK on the literal word `evil`): integration and attribution, not quality. No real V5.1, "
             f"attack campaign, load or latency here; the gateway limit was fixed at {args.gateway_limit} before the run.", ""]

    total = len(runs)
    passed = sum(1 for d in runs.values() if d["pass"])
    commit_ok = all(d.get("commit_matches_pin") for d in runs.values()) if runs else False
    lines += [f"**{passed}/{total} runs pass.** apps commit matches pin for every run: "
              f"{'yes' if commit_ok else 'NO'}.", "",
              "## App × arm", "", "| App | direct | v5only | guarded | crs |", "|---|---|---|---|---|"]
    for app in adapters.APP_NAMES:
        row = [cell(runs.get((app, arm))) for arm in ARMS]
        lines.append(f"| {app} | " + " | ".join(row) + " |")
    lines += ["", "✅ = all checks pass. Each run checks: startup, benign flows + reception, the "
              "no-server-session fact, state reset, block attribution for the arm, large-response handling "
              "(where an asset > 64 KiB exists), teardown and check-clean.", ""]

    # failures with cause
    fails = [(app, arm, d) for (app, arm), d in sorted(runs.items()) if not d["pass"]]
    lines += ["## Failures and causes", ""]
    if not fails:
        lines.append("None — every run passed every check.")
    else:
        lines.append("| App | arm | failing check | cause |")
        lines.append("|---|---|---|---|")
        for app, arm, d in fails:
            for c in d["checks"]:
                if not c["pass"]:
                    cause = {k: v for k, v in c.items()
                             if k not in ("check", "pass", "app_new_console", "note")}
                    cause_s = json.dumps(cause)[:160] if cause else (c.get("note") or "")
                    lines.append(f"| {app} | {arm} | {c['check']} | `{cause_s}` |")
    lines.append("")

    # large responses
    lines += ["## Large-response delivery", "",
              f"The cascade gateway uses `body_size_limit={args.gateway_limit}` in both directions; the front "
              "keeps its 64 KiB request-body cap. The CRS comparator and the direct arm do not use the "
              "cascade response limit.", "",
              "| App | arm | asset | size (B) | status | capped 502? |", "|---|---|---|---|---|---|"]
    any_large = False
    for (app, arm), d in sorted(runs.items()):
        for lr in d.get("large_responses", []):
            any_large = True
            lines.append(f"| {app} | {arm} | `{lr['target']}` | {lr['asset_bytes']} | {lr['status']} | "
                         f"{'yes' if lr['capped_502'] else 'no'} |")
    if not any_large:
        lines.append("| — | — | — | — | — | — |")
    lines.append("")

    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print(json.dumps({"runs": total, "passed": passed, "failures": len(fails),
                      "commit_matches_pin_all": commit_ok, "out": args.out}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
