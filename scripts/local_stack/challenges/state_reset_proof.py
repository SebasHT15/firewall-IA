"""
Cross-restart state-reset proof for the two stateful challenge apps. It mutates the app's state, shows
the mutation is visible, tears the stack down, brings a fresh one up and shows the mutation is gone — so
state resets across `up`. INTEGRATION PHASE, V5 double; not a measurement.

    PY=.venv-dataplane/bin/python
    $PY scripts/local_stack/challenges/state_reset_proof.py --app Inf3ct \
        --work1 <dir1> --work2 <dir2> --evidence <evidence dir>

An0nB0ard: POST /addentry a unique marker post, confirm it shows in /messages, restart, confirm /messages
is back to the seeded baseline (marker gone — MySQL re-seeded from members.sql on ephemeral tmpfs).
Inf3ct: POST / a unique marker, confirm it shows in /log, restart, confirm /log is empty of it (in-memory
log reset with the container).
"""
import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path[:0] = [HERE]
import smoke as SM  # noqa: E402

MUT = {
    "Inf3ct":    {"arm": "v5only", "post": ("/", "msg"), "observe": "/log"},
    "An0nB0ard": {"arm": "v5only", "post": ("/addentry", "entry"), "observe": "/messages"},
}


def front_for(work):
    state = json.load(open(os.path.join(work, "stack-state.json")))
    return SM.Front(state)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--app", choices=tuple(MUT), required=True)
    ap.add_argument("--work1", required=True)
    ap.add_argument("--work2", required=True)
    ap.add_argument("--evidence", required=True)
    ap.add_argument("--v5", default="double")
    args = ap.parse_args(argv)
    spec = MUT[args.app]
    arm = spec["arm"]
    os.makedirs(args.evidence, exist_ok=True)
    cfg = os.path.join(args.evidence, f"{args.app}.reset.stack.json")
    if os.path.exists(cfg):
        os.remove(cfg)
    marker = f"FWLABRESET{int(time.time())}"
    res = {"app": args.app, "arm": arm, "marker": marker, "steps": [], "pass": True}

    def step(name, ok, **info):
        res["steps"].append({"step": name, "pass": bool(ok), **info})
        if not ok:
            res["pass"] = False

    SM.run_cli("config", "--app", args.app, "--arm", arm, "--out", cfg)
    # run 1: mutate
    SM.run_cli("up", "--app", args.app, "--arm", arm, "--config", cfg, "--work", args.work1, "--v5", args.v5)
    try:
        f1 = front_for(args.work1)
        path, field = spec["post"]
        fields = {field: marker}
        if path == "/addentry":
            fields["id"] = marker            # unique id so the insert is not a duplicate
        f1.tls_post_form(path, fields)
        time.sleep(0.4)
        s1, b1 = f1.tls("GET", spec["observe"])
        present = marker.encode() in b1
        step("run1: marker visible after mutation", s1 == 200 and present, observe=spec["observe"],
             status=s1, marker_present=present)
    finally:
        SM.run_cli("down", "--work", args.work1)
        SM.run_cli("check-clean", "--work", args.work1)

    # run 2: fresh stack, marker must be gone
    SM.run_cli("up", "--app", args.app, "--arm", arm, "--config", cfg, "--work", args.work2, "--v5", args.v5)
    try:
        f2 = front_for(args.work2)
        s2, b2 = f2.tls("GET", spec["observe"])
        gone = marker.encode() not in b2
        baseline = (b"test blog entry" in b2) if args.app == "An0nB0ard" else True
        step("run2: marker gone on a fresh up (state reset)", s2 == 200 and gone and baseline,
             observe=spec["observe"], status=s2, marker_absent=gone, seeded_baseline=baseline)
    finally:
        SM.run_cli("down", "--work", args.work2)
        clean = SM.run_cli("check-clean", "--work", args.work2)
        step("teardown + check-clean", "\"clean\": true" in (clean.stdout or ""))

    out = os.path.join(args.evidence, f"state-reset-proof-{args.app}.json")
    json.dump(res, open(out, "w"), indent=2, sort_keys=True)
    print(json.dumps({"app": args.app, "pass": res["pass"], "marker": marker, "evidence": out}, indent=2))
    return 0 if res["pass"] else 1


if __name__ == "__main__":
    sys.exit(main())
