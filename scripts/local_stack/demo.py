"""
Local demonstration: start the stack, walk through a short session over HTTPS (HTTP/2 and HTTP/1.1),
print which LAYER answered each request, and stop everything.

    .venv-dataplane/bin/python -B scripts/local_stack/demo.py --config scripts/local_stack/stack.example.json --work <new private dir>
    .venv-dataplane/bin/python -B scripts/local_stack/demo.py --config <pinned candidate config> --work <new private dir> --v5 real

Default V5 is the DOUBLE: it blocks any request whose canonical text contains `evil` and allows
everything else, attacks included. The banner says so; a demo with the double shows the mechanism only.
`--v5 real` needs the GPU hand-off (GPU_STATUS.json) and shows the model's decisions on a handful of
authored lab requests: a demonstration, never a measurement. `--keep-up` leaves the stack running for
manual requests (the printed curl commands); stop it with `stack.py down --work <dir>`.
"""
import argparse
import json
import os
import shlex
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import app_check as A            # noqa: E402
import stack as S                # noqa: E402

STEPS = [
    # (path, label, method, target, headers, body builder)
    ("tls_h2", "home page", "GET", "/", ()),
    ("tls_h2", "login page (sets session, CSRF token)", "GET", "/login", ()),
    ("tls_h2", "login without CSRF token", "POST", "/login", "login_no_csrf"),
    ("tls_h2", "login with CSRF token", "POST", "/login", "login_ok"),
    ("tls_h2", "notes of the session", "GET", "/notes", ()),
    ("tls_h2", "search with the double's marker", "GET", "/search?q=evil", ()),
    ("tls_h2", "SQL-injection-shaped search", "GET", "/search?q=x%27%20OR%201%3D1--", ()),
    ("tls_h1", "API token", "POST", "/api/v1/token", "token"),
    ("tls_h1", "API with the token", "GET", "/api/v1/notes", "bearer"),
    ("tls_h1", "API with alg=none token", "GET", "/api/v1/notes", "bearer_none"),
    ("tls_h1", "API with an expired token", "GET", "/api/v1/notes", "bearer_expired"),
    ("tls_h1", "traversal-shaped path", "GET", "/notes/..%2F..%2Fetc%2Fpasswd", ()),
]


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", required=True)
    parser.add_argument("--work", required=True)
    parser.add_argument("--v5", default="double", choices=("double", "real"))
    parser.add_argument("--keep-up", action="store_true")
    parser.add_argument("--json", help="also write the rows to this new file")
    args = parser.parse_args(argv)
    if S.main(["up", "--config", args.config, "--work", args.work, "--v5", args.v5]) != 0:
        return 2
    state = S.State(args.work).load()
    try:
        banner = ("V5 = DOUBLE (blocks 'evil', allows everything else): MECHANISM ONLY" if args.v5 == "double"
                  else "V5 = real service of manifest " + state["identity"]["manifest"]["manifest_id"])
        print(f"\n== Firewall-IA local demo — mode {state['mode']}, {banner}; Fast Path off; V4 not running ==\n")
        state["ports_app"] = state["endpoints"]["app_direct"].rsplit(":", 1)[1]
        lab = A.Lab(state["seed"])
        clients = {p: A.Client(p, state) for p in ("tls_h1", "tls_h2")}
        recs = {p: A.Recorder(state, None, p) for p in clients}
        token = None
        csrf = None
        print(f"{'#':>2}  {'path':7} {'request':40} {'status':>6}  layer          control/reason")
        for i, (path, label, method, target, extra) in enumerate(STEPS, 1):
            headers, body = [], b""
            if extra == "login_no_csrf":
                headers, body = [A.FORM, A.ORIGIN], A.form(username="alice", password=lab.password("alice"))
            elif extra == "login_ok":
                headers, body = [A.FORM, A.ORIGIN], A.form(username="alice", password=lab.password("alice"),
                                                           csrf_token=csrf or "")
            elif extra == "token":
                headers = [A.JSON_CT]
                body = json.dumps({"username": "alice", "password": lab.password("alice")}).encode()
            elif extra == "bearer":
                headers = [("Authorization", f"Bearer {token}")]
            elif extra == "bearer_none":
                headers = [("Authorization", "Bearer " + lab.token(header={"alg": "none"}, signature=""))]
            elif extra == "bearer_expired":
                headers = [("Authorization", "Bearer " + lab.token(exp=1, iat=0, nbf=0))]
            status, _h, resp = recs[path].step(clients[path], label, method, target, headers, body,
                                               expect=(None, None, None, None))
            row = recs[path].rows[-1]
            _, layer, control, reason = row["observed"]
            if target == "/login" and method == "GET":
                csrf = A.csrf_from(resp)
            if extra == "token" and status == 200:
                token = json.loads(resp)["access_token"]
            why = f"{control}/{reason}" if layer == "app_rejected" else (f"stage {control}" if layer == "firewall" else "")
            print(f"{i:>2}  {path:7} {label[:40]:40} {status!s:>6}  {layer:14} {why}")
        for c in clients.values():
            c.close()
        rows = recs["tls_h1"].rows + recs["tls_h2"].rows
        if args.json:
            with open(args.json, "x", encoding="utf-8") as fh:
                json.dump({"identity": state["identity"], "v5": args.v5, "rows": rows}, fh, indent=2)
        ca = state["pki"]["ca_cert"]
        port = state["ports"]["front_tls"]
        print("\nManual requests while the stack is up:")
        print("  curl --noproxy '*' --cacert " + shlex.quote(ca) + f" --resolve notes.fwlab.test:{port}:127.0.0.1 "
              f"--http2 https://notes.fwlab.test:{port}/")
        print(f"  logs: {state['front_access_log']}, {state['gateway_decisions']}, {state['app_log']}")
    finally:
        if not args.keep_up:
            S.main(["down", "--work", args.work])
            S.main(["check-clean", "--work", args.work])
    return 0


if __name__ == "__main__":
    sys.exit(main())
