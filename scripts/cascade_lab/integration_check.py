"""
Real-model end-to-end route verification for the cascade lab.

Drives the REAL cascade over real TCP sockets: a controlled upstream, the
`CascadeGateway`, the real Model 2 baseline decider (loaded here), and the real V5
service over HTTP, with the lab Fast Path positive policy. Asserts that each
applicable route fires AND that skipped stages are truly skipped:

  FAST_ALLOW  (synthetic /healthz)      -> forwarded, stage=fast_path, no Model 2, no V5
  Model 2 BLOCK (strong SQLi)           -> 403, stage=model2, V5 NOT called, upstream NOT reached
  DEFER -> V5 BLOCK                      -> 403, stage=v5, upstream NOT reached
  DEFER -> V5 ALLOW (benign)            -> forwarded, stage=v5, upstream reached
  protocol reject (TE + CL)             -> 400, stage=wire, upstream NOT reached

Run in `.venv-analyzer` (Model 2 FINAL load), V5 service already on :8001:
    .venv-analyzer/bin/python scripts/cascade_lab/integration_check.py
"""
import os
import socket
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(REPO, "data_plane"))
sys.path.insert(0, HERE)
sys.path.insert(0, REPO)

import cascade as C          # noqa: E402
import cascade_runtime as RT  # noqa: E402
import fast_path as fp        # noqa: E402
import model2_decider as MD   # noqa: E402
import lab_server as L        # noqa: E402

FINAL = os.path.join(REPO, "model-output-model2/final/v4-d82-20261027T052308Z")
POL = os.path.join(REPO, "reports/v5/hybrid/cascade-lab/policies")
SHA_B = "da6f6eb85c5a687bd038c6298baf59abdbe0489a80c8993b74a34dae7c60aa38"


def send(host, port, raw):
    with socket.create_connection((host, port), timeout=30) as s:
        s.sendall(raw)
        resp = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
        return resp


def main():
    v5_url = os.environ.get("FIREWALL_V5_URL", "http://127.0.0.1:8001")
    decider = MD.Model2Decider.from_policy_file(
        os.path.join(FINAL, "baseline34.json"), expected_sha256=SHA_B,
        policy_path=os.path.join(POL, "model2_lab_baseline34.json"))
    fp_policy = fp.load_policy(os.path.join(POL, "fast_path_lab_app.json"))
    v5 = RT.V5HttpClient(v5_url, timeout_s=30)

    router = C.CascadeRouter(
        C.CascadeConfig(mode=C.CASCADE_ACTIVE, fast_path_policy=fp_policy),
        fast_path_evaluate=fp.safe_evaluate, model2_decide=decider.decide,
        v5_classify=v5, make_fast_path_input=RT.make_fast_path_input)

    logs = []
    sink = L.UpstreamSink()
    sink.start()
    gw = L.CascadeGateway(router, L.GatewayConfig(upstream_addr=(sink.host, sink.port),
                                                  log_sink=logs.append))
    gw.start()

    def last():
        return logs[-1]

    failures = []

    def check(name, cond, detail=""):
        status = "PASS" if cond else "FAIL"
        print("  [%s] %s %s" % (status, name, detail))
        if not cond:
            failures.append(name)

    try:
        before = len(sink.received())

        # 1. FAST_ALLOW
        r = send(gw.host, gw.port, b"GET /healthz HTTP/1.1\r\nHost: lab.local\r\n\r\n")
        rec = last()
        check("fast_allow_forwarded", b"200 OK" in r and rec["applied"] == "FORWARD")
        check("fast_allow_stage", rec["deciding_stage"] == "fast_path", rec["deciding_stage"])
        check("fast_allow_no_model2", rec["model2"] is None)
        check("fast_allow_no_v5", rec["v5"] is None)
        check("fast_allow_upstream_received", rec["upstream_received"])

        # 2. Model 2 BLOCK (path traversal scores above the lab threshold) — V5 must NOT be called
        r = send(gw.host, gw.port,
                 b"GET /download?file=..%2f..%2f..%2fetc%2fpasswd HTTP/1.1\r\nHost: files.local\r\n\r\n")
        rec = last()
        check("model2_block_403", b"403" in r and rec["applied"] == "DENY")
        check("model2_block_stage", rec["deciding_stage"] == "model2", rec["deciding_stage"])
        check("model2_block_no_v5_call", rec["v5"] is None)
        check("model2_block_p", (rec["model2"] or {}).get("decision") == "BLOCK",
              str((rec["model2"] or {}).get("p_block")))
        check("model2_block_upstream_not_reached", not rec["upstream_received"])

        # 3. benign -> DEFER -> V5 ALLOW
        r = send(gw.host, gw.port, b"GET /catalog/widgets HTTP/1.1\r\nHost: shop.local\r\n\r\n")
        rec = last()
        check("benign_defer_to_v5", (rec["model2"] or {}).get("decision") == "DEFER")
        check("benign_v5_stage", rec["deciding_stage"] == "v5", rec["deciding_stage"])
        check("benign_v5_allow_forward", rec["applied"] == "FORWARD" and b"200 OK" in r,
              str((rec["v5"] or {}).get("decision")))

        # 4. SQLi that Model 2 DEFERS (below threshold) -> reaches V5 -> V5 BLOCK
        r = send(gw.host, gw.port,
                 b"GET /products?id=1%27%20OR%20%271%27%3D%271%20UNION%20SELECT%20password%20FROM%20users"
                 b" HTTP/1.1\r\nHost: shop.local\r\n\r\n")
        rec = last()
        check("sqli_defer_to_v5", (rec["model2"] or {}).get("decision") == "DEFER",
              str((rec["model2"] or {}).get("p_block")))
        check("sqli_v5_block_denied", rec["deciding_stage"] == "v5" and rec["applied"] == "DENY"
              and b"403" in r, str((rec["v5"] or {}).get("decision")))

        # 5. protocol reject (TE + CL)
        r = send(gw.host, gw.port,
                 b"POST /u HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n"
                 b"Content-Length: 5\r\n\r\n0\r\n\r\n")
        rec = last()
        check("protocol_reject_400", b"400" in r and rec["deciding_stage"] == "wire",
              rec.get("reason"))
        check("protocol_reject_upstream_not_reached", not rec["upstream_received"])

        total_forwarded = len(sink.received()) - before
        check("only_two_forwarded_to_upstream", total_forwarded == 2, str(total_forwarded))
    finally:
        gw.stop()
        sink.stop()

    print("\nRESULT:", "ALL ROUTES OK" if not failures else "FAILURES: " + ", ".join(failures))
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
