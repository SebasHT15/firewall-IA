"""
A local stack whose V5 is a DOUBLE behind a counting forwarder, for the mechanism checks. The forwarder
(`scripts/gateway_ops/fault_proxy.py`) counts the classify calls that reached V5 and keeps the SHA-256 of
the last canonical text, never the text. Everything is stopped on exit and the cleanliness report is
returned in `holder["clean"]`.
"""
import contextlib
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))
OPS = os.path.join(REPO, "scripts", "gateway_ops")
sys.path[:0] = [HERE, OPS, os.path.join(REPO, "data_plane")]

import fault_proxy as FP          # noqa: E402
import live_stack as L            # noqa: E402
import stack as S                 # noqa: E402


@contextlib.contextmanager
def doubled_stack(config, work, upstream, extra=(), holder=None):
    holder = holder if holder is not None else {}
    cfg = S.load_config(config)
    manifest_path, _ = S.check_manifest(cfg)
    os.makedirs(work, exist_ok=True)
    port = L.free_port()
    log = open(os.path.join(work, "v5-double.log"), "ab")
    double = subprocess.Popen([L.PYTHON, os.path.join(OPS, "service_doubles.py"), "--role", "v5", "--port",
                               str(port), "--manifest", manifest_path], stdout=log, stderr=subprocess.STDOUT,
                              start_new_session=True)
    proxy = None
    stack_work = os.path.join(work, "stack")
    started = False
    try:
        S.wait_until(lambda: S.http_get(f"http://127.0.0.1:{port}/health")[0] == 200, 15, "V5 double", double)
        proxy = FP.FaultProxy(f"http://127.0.0.1:{port}")
        code = S.main(["up", "--config", config, "--work", stack_work, "--v5", "url:" + proxy.url,
                       "--upstream", upstream, *extra])
        if code != 0:
            raise RuntimeError(f"stack up failed ({code})")
        started = True
        yield S.State(stack_work).load(), proxy
    finally:
        if started:
            S.main(["down", "--work", stack_work])
        if proxy is not None:
            proxy.close()
        double.terminate()
        try:
            double.wait(timeout=5)
        except subprocess.TimeoutExpired:
            double.kill()
            double.wait(timeout=5)
        log.close()
        if os.path.exists(os.path.join(stack_work, S.STATE_FILE)):
            state = S.State(stack_work)
            state.load()
            holder["clean"] = S.clean_report(state)
