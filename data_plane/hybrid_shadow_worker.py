"""
firewall-IA — Hybrid shadow Analyzer WORKER (runs in the analyzer environment, not the gateway's).

    .venv-analyzer/bin/python -I data_plane/hybrid_shadow_worker.py --artifact PATH

Started and killed by `hybrid_shadow_process.ProcessShadowRunner`; not meant to be run by hand
except to debug (it then speaks the IPC protocol on stdin/stdout). Protocol and bounds:
see hybrid_shadow_process.py.

Start-up, in this order (the order is the security property):
  1. read the artifact ONCE and verify its SHA-256 against the frozen evidence;
  2. only then import numpy / scikit-learn and unpickle those verified bytes;
  3. check the feature contract;
  4. say `{"ready": true, ...}` — or `{"ready": false, "detail": ...}` and exit.
Then, for every request line, exactly one answer line. EOF on stdin (the gateway is gone)
ends the worker.

The worker never logs and never writes anything but protocol lines to stdout: stdout is
duplicated for the protocol and `sys.stdout` is pointed at stderr, which the gateway discards.
It receives FEATURES, not request text.
"""

import argparse
import os
import sys
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:   # -I drops the script directory from sys.path
    sys.path.insert(0, HERE)

import hybrid_contracts as contracts  # noqa: E402
import hybrid_shadow as shadow  # noqa: E402
import hybrid_shadow_process as ipc  # noqa: E402
import request_features  # noqa: E402


def _where(exc: BaseException) -> str:
    frame = traceback.extract_tb(exc.__traceback__)[-1]
    return f"{type(exc).__name__}@{os.path.basename(frame.filename)}:{frame.lineno}"


def serve(model, out, stdin) -> int:
    """Answer request lines until EOF. Returns the process exit code."""
    while True:
        line = stdin.readline(ipc.MAX_LINE_BYTES + 1)
        if not line:
            return 0                      # the gateway closed our stdin: it is gone
        if len(line) > ipc.MAX_LINE_BYTES or not line.endswith(b"\n"):
            return 3                      # protocol violation: stop rather than guess
        try:
            request = ipc.decode_line(line)
            message_id = request["id"]
        except (ValueError, KeyError):
            return 3
        out.write(reply(model, message_id, request.get("features")))
        out.flush()


def reply(model, message_id, features_dict) -> bytes:
    """One answer line. Never raises: a failure is a message, not a crash."""
    return ipc.encode_line(_answer(model, message_id, features_dict))


def _answer(model, message_id, features_dict) -> dict:
    started = time.perf_counter()
    try:
        features = request_features.RequestFeatures(**features_dict)
        if features.schema_version != shadow.FROZEN_FEATURE_SCHEMA:
            return {"id": message_id, "ok": False, "kind": "unavailable",
                    "detail": "feature_contract_mismatch"}
        output = shadow.analyze_strict(model, features)
        analyze_ms = (time.perf_counter() - started) * 1000
        answer = {"id": message_id, "ok": True, "signals": dict(output.signals),
                  "version": output.analyzer_version, "analyze_ms": analyze_ms}
        try:
            ipc.encode_line(answer)   # allow_nan=False: a non-finite value cannot reach the wire
        except ValueError:
            raise shadow.InvalidAnalyzerOutput("non_finite_output") from None
        return answer
    except shadow.InvalidAnalyzerOutput as exc:
        return {"id": message_id, "ok": False, "kind": "invalid",
                "detail": ipc.safe_detail(str(exc), "invalid_output"),
                "analyze_ms": (time.perf_counter() - started) * 1000}
    except ValueError as exc:
        # hybrid_contracts raising on the answer is an invalid output; any other ValueError
        # (including bad feature values) is a failure of the worker.
        frames = traceback.extract_tb(exc.__traceback__)
        in_contract = bool(frames) and os.path.basename(frames[-1].filename) == "hybrid_contracts.py"
        return {"id": message_id, "ok": False,
                "kind": "invalid" if in_contract else "failed",
                "detail": "contract_violation" if in_contract else f"analyze:{_where(exc)}",
                "analyze_ms": (time.perf_counter() - started) * 1000}
    except Exception as exc:  # noqa: BLE001 — exception type and location only, never a message
        return {"id": message_id, "ok": False, "kind": "failed",
                "detail": f"analyze:{_where(exc)}",
                "analyze_ms": (time.perf_counter() - started) * 1000}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact", required=True)
    parser.add_argument("--evidence", default=shadow.FROZEN_EVIDENCE)
    args = parser.parse_args(argv)

    out = os.fdopen(os.dup(1), "wb", buffering=0)   # the protocol channel
    sys.stdout = sys.stderr                          # nothing else may reach it
    stdin = sys.stdin.buffer

    try:
        analyzer = shadow.load_frozen_analyzer(args.artifact, args.evidence)
    except shadow.AnalyzerUnavailable as exc:
        out.write(ipc.encode_line({"ready": False, "detail": exc.detail}))
        return 2
    try:   # one OpenMP thread: HistGradientBoosting would otherwise fan out to every core
        from threadpoolctl import threadpool_limits
        threadpool_limits(limits=1)
    except ImportError:
        pass
    out.write(ipc.encode_line({"ready": True, "protocol": ipc.PROTOCOL, "pid": os.getpid(),
                               "version": analyzer.version,
                               "feature_schema": analyzer.feature_schema,
                               "guard": shadow.INFERENCE_GUARD}))
    return serve(analyzer._model, out, stdin)


if __name__ == "__main__":
    sys.exit(main())
