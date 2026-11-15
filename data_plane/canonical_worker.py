"""
firewall-IA — canonical-request/v1 OBSERVER WORKER (runs in the DATA-PLANE interpreter).

    .venv-dataplane/bin/python -I data_plane/canonical_worker.py --max-decoded-body N --max-frame-bytes M

Started and killed by `canonical_observer.ProcessCanonicalObserver`; not meant to be run by hand
except to debug (it then speaks the length-prefixed binary frame protocol on stdin/stdout).
Protocol, frame bounds and the safe reply shape: see canonical_observer.py.

Unlike the Analyzer worker this runs under the gateway's OWN interpreter (stdlib + the
brotli/zstandard mitmproxy already ships); it imports NO numpy/scikit-learn. It receives a bounded
request SNAPSHOT (method/target/headers/body), runs the ONE `canonical_request.canonicalize`, and
replies with codes/sizes/hash ONLY — never the request text, target, a header value or the body.

Start-up: emit one `ready` frame (protocol id + contract id + version), then for every snapshot
frame emit exactly one reply frame. EOF on stdin (the gateway is gone) ends the worker. A malformed
or over-long frame is a protocol violation: the worker stops rather than guess (exit code 3).

The worker never logs and never writes anything but protocol frames to its protocol fd: fd 1 is
duplicated for the protocol and `sys.stdout` is pointed at stderr, which the gateway discards.
"""
import argparse
import os
import sys
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:   # -I drops the script directory from sys.path
    sys.path.insert(0, HERE)

import canonical_adapter as adapter  # noqa: E402
import canonical_observer as ipc  # noqa: E402
import canonical_request as cr  # noqa: E402

WORKER_VERSION = cr.CONTRACT_ID


def _where(exc: BaseException) -> str:
    frame = traceback.extract_tb(exc.__traceback__)[-1]
    return f"{type(exc).__name__}@{os.path.basename(frame.filename)}:{frame.lineno}"


def _safe_audit_reply(snapshot_id: int, res: cr.CanonicalResult, canonicalize_ms: float) -> dict:
    """Build the reply from a CanonicalResult using SAFE fields only. The audit dict is NEVER
    forwarded wholesale: only closed enumerations, sizes and the text hash are copied out."""
    audit = res.audit
    framing = audit.get("framing") or {}
    return {
        "id": snapshot_id,
        "ok": True,
        "outcome": res.outcome,
        "reject": res.reject,
        "reason": res.reason,
        "size": res.size,
        "signals": sorted(res.signals),
        "target_form": audit.get("target_form"),
        "content_codings": list(audit.get("content_codings") or ()),
        "transfer_encoding": list(framing.get("transfer_encoding") or ()),
        "decoded_body_bytes": audit.get("decoded_body_bytes"),
        "text_sha256": audit.get("text_sha256"),
        "canonicalize_ms": canonicalize_ms,
    }


def _answer(payload: bytes, max_decoded_body: int) -> dict:
    """Decode one snapshot frame, canonicalize, and build a reply dict. Never raises: a failure is
    a message, not a crash. A frame that cannot even be decoded raises FrameError to the caller,
    which is a protocol violation handled by serve()."""
    snapshot_id, _frame_cap, parts = ipc.decode_snapshot(payload)   # FrameError -> protocol error
    started = time.perf_counter()
    try:
        # The worker enforces its OWN configured decode cap, regardless of the frame's claimed value.
        limits = adapter.make_limits(max_decoded_body)
        res = cr.canonicalize(parts, limits)
        canonicalize_ms = (time.perf_counter() - started) * 1000
        reply = _safe_audit_reply(snapshot_id, res, canonicalize_ms)
        try:
            ipc.encode_reply(reply)   # allow_nan=False: a non-finite value cannot reach the wire
        except ValueError:
            return {"id": snapshot_id, "ok": False, "kind": "invalid", "detail": "non_finite_output",
                    "canonicalize_ms": canonicalize_ms}
        return reply
    except Exception as exc:  # noqa: BLE001 — canonicalize is documented not to raise on input data;
        # any exception here is an infrastructure fault, reported by TYPE and LOCATION only.
        return {"id": snapshot_id, "ok": False, "kind": "failed",
                "detail": f"canon:{_where(exc)}",
                "canonicalize_ms": (time.perf_counter() - started) * 1000}


def serve(out, stdin, max_decoded_body: int, max_frame_bytes: int) -> int:
    """Answer snapshot frames until EOF. Returns the process exit code."""
    while True:
        try:
            payload = ipc.read_frame_sync(stdin, max_frame_bytes)
        except ipc.FrameError:
            return 3                       # protocol violation: stop rather than guess
        if payload is None:
            return 0                       # the gateway closed our stdin: it is gone
        try:
            reply = _answer(payload, max_decoded_body)
        except ipc.FrameError:
            return 3                       # undecodable snapshot: protocol violation
        try:
            out.write(ipc.encode_reply(reply))
        except ValueError:
            # A detail token somehow exceeded the reply cap: send a minimal safe failure instead.
            out.write(ipc.encode_reply({"id": reply.get("id"), "ok": False, "kind": "failed",
                                        "detail": "reply_too_large"}))
        out.flush()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-decoded-body", type=int, required=True)
    parser.add_argument("--max-frame-bytes", type=int, required=True)
    args = parser.parse_args(argv)
    if args.max_decoded_body <= 0 or args.max_frame_bytes <= 0:
        return 2

    out = os.fdopen(os.dup(1), "wb", buffering=0)   # the protocol channel
    sys.stdout = sys.stderr                          # nothing else may reach the protocol fd
    stdin = sys.stdin.buffer

    out.write(ipc.encode_reply({"ready": True, "protocol": ipc.PROTOCOL,
                                "contract": cr.CONTRACT_ID, "version": WORKER_VERSION,
                                "pid": os.getpid()}))
    out.flush()
    return serve(out, stdin, args.max_decoded_body, args.max_frame_bytes)


if __name__ == "__main__":
    sys.exit(main())
