"""
firewall-IA — canonical-request/v1 worker for the cascade decision path.

    .venv-dataplane/bin/python -I data_plane/cascade_canonical_worker.py --max-decoded-body N \
        --token-budget B --max-bytes-per-token M --max-frame-bytes F --max-text-bytes T

Same process model, snapshot codec and safe reply as `canonical_worker.py` (D69), which stays the
shadow observer's worker and never returns text. The decision path needs the text itself, because
Model 2 and V5 consume it, so every snapshot gets TWO frames back: the unchanged safe reply, then one
frame holding the UTF-8 canonical text (empty unless ACCEPT within `--max-text-bytes`). Keeping the
text in its own frame leaves the reply validation of the observer untouched, and the gateway checks
the frame against `text_sha256` from the safe reply. The token budget is a parameter taken from the
versioned manifest; nothing here knows its value.
"""
import argparse
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:   # -I drops the script directory from sys.path
    sys.path.insert(0, HERE)

import canonical_observer as ipc  # noqa: E402
import canonical_request as cr  # noqa: E402
import canonical_worker as shadow  # noqa: E402


def answer(payload: bytes, limits: cr.Limits, max_text_bytes: int) -> tuple:
    """(safe reply dict, text bytes). A frame that cannot be decoded raises FrameError."""
    snapshot_id, _claimed_cap, parts = ipc.decode_snapshot(payload)
    started = time.perf_counter()
    try:
        res = cr.canonicalize(parts, limits)
        canonicalize_ms = (time.perf_counter() - started) * 1000
        reply = shadow._safe_audit_reply(snapshot_id, res, canonicalize_ms)
        ipc.encode_reply(reply)   # allow_nan=False: a non-finite value cannot reach the wire
    except ValueError:
        return ({"id": snapshot_id, "ok": False, "kind": "invalid",
                 "detail": "non_finite_output"}, b"")
    except Exception as exc:  # noqa: BLE001 — by TYPE and LOCATION only, like the shadow worker
        return ({"id": snapshot_id, "ok": False, "kind": "failed",
                 "detail": f"canon:{shadow._where(exc)}"}, b"")
    text = b""
    if res.text is not None:
        encoded = res.text.encode("utf-8")
        if len(encoded) <= max_text_bytes:
            text = encoded
    return reply, text


def serve(out, stdin, limits: cr.Limits, max_frame_bytes: int, max_text_bytes: int) -> int:
    while True:
        try:
            payload = ipc.read_frame_sync(stdin, max_frame_bytes)
        except ipc.FrameError:
            return 3
        if payload is None:
            return 0
        try:
            reply, text = answer(payload, limits, max_text_bytes)
        except ipc.FrameError:
            return 3
        out.write(ipc.encode_reply(reply) + ipc.encode_frame(text, max_text_bytes))
        out.flush()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-decoded-body", type=int, required=True)
    parser.add_argument("--token-budget", type=int, required=True)
    parser.add_argument("--max-bytes-per-token", type=int, required=True)
    parser.add_argument("--max-frame-bytes", type=int, required=True)
    parser.add_argument("--max-text-bytes", type=int, required=True)
    args = parser.parse_args(argv)
    if min(args.max_frame_bytes, args.max_text_bytes) <= 0:
        return 2
    try:
        limits = cr.Limits(max_decoded_body=args.max_decoded_body, token_budget=args.token_budget,
                           max_bytes_per_token=args.max_bytes_per_token)
    except ValueError:
        return 2

    out = os.fdopen(os.dup(1), "wb", buffering=0)
    sys.stdout = sys.stderr
    stdin = sys.stdin.buffer
    out.write(ipc.encode_reply({"ready": True, "protocol": ipc.PROTOCOL, "contract": cr.CONTRACT_ID,
                                "version": shadow.WORKER_VERSION, "pid": os.getpid()}))
    out.flush()
    return serve(out, stdin, limits, args.max_frame_bytes, args.max_text_bytes)


if __name__ == "__main__":
    sys.exit(main())
