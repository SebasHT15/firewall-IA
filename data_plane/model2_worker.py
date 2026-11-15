"""
firewall-IA — Model 2 worker (runs in the analyzer environment, not the gateway's).

    .venv-analyzer/bin/python -I data_plane/model2_worker.py --artifact PATH --artifact-sha256 HEX \
        --policy PATH --max-frame-bytes N

`Model2Decider` verifies the FINAL artifact, which needs numpy/scikit-learn; the gateway's environment
has neither (D33). So the verified scorer lives here and the gateway talks to it over the length-
prefixed frames of `canonical_observer`. This module adds no scoring and no policy logic.

Start-up: one `ready` frame carrying the identity that was really loaded (artifact, feature view,
policy), which `model2_client` compares with the manifest. Then one reply per request frame. EOF on
stdin ends the worker; a malformed frame is a protocol violation and ends it too. Replies carry
numbers and closed codes only, never the canonical text.
"""
import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:   # -I drops the script directory from sys.path
    sys.path.insert(0, HERE)

import canonical_observer as ipc  # noqa: E402
import model2_decider as md  # noqa: E402

PROTOCOL = "model2-worker-ipc/v1"
REPLY_FIELDS = ("decision", "status", "p_block", "threshold", "feature_view",
                "model_artifact_sha256", "policy_id", "policy_sha256", "policy_status")


def serve(out, stdin, decider, max_frame_bytes: int) -> int:
    while True:
        try:
            payload = ipc.read_frame_sync(stdin, max_frame_bytes)
        except ipc.FrameError:
            return 3
        if payload is None:
            return 0
        try:
            message = json.loads(payload)
            request_id = message["id"]
            outcome = decider.decide(canonical_outcome=message["canonical_outcome"],
                                     canonical_text=message["canonical_text"])
            reply = {"id": request_id, "ok": True}
            reply.update({name: getattr(outcome, name) for name in REPLY_FIELDS})
        except (ValueError, KeyError, TypeError):
            return 3
        out.write(ipc.encode_reply(reply))
        out.flush()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact", required=True)
    parser.add_argument("--artifact-sha256", required=True)
    parser.add_argument("--policy", required=True)
    parser.add_argument("--max-frame-bytes", type=int, required=True)
    args = parser.parse_args(argv)

    out = os.fdopen(os.dup(1), "wb", buffering=0)
    sys.stdout = sys.stderr
    try:
        decider = md.Model2Decider.from_policy_file(
            args.artifact, expected_sha256=args.artifact_sha256, policy_path=args.policy)
    except Exception as exc:  # noqa: BLE001 — by type only: the gateway reports it as a status
        out.write(ipc.encode_reply({"ready": False, "protocol": PROTOCOL,
                                    "detail": type(exc).__name__}))
        return 4
    policy = decider.policy
    out.write(ipc.encode_reply({
        "ready": True, "protocol": PROTOCOL, "pid": os.getpid(),
        "model_artifact_sha256": decider.artifact_sha256, "feature_view": decider.feature_view,
        "policy_id": policy.policy_id if policy else None,
        "policy_sha256": policy.sha256 if policy else None,
        "policy_status": policy.status if policy else None,
        "threshold": policy.threshold if policy else None}))
    return serve(out, sys.stdin.buffer, decider, args.max_frame_bytes)


if __name__ == "__main__":
    sys.exit(main())
