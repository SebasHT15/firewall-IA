"""A scriptable stand-in for data_plane/hybrid_shadow_worker.py, for tests only.

It speaks the real IPC protocol (hybrid_shadow_process) with stdlib only, so the runner's
process handling can be tested without numpy, scikit-learn or the artifact. The behaviour is
chosen by --mode; --once-flag PATH makes a "first process only" fault: the fault happens only
while PATH does not exist (the first process creates it), so a restarted worker is healthy.

    ok                       answer every request with a valid output
    ready_false:<detail>     handshake `ready: false` with that detail, then exit
    never_ready              never send the handshake
    exit_at_start            exit before the handshake
    bad_hello                a handshake that is not JSON
    bad_schema_hello         a ready handshake with another feature schema
    hang                     handshake, then never answer
    crash                    handshake, then exit(7) on the first request
    garbage                  answer a line that is not JSON
    nan                      answer a line with a NaN attack (a raw NaN token)
    inf                      answer a line with an Infinity category value
    wrong_id                 answer with another request id
    oversize                 answer with a line longer than MAX_LINE_BYTES
    out_of_range             attack = 1.7
    bad_version              a version other than the handshake's
    worker_invalid:<detail>  `ok: false, kind: invalid`
    worker_failed:<detail>   `ok: false, kind: failed`
    slow:<seconds>           sleep, then answer ok
"""

import argparse
import os
import sys
import time

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "data_plane"))

import hybrid_contracts as contracts  # noqa: E402
import hybrid_shadow_process as ipc  # noqa: E402
import request_features  # noqa: E402

VERSION = "fake-analyzer/test"


def signals(attack=0.25):
    out = {contracts.ATTACK: attack}
    out.update({s: (1.0 if s == "category:sql_injection" else 0.0)
                for s in contracts.CATEGORY_SIGNALS})
    return out


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", default="ok")
    parser.add_argument("--once-flag")
    args = parser.parse_args()
    mode, _, arg = args.mode.partition(":")

    faulty = True
    if args.once_flag:
        faulty = not os.path.exists(args.once_flag)
        if faulty:
            open(args.once_flag, "w").close()

    out = os.fdopen(os.dup(1), "wb", buffering=0)
    if mode == "exit_at_start" and faulty:
        return 5
    if mode == "never_ready" and faulty:
        time.sleep(600)
    if mode == "bad_hello" and faulty:
        out.write(b"this is not json\n")
        time.sleep(600)
    if mode == "ready_false":
        out.write(ipc.encode_line({"ready": False, "detail": arg}))
        return 2
    schema = "request-features/v1" if mode == "bad_schema_hello" and faulty \
        else request_features.FEATURE_SCHEMA_VERSION
    out.write(ipc.encode_line({"ready": True, "protocol": ipc.PROTOCOL, "pid": os.getpid(),
                               "version": VERSION, "feature_schema": schema,
                               "guard": "fake"}))
    stdin = sys.stdin.buffer
    while True:
        line = stdin.readline(ipc.MAX_LINE_BYTES + 1)
        if not line:
            return 0
        request = ipc.decode_line(line)
        rid = request["id"]
        ok = {"id": rid, "ok": True, "signals": signals(), "version": VERSION, "analyze_ms": 0.01}
        if not faulty or mode == "ok":
            out.write(ipc.encode_line(ok))
        elif mode == "hang":
            time.sleep(600)
        elif mode == "crash":
            os._exit(7)
        elif mode == "garbage":
            out.write(b"definitely not json\n")
        elif mode == "nan":
            out.write(b'{"id":%d,"ok":true,"signals":{"attack":NaN,"category:sql_injection":1.0},'
                      b'"version":"%s"}\n' % (rid, VERSION.encode()))
        elif mode == "inf":
            out.write(b'{"id":%d,"ok":true,"signals":{"attack":0.5,"category:xss":Infinity},'
                      b'"version":"%s"}\n' % (rid, VERSION.encode()))
        elif mode == "wrong_id":
            out.write(ipc.encode_line({**ok, "id": rid + 1000}))
        elif mode == "oversize":
            out.write(b"x" * (ipc.MAX_LINE_BYTES + 10) + b"\n")
        elif mode == "out_of_range":
            out.write(ipc.encode_line({**ok, "signals": signals(1.7)}))
        elif mode == "bad_version":
            out.write(ipc.encode_line({**ok, "version": "something-else"}))
        elif mode == "worker_invalid":
            out.write(ipc.encode_line({"id": rid, "ok": False, "kind": "invalid", "detail": arg,
                                       "analyze_ms": 0.1}))
        elif mode == "worker_failed":
            out.write(ipc.encode_line({"id": rid, "ok": False, "kind": "failed", "detail": arg,
                                       "analyze_ms": 0.1}))
        elif mode == "slow":
            time.sleep(float(arg))
            out.write(ipc.encode_line(ok))
        else:
            return 9


if __name__ == "__main__":
    sys.exit(main())
