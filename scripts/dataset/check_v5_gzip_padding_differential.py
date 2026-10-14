"""P9 (D63) local differential check: how do locally available gzip decoders treat multi-member
bodies, NUL padding and trailing data, compared with `canonical_request._decode_gzip`?

Bounded, local only: fixed in-memory vectors, local executables with a timeout, no network, no
gateway. The result is EVIDENCE about these components only; it says nothing about any other
backend. Writes `reports/v5/canonical-request-v1/p9_gzip_padding_differential.json`.

    .venv-dataplane/bin/python scripts/dataset/check_v5_gzip_padding_differential.py
"""

import gzip
import hashlib
import json
import os
import shutil
import subprocess
import sys
import zlib

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO, "data_plane"))
import canonical_request as cr  # noqa: E402

OUT = os.path.join(REPO, "reports", "v5", "canonical-request-v1", "p9_gzip_padding_differential.json")
A, B = gzip.compress(b"alpha=1", mtime=0), gzip.compress(b"&beta=2", mtime=0)
VECTORS = {
    "single_member": A,
    "two_members": A + B,
    "nul_pad_1": A + b"\x00",
    "nul_pad_1000": A + b"\x00" * 1000,
    "member_nul_member": A + b"\x00" * 8 + B,
    "trailing_garbage": A + b"XYZ",
    "nul_then_garbage": A + b"\x00\x00XYZ",
    "partial_magic": A + b"\x1f",
    "truncated": A[:-3],
    "zlib_not_gzip": zlib.compress(b"alpha=1"),
}


def ours(data):
    try:
        return "ok", cr._decode_gzip(data, 1 << 20)
    except Exception as exc:  # R3 in canonicalize
        return "error", f"{type(exc).__module__}.{type(exc).__name__}"


def cpython(data):
    try:
        return "ok", gzip.decompress(data)
    except Exception as exc:
        return "error", type(exc).__name__


def mitmproxy_decode(data):
    try:
        from mitmproxy.net import encoding
    except ImportError:
        return None
    try:
        return "ok", encoding.decode(data, "gzip")
    except Exception as exc:
        return "error", type(exc).__name__


NODE = ("const z=require('zlib');const c=[];process.stdin.on('data',d=>c.push(d));"
        "process.stdin.on('end',()=>{try{process.stdout.write(z.gunzipSync(Buffer.concat(c)))}"
        "catch(e){process.stderr.write(String(e.code));process.exit(1)}})")


def tool(argv):
    if shutil.which(argv[0]) is None:
        return None

    def run(data):
        p = subprocess.run(argv, input=data, capture_output=True, timeout=10)
        status = "ok" if p.returncode == 0 else ("warning" if p.returncode == 2 else "error")
        return status, p.stdout if p.stdout else p.stderr.decode(errors="replace").strip()[:80]
    return run


def describe(res):
    if res is None:
        return "unavailable"
    status, val = res
    if isinstance(val, bytes):
        return f"{status}:{val.decode(errors='replace')}"
    return f"{status}:{val}"


def main():
    components = {
        "canonical_request": ours,
        f"cpython_{sys.version.split()[0]}_gzip.decompress": cpython,
        "mitmproxy_net_encoding.decode": mitmproxy_decode if mitmproxy_decode(A) else None,
        "gnu_gzip_-dc": tool(["gzip", "-dc"]),
        "pigz_-dc": tool(["pigz", "-dc"]),
        "busybox_gunzip_-c": tool(["busybox", "gunzip", "-c"]),
        "node_zlib.gunzipSync": tool(["node", "-e", NODE]),
    }
    versions = {"python": sys.version.split()[0]}
    for name, argv in (("gzip", ["gzip", "--version"]), ("node", ["node", "--version"])):
        if shutil.which(argv[0]):
            versions[name] = subprocess.run(argv, capture_output=True, text=True).stdout.splitlines()[0]
    table = {}
    for vname, data in VECTORS.items():
        row = {"sha256": hashlib.sha256(data).hexdigest()}
        for cname, fn in components.items():
            row[cname] = "unavailable" if fn is None else describe(fn(data))
        table[vname] = row
    with open(OUT, "w", encoding="utf-8") as fh:
        json.dump({"versions": versions, "vectors": table}, fh, indent=2, sort_keys=True)
        fh.write("\n")
    for vname, row in table.items():
        print(vname, {k: v for k, v in row.items() if k != "sha256"})


if __name__ == "__main__":
    main()
