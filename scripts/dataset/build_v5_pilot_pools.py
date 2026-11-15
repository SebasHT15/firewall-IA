#!/usr/bin/env python3
"""V5 pilot benign-value pools with no real builder yet — CONSTRUCTED, deterministic, harmless.

Builds the five benign value pools the generator config references that `build_v5_benign_pools.py` does
NOT produce (fixture stand-ins only until now):

    passwords       fictitious passwords with non-alphanumerics (NIST 800-63B printing ASCII)
    urls_public     external URLs on RESERVED hosts only (RFC 2606: example.com/.net/.org/.test)
    urls_relative   origin-form relative URLs ("/a/b?x=1"); never "//", never "/.."
    rel_paths       relative file paths ("a/b/c.txt"); never leading "/", never ".." segments
    addr_data       IP / hostname as NON-URL data: RFC 5737 TEST-NET + RFC 3849 2001:db8:: + RFC 2606 hosts

Every value is CONSTRUCTED (marked `constructed: true`, source `CONSTRUCTED/<pool>`, licence `synthetic`):
these are NOT observations of real traffic, real secrets, real hosts or real users. The passwords are
fictitious; the addresses are documentation/test ranges. The pools are deterministic (a seeded sha256
stream), so two runs are byte-identical; `value_entry_id` is the spec §4.6 id
(`sha256(pool_id NUL NFC(value))`), identical to `v5_pools_common.value_entry_id`, so the values are
drop-in for the generator / split assignment.

Oracle survival (spec §4.4) is reported like the benign builder: APPLIED only when an `--attack-pool` is
supplied (exact canonical-key collision excluded); otherwise NOT_APPLIED. Nothing here is ratified, and a
built pool is not a real-build authorization (that is `v5_generator.real_build_preconditions`).

CLI:
  python3 scripts/dataset/build_v5_pilot_pools.py build --out DIR [--count N] [--attack-pool POOL.jsonl]
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import string
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))
for _p in (HERE, os.path.join(REPO_ROOT, "data_plane")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import v5_pools_common as C  # noqa: E402
import v5_split_checks as SC  # noqa: E402  (guard_output: path protection before writing)

BUILDER_SCHEMA = "v5-pilot-pools/v1"
POOL_IDS = ("passwords", "urls_public", "urls_relative", "rel_paths", "addr_data")
DEFAULT_COUNT = 300
SALT = "v5-pilot-pools/v1"               # part of the deterministic stream; not a secret

# Reserved, non-routable building blocks (never a real host/address). The hosts match the labeler's
# `public_host_suffixes` (example.com / example.net / example.org / `example`), so every urls_public value
# classifies as POL-URL-PUBLIC (a reserved public stand-in), never PUBLIC_UNRESERVED.
RFC2606_HOSTS = ("example.com", "example.net", "example.org", "www.example.com", "api.example.org",
                 "cdn.example.net")
RFC5737_NETS = ("192.0.2", "198.51.100", "203.0.113")        # TEST-NET-1/2/3
PW_SPECIALS = "!#$%&*+-=?@_^~."           # printable ASCII specials that trip NO attack oracle signature
_PW_ALPHABET = string.ascii_letters + string.digits + PW_SPECIALS
_SEG_ALPHABET = string.ascii_lowercase + string.digits


def _digest(pool_id: str, i: int) -> str:
    return hashlib.sha256(f"{SALT}\0{pool_id}\0{i}".encode()).hexdigest()


def _letters(h: str, n: int, alphabet: str = string.ascii_lowercase) -> str:
    return "".join(alphabet[int(h[j * 2:j * 2 + 2], 16) % len(alphabet)] for j in range(n))


def _gen_password(i: int) -> str:
    """A fictitious password: 12..20 chars, with letters, digits and non-alphanumerics; no quotes, no
    angle brackets, no SQL/shell metacharacters (so it is unambiguously a benign value). A second digest
    extends the stream past the 32 bytes of the first so every position is well defined."""
    h = _digest("passwords", i) + _digest("passwords-ext", i)       # 128 hex chars = 64 bytes
    length = 12 + (int(h[:2], 16) % 9)                               # 12..20
    return "".join(_PW_ALPHABET[int(h[j * 2:j * 2 + 2], 16) % len(_PW_ALPHABET)] for j in range(length))


def _gen_url_public(i: int) -> str:
    h = _digest("urls_public", i)
    host = RFC2606_HOSTS[int(h[:2], 16) % len(RFC2606_HOSTS)]
    scheme = "https" if int(h[2:4], 16) % 4 else "http"
    seg = _letters(h[4:], 6)
    return f"{scheme}://{host}/{seg}/{i:04d}?ref={_letters(h[20:], 5)}"


def _gen_url_relative(i: int) -> str:
    h = _digest("urls_relative", i)
    return f"/{_letters(h, 5)}/{_letters(h[12:], 5)}/{i:04d}?q={_letters(h[24:], 4)}"


def _gen_rel_path(i: int) -> str:
    h = _digest("rel_paths", i)
    ext = ("txt", "csv", "json", "md")[int(h[:2], 16) % 4]
    return f"{_letters(h, 5)}/{_letters(h[12:], 5)}/{i:04d}.{ext}"


def _gen_addr_data(i: int) -> str:
    h = _digest("addr_data", i)
    kind = int(h[:2], 16) % 3
    if kind == 0:
        net = RFC5737_NETS[int(h[2:4], 16) % len(RFC5737_NETS)]
        return f"{net}.{int(h[4:6], 16)}"                       # RFC 5737 IPv4 test address
    if kind == 1:
        return f"2001:db8:{h[4:8]}::{int(h[8:10], 16):x}"       # RFC 3849 IPv6 documentation address
    return f"host{i:04d}.example.com"                           # RFC 2606 reserved hostname


_GENERATORS = {"passwords": _gen_password, "urls_public": _gen_url_public,
               "urls_relative": _gen_url_relative, "rel_paths": _gen_rel_path, "addr_data": _gen_addr_data}


def _flags(value: str) -> list:
    """Closed structural flags; a flagged value is EXCLUDED (never a benign row), so no constructed value
    can smuggle a control byte or a dot-segment."""
    flags = []
    if any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in value):
        flags.append("control_char")
    if not value.isascii() or not all(ch in string.printable.strip() + " " for ch in value):
        flags.append("non_printable_ascii")
    if ".." in value:
        flags.append("dot_segment")
    if value != value.strip():
        flags.append("surrounding_whitespace")
    if "//" in value.split("://", 1)[-1]:
        flags.append("double_slash")
    return flags


def _record(pool_id: str, value: str, i: int, status: str, reason) -> dict:
    return {"pool_id": pool_id, "value": value,
            "value_entry_id": C.value_entry_id(pool_id, value),
            "source_id": f"CONSTRUCTED/{pool_id}", "source_ref": f"{pool_id}:{i:06d}",
            "license": "synthetic", "constructed": True,
            "status": status, "exclusion_reason": reason, "flags": _flags(value)}


def build_pool(pool_id: str, count: int, oracle_keys=None) -> tuple:
    """(records, values) for one pool. Deterministic; de-duplicated by value; a flagged or
    attack-colliding value is ACCEPTED→EXCLUDED and counted, never silently dropped."""
    gen, seen, records, values = _GENERATORS[pool_id], set(), [], []
    for i in range(count):
        value = gen(i)
        if value in seen:                 # exact repeat: keep one, count the rest as a dedup exclusion
            records.append(_record(pool_id, value, i, C.EXCLUDED, "duplicate_value"))
            continue
        seen.add(value)
        flags = _flags(value)
        if flags:
            records.append(_record(pool_id, value, i, C.EXCLUDED, f"structural:{','.join(flags)}"))
            continue
        if oracle_keys is not None and _canonical_key(value) in oracle_keys:
            records.append(_record(pool_id, value, i, C.EXCLUDED, "attack_canonical_key_collision"))
            continue
        records.append(_record(pool_id, value, i, C.ACCEPTED, None))
        values.append(value)
    return records, values


def _canonical_key(value: str) -> str:
    from parse_dataset_v4 import canonical_key
    return canonical_key(value)


def load_attack_keys(path):
    C.assert_not_protected(path)
    keys = set()
    for rec in C.read_jsonl(path):
        ck = rec.get("canonical_key")
        if ck:
            keys.add(ck)
    return keys


def cmd_build(args) -> int:
    out_dir = args.out
    SC.guard_output(out_dir)                 # path protection before writing
    if args.count < 1:
        raise ValueError('count must be positive')
    os.makedirs(out_dir, exist_ok=False)
    oracle_keys = load_attack_keys(args.attack_pool) if args.attack_pool else None
    pools, artifacts = {}, []
    for pool_id in POOL_IDS:
        records, values = build_pool(pool_id, args.count, oracle_keys)
        art = C.write_jsonl(os.path.join(out_dir, f"{pool_id}.jsonl"), records,
                            key=lambda r: (r["source_ref"], r["value"]))
        artifacts.append(art)
        excluded = sum(1 for r in records if r["exclusion_reason"] is not None)
        pools[pool_id] = {"generated": len(records), "accepted": len(values), "excluded": excluded,
                          "value_count": len(values), "sha256": art["sha256"]}
    code_files = [os.path.join(HERE, "build_v5_pilot_pools.py"), os.path.join(HERE, "v5_pools_common.py")]
    manifest = {
        "schema": BUILDER_SCHEMA, "pool_schema": C.SCHEMA, "kind": "pilot_constructed_pools",
        "constructed": True,
        "disclaimer": "CONSTRUCTED values, not real traffic/secrets/hosts/users. Passwords are fictitious; "
                      "addresses are RFC 5737/3849/2606 documentation/test ranges. Not ratified; a built pool "
                      "is not a real-build authorization.",
        "count_per_pool": args.count, "salt": SALT, "pools": dict(sorted(pools.items())),
        "oracle": {"exact_canonical_key": ("APPLIED" if oracle_keys is not None
                                           else "NOT_APPLIED: no --attack-pool given"),
                   "attack_pool": (os.path.relpath(args.attack_pool, REPO_ROOT) if args.attack_pool else None),
                   "containment_ge_L": "PENDING: L not calibrated (spec 4.4, pilot)"},
        "privacy": "RFC 2606 reserved hosts, RFC 5737/3849 documentation addresses, fictitious passwords, "
                   "relative paths/URLs with no dot-segment. Local and may be gitignored; bytes pinned by sha256.",
        "sources": {p: {"source_id": f"CONSTRUCTED/{p}", "license": "synthetic"} for p in POOL_IDS},
        "code_fingerprint": C.code_fingerprint(code_files), "environment": C.environment(),
        "provenance": C.provenance(code_files),
        "artifacts": sorted(artifacts, key=lambda a: a["path"]),
    }
    C.write_json(os.path.join(out_dir, "manifest.json"), manifest)
    print(json.dumps({"out_dir": out_dir, "schema": BUILDER_SCHEMA,
                      "accepted": {p: v["accepted"] for p, v in sorted(pools.items())},
                      "excluded": {p: v["excluded"] for p, v in sorted(pools.items())}}, sort_keys=True))
    return 0


def build_parser():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build", help="build the five constructed pilot pools")
    b.add_argument("--out", required=True, help="output directory (throwaway / gitignored)")
    b.add_argument("--count", type=int, default=DEFAULT_COUNT, help=f"candidates per pool (default {DEFAULT_COUNT})")
    b.add_argument("--attack-pool", default=None, help="optional admitted attack pool jsonl for exact-collision exclusion")
    b.set_defaults(func=cmd_build)
    return ap


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
