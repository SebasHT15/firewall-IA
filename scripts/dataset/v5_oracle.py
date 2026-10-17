#!/usr/bin/env python3
"""V5 stage 4 — the benign oracle (V5-DATA-SPEC-r3 §4.4, APPROVED D59; L and signatures PENDING; #74).

A benign generator value is rejected (`ORACLE_REJECT`) when
  1. its `canonical_key` equals an attack-pool `canonical_key`;
  2. its `canonical_key` contains an attack-pool canonical payload of length >= L;
  3. it matches a breakout signature of a category compatible with its slot (§4.2), tested on the
     value and on its `canonical_key` (which collapses CR / LF, so header-break signatures need the
     raw value).

The oracle is built from attack-pool records only (never probe, development, INTERNAL TEST or
External Test material). `canonical_key` is the D16 function, imported, never re-implemented; it is
applied to VALUES, never to rendered model text (I9).

L and the signature list are PENDING (calibrated on the pilot, ratified in the preregistration).
They are configuration: `OracleConfig.status` carries their status into the manifest, and a real
build refuses anything but RATIFIED. L is never V4's MIN_LEN = 4 (§4.4); values <= 4 are refused.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import v5_catalog as K  # noqa: E402
from parse_dataset_v4 import canonical_key  # noqa: E402  (D16 identity: imported, never edited)

SIGNATURE_SCHEMA = "v5-oracle-signatures/v1"
DEFAULT_SIGNATURES = os.path.join(HERE, "v5_policy", "oracle_signatures_v1.json")
SURVIVAL_FIXTURE = ("O'Neil", "Apt #4", "AT&T", "100%", "a<b")      # spec §4.4: must survive
V4_MIN_LEN = 4
STATUSES = ("PENDING", "FIXTURE", "RATIFIED")


class OracleError(ValueError):
    pass


@dataclass(frozen=True)
class OracleConfig:
    L: int
    status: str                   # PENDING | FIXTURE | RATIFIED (only RATIFIED for a real build)
    signatures_path: str = DEFAULT_SIGNATURES

    def __post_init__(self):
        if isinstance(self.L, bool) or not isinstance(self.L, int) or self.L <= V4_MIN_LEN:
            raise OracleError(f"L={self.L!r}: L is calibrated on the pilot and is never V4's MIN_LEN=4 (§4.4); "
                              "values <= 4 are refused")
        if self.status not in STATUSES:
            raise OracleError(f"oracle status must be one of {STATUSES}")


def load_signatures(path: str = DEFAULT_SIGNATURES) -> tuple:
    with open(path, "rb") as fh:
        data = fh.read()
    obj = json.loads(data)
    if obj.get("schema") != SIGNATURE_SCHEMA:
        raise OracleError(f"signature schema must be {SIGNATURE_SCHEMA!r}")
    sigs = {}
    for cat, items in obj.get("signatures", {}).items():
        if cat not in set().union(*K.SLOT_COMPATIBILITY.values()):
            raise OracleError(f"signature category {cat!r} is not a §4.2 category")
        seen = set()
        out = []
        for it in items:
            sid, pat = it.get("id"), it.get("pattern")
            if not sid or sid in seen or not isinstance(pat, str):
                raise OracleError(f"{cat}: signature needs a unique id and a pattern")
            seen.add(sid)
            out.append((sid, re.compile(pat, re.IGNORECASE | re.DOTALL)))
        sigs[cat] = tuple(out)
    return sigs, hashlib.sha256(data).hexdigest(), obj.get("status", "")


class BenignOracle:
    """Built once from the attack pool's ACCEPTED records (their stored `canonical_key`)."""

    def __init__(self, attack_records, config: OracleConfig):
        keys = set()
        for r in attack_records:
            k = r.get("canonical_key")
            if not isinstance(k, str) or not k:
                raise OracleError(f"attack record {r.get('record_id')} has no canonical_key")
            if k != canonical_key(r["payload_wire"]):
                raise OracleError(f"attack record {r.get('record_id')}: stored canonical_key is stale")
            keys.add(k)
        self.config = config
        self.keys = frozenset(keys)
        self.long_keys = tuple(sorted(k for k in keys if len(k) >= config.L))
        self.signatures, self.signatures_sha256, self.signatures_status = load_signatures(config.signatures_path)
        self.keys_sha256 = hashlib.sha256("\n".join(sorted(keys)).encode()).hexdigest()

    def check(self, value: str, slot_type: str) -> str | None:
        """None if the value survives, else the first failing rule (deterministic order)."""
        if slot_type not in K.SLOT_COMPATIBILITY:
            raise OracleError(f"{slot_type} is not an attackable slot type")
        ck = canonical_key(value)
        if ck in self.keys:
            return "exact_canonical_key"
        for k in self.long_keys:
            if k in ck:
                return f"contains_attack_payload_ge_L:{len(k)}"
        for cat in sorted(K.SLOT_COMPATIBILITY[slot_type]):
            for sid, rx in self.signatures.get(cat, ()):
                if rx.search(ck) or rx.search(value):    # raw too: canonical_key collapses CR / LF
                    return f"signature:{cat}:{sid}"
        return None

    def manifest(self) -> dict:
        return {"L": self.config.L, "L_status": self.config.status, "attack_keys": len(self.keys),
                "attack_keys_sha256": self.keys_sha256, "keys_ge_L": len(self.long_keys),
                "signatures_sha256": self.signatures_sha256, "signatures_status": self.signatures_status,
                "signature_counts": {c: len(v) for c, v in sorted(self.signatures.items())},
                "survival_fixture": self.survival()}

    def survival(self) -> dict:
        """§4.4 fixture: every value must survive in every attackable slot type."""
        res = {v: {t: self.check(v, t) for t in sorted(K.SLOT_COMPATIBILITY)} for v in SURVIVAL_FIXTURE}
        return {"all_survive": all(r is None for x in res.values() for r in x.values()), "results": res}
