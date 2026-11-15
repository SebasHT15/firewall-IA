#!/usr/bin/env python3
"""
firewall-IA — V5 split-assignment METADATA reader (consumer side).  READ-ONLY, standard library only.

**This is a metadata tool, NOT a training-example loader.** `v5-split-assignment/v1` maps IDENTITIES
(cluster / template / payload_family / value_entry) to split roles; it contains no canonical example text
or reference labels. To consume TRAIN/VALIDATION *examples*, use `v5_example_exchange.py`, which reads the
`rows.{split}.jsonl` / `rows.{split}.meta.jsonl` files through the gated `v5_train_data` loaders and never
opens a protected-role file. This module only lets a consumer inspect / sanity-check the split-assignment
metadata artifact produced by `scripts/dataset/v5_split.py:write_assignment`.

It defines no parallel format and re-implements no SPL invariant — the authoritative invariants
SPL-1…SPL-9 are the producer's, in `scripts/dataset/v5_split_checks.py`. What it adds is a defensive
CONSUME-TIME integrity guard over ONE snapshot of the artifact:

* `verify_exchange(dir)` → closed diagnostics (empty = clean), diagnostic-only: it returns NO data.
* `load_exchange(dir)` → `{"TRAIN": [...], "VALIDATION": [...]}` identity records, **only when the same
  snapshot verifies clean** (it raises `ExchangeError` otherwise — there is no bypass). `INTERNAL_TEST` and
  `E6_RESERVE` are never returned.

Integrity model (read this): the artifact is read ONCE; the SAME parsed snapshot is both verified and
returned (no re-read between check and use). The consumed `assignment.jsonl` bytes are hashed and compared
to the manifest's recorded `assignment_sha256`, so an edit of `assignment.jsonl` alone is caught. This is
tamper-EVIDENT, not authentication: a coordinated rewrite of both `assignment.jsonl` and the manifest's
`assignment_sha256` is self-consistent and passes. True authenticity needs a trusted EXTERNAL digest (e.g.
a git-committed freeze record); pass it as `expected_assignment_sha256` and it is checked against the
consumed bytes. `config_sha256` authenticates only the config block, never the assignment content.

Diagnostics and return values carry identity identifiers, counts and closed codes only — never request
text, payloads, header values or bodies.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
_DATASET = os.path.join(os.path.dirname(HERE), "dataset")
for _p in (HERE, _DATASET):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import v5_split as S  # noqa: E402  (the producer; its schema + constants are reused, never duplicated)

SCHEMA = S.SCHEMA_ASSIGNMENT                      # "v5-split-assignment/v1"
TRAIN, VALIDATION = S.TRAIN, S.VALIDATION
INTERNAL_TEST, E6_RESERVE = S.INTERNAL_TEST, S.E6_RESERVE
CONSUMABLE_SPLITS = (TRAIN, VALIDATION)
EXCLUDED_SPLITS = (INTERNAL_TEST, E6_RESERVE)
KNOWN_SPLITS = (TRAIN, VALIDATION, INTERNAL_TEST, E6_RESERVE)
KNOWN_KINDS = ("cluster", "template", "payload_family", "value_entry")

ASSIGNMENT_FILE = "assignment.jsonl"
MANIFEST_FILE = "manifest.json"


class ExchangeError(ValueError):
    """The split-assignment artifact cannot be consumed safely. Never partially loaded."""


def _diag(code: str, detail: str = "") -> dict:
    return {"code": code, "detail": detail}


class _Snapshot:
    """One read of the artifact: manifest dict, raw assignment bytes, parsed records. Verify and consume
    operate on THIS object, so nothing is re-read between the check and the use."""
    __slots__ = ("manifest", "assignment_bytes", "records", "read_error")

    def __init__(self, manifest=None, assignment_bytes=None, records=None, read_error=None):
        self.manifest = manifest
        self.assignment_bytes = assignment_bytes
        self.records = records
        self.read_error = read_error          # a single diagnostic if the files could not be read


def _read_once(dataset_dir: str) -> _Snapshot:
    try:
        with open(os.path.join(dataset_dir, MANIFEST_FILE), encoding="utf-8") as fh:
            manifest = json.load(fh)
    except (OSError, ValueError) as e:
        return _Snapshot(read_error=_diag("MANIFEST_UNREADABLE", type(e).__name__))
    try:
        with open(os.path.join(dataset_dir, ASSIGNMENT_FILE), "rb") as fh:
            raw = fh.read()
    except OSError as e:
        return _Snapshot(read_error=_diag("ASSIGNMENT_UNREADABLE", type(e).__name__))
    records = []
    try:
        # Split on LF ONLY (accept a trailing CR for CRLF); NOT str.splitlines(), which also breaks on
        # U+0085 / U+2028 / U+2029 that are valid, unescaped, inside a JSON string value.
        for raw_line in raw.decode("utf-8").split("\n"):
            line = raw_line.rstrip("\r")
            if line.strip():
                records.append(json.loads(line))
    except (UnicodeDecodeError, ValueError) as e:
        return _Snapshot(read_error=_diag("ASSIGNMENT_UNREADABLE", type(e).__name__))
    return _Snapshot(manifest=manifest, assignment_bytes=raw, records=records)


def _valid_record(r) -> bool:
    return (isinstance(r, dict) and r.get("kind") in KNOWN_KINDS
            and isinstance(r.get("id"), str) and r.get("id") != ""
            and r.get("split") in KNOWN_SPLITS)


def _verify_snapshot(snap: _Snapshot, *, expected_assignment_sha256=None) -> list:
    diags = []
    manifest, raw, records = snap.manifest, snap.assignment_bytes, snap.records

    if not isinstance(manifest, dict):
        return [_diag("MANIFEST_SCHEMA", "manifest is not a JSON object")]
    if manifest.get("schema") != SCHEMA:
        diags.append(_diag("EXCHANGE_SCHEMA", f"{manifest.get('schema')!r} != {SCHEMA!r}"))

    # (a) config block integrity — authenticates the config, NOT the assignment content.
    cfg, recorded_cfg = manifest.get("config"), manifest.get("config_sha256")
    if cfg is None or not recorded_cfg:
        diags.append(_diag("CONFIG_MISSING", "manifest lacks config or config_sha256"))
    else:
        try:
            recomputed = S.config_sha256(cfg)
        except Exception as e:  # noqa: BLE001 — a malformed config is a refusal, not a crash
            diags.append(_diag("CONFIG_UNHASHABLE", type(e).__name__))
        else:
            if recomputed != recorded_cfg:
                diags.append(_diag("CONFIG_SHA_MISMATCH", f"recorded {recorded_cfg} != recomputed {recomputed}"))

    # (b) assignment CONTENT integrity over the bytes actually consumed.
    got = hashlib.sha256(raw).hexdigest()
    manifest_asha = manifest.get("assignment_sha256")
    if not manifest_asha:
        diags.append(_diag("ASSIGNMENT_SHA_MISSING", "manifest records no assignment_sha256"))
    elif got != manifest_asha:
        diags.append(_diag("ASSIGNMENT_SHA_MISMATCH", f"consumed bytes {got} != manifest {manifest_asha}"))
    if expected_assignment_sha256 is not None and got != expected_assignment_sha256:
        diags.append(_diag("ASSIGNMENT_SHA_UNTRUSTED",
                           f"consumed bytes {got} != trusted {expected_assignment_sha256}"))

    if not records:
        diags.append(_diag("ASSIGNMENT_EMPTY", "no assignment records"))

    # (c) per-record type/field validation (defect 4) and single-split-per-identity.
    seen: dict = {}
    for i, r in enumerate(records):
        if not _valid_record(r):
            kind = r.get("kind") if isinstance(r, dict) else type(r).__name__
            diags.append(_diag("MALFORMED_RECORD", f"record[{i}] kind={str(kind)[:40]!r}"))
            continue
        key = (r["kind"], r["id"])
        if key in seen and seen[key] != r["split"]:
            diags.append(_diag("IDENTITY_MULTIPLE_SPLITS",
                               f"{r['kind']}:{r['id'][:60]} in {seen[key]!r} and {r['split']!r}"))
        else:
            seen.setdefault(key, r["split"])

    # (d) TRAIN ∩ VALIDATION disjointness by identity (consumer re-check of SPL-3).
    train_ids = {k for k, s in seen.items() if s == TRAIN}
    val_ids = {k for k, s in seen.items() if s == VALIDATION}
    for kind, ident in sorted(train_ids & val_ids):
        diags.append(_diag("TRAIN_VALIDATION_OVERLAP", f"{kind}:{ident[:60]}"))
    return diags


def verify_exchange(dataset_dir: str, *, expected_assignment_sha256=None) -> list:
    """Diagnostic-only: closed diagnostics for the artifact (empty = clean). Returns NO example data."""
    snap = _read_once(dataset_dir)
    if snap.read_error is not None:
        return [snap.read_error]
    return _verify_snapshot(snap, expected_assignment_sha256=expected_assignment_sha256)


def load_exchange(dataset_dir: str, *, expected_assignment_sha256=None) -> dict:
    """Return `{"TRAIN": [...identity records...], "VALIDATION": [...]}` ONLY when the artifact verifies
    clean; otherwise raise `ExchangeError`. There is NO bypass. Verification and consumption use the SAME
    snapshot (one read). `INTERNAL_TEST` / `E6_RESERVE` records are never returned, and only well-formed
    records are returned."""
    snap = _read_once(dataset_dir)
    if snap.read_error is not None:
        raise ExchangeError(f"unreadable split-assignment artifact: {snap.read_error['code']}")
    diags = _verify_snapshot(snap, expected_assignment_sha256=expected_assignment_sha256)
    if diags:
        raise ExchangeError(f"split-assignment artifact is not consumable: {[d['code'] for d in diags]}")
    out = {TRAIN: [], VALIDATION: []}
    for r in snap.records:                      # snap already verified; every record here is well-formed
        if _valid_record(r) and r["split"] in CONSUMABLE_SPLITS:
            out[r["split"]].append(r)
    return out


def _counts(exchange: dict) -> dict:
    return {split: len(rows) for split, rows in exchange.items()}


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Verify / summarise a v5-split-assignment/v1 metadata directory")
    ap.add_argument("dataset_dir", help="directory with assignment.jsonl + manifest.json")
    ap.add_argument("--expected-assignment-sha256", default=None,
                    help="a TRUSTED external digest of assignment.jsonl (e.g. from a committed freeze record)")
    args = ap.parse_args(argv)
    diags = verify_exchange(args.dataset_dir, expected_assignment_sha256=args.expected_assignment_sha256)
    if diags:
        print("NOT CONSUMABLE:")
        for d in diags:
            print(f"  {d['code']}: {d['detail']}")
        return 1
    print("CONSUMABLE (metadata):", json.dumps(_counts(load_exchange(
        args.dataset_dir, expected_assignment_sha256=args.expected_assignment_sha256))))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
