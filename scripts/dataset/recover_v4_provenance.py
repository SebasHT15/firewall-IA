"""
firewall-IA — recover the V4 generator's provenance of every V4-clean row (Hybrid
Architecture Phase 2B, run-002; Issue #53).

The V4 generator (`parse_dataset_v4.py`) splits train / eval by GENERATOR GROUP (D16):

  attack           group_id("attack", canonical_key(payload)) — one canonical payload,
                   rendered as a base row plus its augmentation variant(s)
  CSIC             group_id("csic_attack" | "csic_benign", csic_group_key(record)) — one
                   CSIC request shape with digits collapsed and values decoded
  synthetic benign group_id("benign", "shape|path|param|value")

It keeps that identity in memory (`_gid`, plus `_src` and `_cat`) and strips it before
writing the JSONL ("[9/9]"). Nothing else in the repository stores it.

This script re-runs the UNMODIFIED generator (its own `main()`, default arguments, which
are the manifest's: seed 42, eval fraction 0.2, cap 2500 policy B, row cap 4000, one
augmentation per group) into a temporary directory, observes each row as the generator
writes it, and accepts the observation ONLY if both regenerated files are byte-identical
to `datasets/v4_clean/{train,eval}.jsonl` and to the SHA-256 in
`datasets/manifest_v4_clean.json`. The row order of the files is the write order, so line
i of each split gets the provenance of the i-th row written.

How a row is observed: the generator serializes each row with
`json.dumps({k: v for k, v in r.items() if not k.startswith("_")})`. The module's `json`
is replaced by a shim whose `dumps` reads the full row `r` (with its `_` tags) from the
caller's frame before delegating to the real `json.dumps`. The generator's code and output
are untouched; the byte-identity check proves it.

Inputs (all verified): `csic_database.csv` (SHA-256 in docs/data_sources.md),
`~/PayloadsAllTheThings` at the manifest commit, V4-clean files. External Test v1 is not
read. `build_hybrid_analyzer_v2.py` calls `recover()` in memory on every build; the CLI
below only exists to inspect the result (one JSON line per V4-clean row — split, line,
row_id = SHA-256 of `input`, generator_group_id, generator_source, generator_category; no
request text). Nothing is written to the repository by the builder.

Note: synthetic benign generator groups always hold one row (the renderer redraws path,
parameter and value), so the generator group adds links only for attack payloads
(augmentation variants) and CSIC request shapes.

RUN (repository root, ML environment — the generator reads the CSIC CSV with pandas):
    python3.12 scripts/dataset/recover_v4_provenance.py --out <scratch path>.jsonl
"""

import argparse
import hashlib
import io
import json
import os
import sys
import tempfile
from contextlib import redirect_stdout

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO_ROOT, "scripts", "dataset"))

import parse_dataset_v4 as gen  # noqa: E402

V4_DIR = os.path.join(REPO_ROOT, "datasets", "v4_clean")
V4_MANIFEST = os.path.join(REPO_ROOT, "datasets", "manifest_v4_clean.json")
CSIC_SHA256 = "c420f0bc0464376de75b6c419a0ac226fe69fe12c8ac4908843273721e44e637"


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class _ObservingJson:
    """Stands in for the generator's `json` module; records the full row behind each
    serialized dataset line, then delegates every call to the real module."""

    def __init__(self, real):
        self._real = real
        self.rows = []

    def __getattr__(self, name):
        return getattr(self._real, name)

    def dumps(self, obj, *args, **kwargs):
        caller = sys._getframe(1).f_locals
        r, split = caller.get("r"), caller.get("sp")
        if (isinstance(obj, dict) and "input" in obj and isinstance(r, dict)
                and "_gid" in r and r.get("input") == obj["input"]):
            self.rows.append((split, r["_gid"], r["_src"], r["_cat"], r["input"]))
        return self._real.dumps(obj, *args, **kwargs)


def recover():
    """(provenance rows, verification record). Raises SystemExit unless the regenerated
    dataset is byte-identical to V4-clean."""
    manifest = json.load(open(V4_MANIFEST))
    if sha256_file(gen.CSIC_PATH) != CSIC_SHA256:
        raise SystemExit("FATAL: csic_database.csv is not the copy V4 was generated from")
    head = gen.git_rev(gen.PAYLOADS_REPO)
    if head != manifest["payloadsallthethings_commit"]:
        raise SystemExit(f"FATAL: {gen.PAYLOADS_REPO} at {head}, manifest needs "
                         f"{manifest['payloadsallthethings_commit']}")

    shim = _ObservingJson(gen.json)
    real_json, real_argv = gen.json, sys.argv
    with tempfile.TemporaryDirectory() as tmp:
        sys.argv = ["parse_dataset_v4.py", "--out-dir", tmp,
                    "--manifest", os.path.join(tmp, "manifest.json")]
        gen.json = shim
        log = io.StringIO()
        try:
            with redirect_stdout(log):
                gen.main()
        finally:
            gen.json, sys.argv = real_json, real_argv
        regenerated = {s: sha256_file(os.path.join(tmp, f"{s}.jsonl")) for s in ("train", "eval")}

    for split in ("train", "eval"):
        if regenerated[split] != manifest["artifact_sha256"][split]:
            raise SystemExit(f"FATAL: regenerated {split} {regenerated[split]} != manifest "
                             f"{manifest['artifact_sha256'][split]}; provenance not recoverable")
        if sha256_file(os.path.join(V4_DIR, f"{split}.jsonl")) != regenerated[split]:
            raise SystemExit(f"FATAL: datasets/v4_clean/{split}.jsonl differs from the regeneration")

    out, line = [], {"train": 0, "eval": 0}
    for split, gid, src, cat, text in shim.rows:
        out.append({"split": split, "line": line[split],
                    "row_id": hashlib.sha256(text.encode("utf-8")).hexdigest(),
                    "generator_group_id": gid, "generator_source": src,
                    "generator_category": cat})
        line[split] += 1
    expected = manifest["final_rows"]
    if line != {"train": expected["train"], "eval": expected["eval"]}:
        raise SystemExit(f"FATAL: observed {line} rows, manifest has {expected}")
    # every observed row must be the row on that line of the real file
    for split in ("train", "eval"):
        with open(os.path.join(V4_DIR, f"{split}.jsonl"), encoding="utf-8") as f:
            ids = [hashlib.sha256(json.loads(l)["input"].encode("utf-8")).hexdigest() for l in f]
        obs = [r["row_id"] for r in out if r["split"] == split]
        if ids != obs:
            raise SystemExit(f"FATAL: observed row order differs from {split}.jsonl")
    return out, {"v4_sha256": regenerated, "payloadsallthethings_commit": head,
                 "csic_sha256": CSIC_SHA256, "generator_log_lines": log.getvalue().count("\n")}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--out", required=True)
    args = ap.parse_args()
    rows, check = recover()
    data = "".join(json.dumps(r, sort_keys=True) + "\n" for r in rows).encode("utf-8")
    if os.path.exists(args.out):
        if sha256_file(args.out) != hashlib.sha256(data).hexdigest():
            raise SystemExit(f"FATAL: {args.out} exists with different content; never overwritten")
        print(f"identical: {args.out}")
    else:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
        with open(args.out, "xb") as f:
            f.write(data)
        print(f"wrote {args.out}")
    print(json.dumps({**check, "rows": len(rows), "sha256": hashlib.sha256(data).hexdigest()},
                     indent=2))


if __name__ == "__main__":
    main()
