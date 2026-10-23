#!/usr/bin/env python3
"""
firewall-IA — V5 TRAIN/VALIDATION EXAMPLE interface for a consumer (Model 2 / V5).  READ-ONLY.

This is the training-EXAMPLE loader (distinct from `v5_split_exchange.py`, which reads split-assignment
IDENTITY metadata). It exposes the existing final `rows.{split}.jsonl` / `rows.{split}.meta.jsonl` examples
through the gated `v5_train_data` loaders, so Model 2 and V5 consume the SAME eligible examples without
either building a parallel pipeline and without opening a protected-role file.

It reuses `v5_train_data` wholesale — `load_manifest`, `verify_read_artifacts`, `load_split`, `check_rows`,
`check_disjoint`, the mode gates and the `IDENTITY_KEYS`/`TRAINABLE_LABEL_STATUSES` contracts — and adds
no new data rules. Guarantees it inherits and enforces (no bypass — any diagnostic raises
`ExampleExchangeError`):

* Only TRAIN and VALIDATION `rows.*`/`meta.*` files are opened. `INTERNAL_TEST`, `E6_RESERVE`, slices and
  the combined assignment file are NEVER opened (the test suite spies on `open()` to prove this).
* Row/meta alignment and `text_sha256` are checked over the bytes actually consumed.
* Row eligibility is enforced: `label_status ∈ {VERIFIED, POLICY_DEFINED}`, not excluded/sliced, output in
  the recipe vocabulary, label/output consistent, and TRAIN × VALIDATION identity-disjoint.
* **Fixture vs authorized real access is distinguished:** a stage-4 synthetic FIXTURE manifest loads under
  SMOKE with no authorization; a non-fixture (real/provisional) manifest REQUIRES a committed
  `v5-experimental-authorization/v1` record (EXPERIMENTAL gate) or it is refused. FINAL launching stays with
  `finetune_v5.py --mode final` (full prereg/freeze/output-dir gates); this reader does not shortcut it.

What this reader does NOT do: train, select a threshold, tokenize for a model, or place training artifacts.
It never turns a V4/V5 decision into a label (the label is the dataset's reference label), never promotes
an AI-audited / policy-defined provenance into VERIFIED, and treats `label`/`label_status`/`label_basis`/
identities/`manifest_sha256` as metadata for validation, grouping and reporting — never as learned features.

Example schema returned per row (import and consume this):
    {
      "split": "TRAIN"|"VALIDATION", "row_index": int,
      "text": <canonical-request/v1 ACCEPT text>,          # the learned-input text
      "output": "ALLOW | …"|"BLOCK | …",                    # reference output string
      "label": "ALLOW"|"BLOCK",                              # reference label
      "label_status": "VERIFIED"|"POLICY_DEFINED",           # trainable eligibility
      "label_basis": <str|None>,                             # provenance; NEVER a feature, NEVER ⇒ VERIFIED
      "text_sha256": <hash of the consumed text>,            # integrity/provenance
      "identities": {<IDENTITY_KEYS>: …},                    # row/group/contamination ids
      "manifest_sha256": <str>,                              # binds the example to the authorized manifest
      "eligibility": {"trainable": true},
    }

Usage (fixture, no real data, no authorization needed):
    python3 scripts/training/v5_example_exchange.py --dataset <FIXTURE_DIR>
    # or, programmatically:
    from v5_example_exchange import load_examples
    ex = load_examples(fixture_dir)                 # {"TRAIN":[...], "VALIDATION":[...]}
"""
from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import v5_train_data as D  # noqa: E402  (the gated loaders + contracts are reused, never duplicated)

DEFAULT_RECIPE = os.path.join(HERE, "v5_training_recipe_v1.json")


class ExampleExchangeError(ValueError):
    """The TRAIN/VALIDATION examples cannot be consumed safely. Never partially loaded."""


def _is_fixture_manifest(manifest: dict) -> bool:
    return (str(manifest.get("status", "")).startswith("FIXTURE")
            and manifest.get("fixture") is True
            and manifest.get("generator_config", {}).get("mode") == "fixture"
            and manifest.get("attack_label_basis") == "fixture_synthetic")


def _to_example(row: dict, manifest_sha: str) -> dict:
    meta = row["meta"]
    return {
        "split": row["split"],
        "row_index": row["index"],
        "text": row["text"],
        "output": row["output"],
        "label": meta.get("label"),
        "label_status": meta.get("label_status"),
        "label_basis": meta.get("label_basis"),
        "text_sha256": meta.get("text_sha256"),
        "identities": {k: meta.get(k) for k in D.IDENTITY_KEYS},
        "manifest_sha256": manifest_sha,
        "eligibility": {"trainable": True},
    }


def _verify_and_parse(dataset_dir: str, manifest: dict, split: str, vocabulary) -> tuple:
    """SINGLE capture of one allowed split: read the rows+meta files' bytes ONCE, verify those exact bytes
    against the manifest's recorded sha256/size, and parse the SAME bytes. Returns (rows, diags). Only a
    READ split (TRAIN/VALIDATION) reaches here; a protected-role file is never opened."""
    idx = D._artifact_index(manifest)
    diags, texts = [], {}
    for pat in (D.ROWS_FILE, D.META_FILE):
        name = pat.format(split=split)
        try:
            with open(os.path.join(dataset_dir, name), "rb") as fh:
                raw = fh.read()
        except OSError as e:
            diags.append(D.Diag("ARTIFACT_MISSING", f"{name}: {type(e).__name__}"))
            texts[pat] = None
            continue
        art = idx.get(name)
        if art is None:
            diags.append(D.Diag("ARTIFACT_NOT_IN_MANIFEST", name))
        elif D.sha256_bytes(raw) != art.get("sha256") or len(raw) != art.get("bytes"):
            diags.append(D.Diag("ARTIFACT_HASH_MISMATCH", f"{name}: manifest {art.get('sha256')} "
                                                          f"consumed {D.sha256_bytes(raw)}"))
        try:
            texts[pat] = raw.decode("utf-8")
        except UnicodeDecodeError as e:
            diags.append(D.Diag("ARTIFACT_UNDECODABLE", f"{name}: {type(e).__name__}"))
            texts[pat] = None
    if texts.get(D.ROWS_FILE) is None or texts.get(D.META_FILE) is None:
        return [], diags
    rows, pdiags = D.parse_split(texts[D.ROWS_FILE], texts[D.META_FILE], split)   # parses the SAME bytes
    return rows, diags + pdiags


def _load_and_check(dataset_dir: str, *, recipe_path: str, authorization: str | None) -> tuple:
    """One pass: resolve the manifest/recipe, run the ACCESS gate (schema/spec + fixture-or-authorization)
    BEFORE opening any rows/meta, and only if access is granted do a single capture + verify + parse +
    eligibility/disjointness. Returns (diags, train_rows, val_rows, manifest_sha). `gate_diagnostics` and
    `load_examples` both go through here, so a consumed example is exactly the one that was verified."""
    try:
        manifest, manifest_sha = D.load_manifest(dataset_dir)
    except (OSError, ValueError) as e:
        return [D.Diag("MANIFEST_UNREADABLE", type(e).__name__)], None, None, None
    try:
        recipe, _ = D.load_recipe(recipe_path)
        vocabulary = D.recipe_vocabulary(recipe)
    except (OSError, ValueError) as e:
        return [D.Diag("RECIPE_UNREADABLE", type(e).__name__)], None, None, None

    # ── ACCESS gate FIRST: if this fails, STOP before opening any rows/meta file (defect 2). ──
    access = []
    if manifest.get("schema") != D.MANIFEST_SCHEMA:
        access.append(D.Diag("MANIFEST_SCHEMA", f"{manifest.get('schema')!r} != {D.MANIFEST_SCHEMA!r}"))
    if manifest.get("spec") not in D.SUPPORTED_SPECS:
        access.append(D.Diag("SPEC_UNSUPPORTED", f"{manifest.get('spec')!r}; supported {D.SUPPORTED_SPECS}"))
    # Fixture vs authorized-real (never inferred; a real manifest without authorization is refused here,
    # before any example bytes are read).
    access += D.gate_smoke(manifest) if _is_fixture_manifest(manifest) \
        else D.gate_experimental(manifest, manifest_sha, authorization)
    if access:
        return access, None, None, None

    # ── Authorized: ONE capture of TRAIN then VALIDATION; verify+parse the SAME bytes (defect 1). ──
    diags = []
    # INTERNAL_TEST must be DECLARED (metadata inspection, no open) so the split is not silently incomplete.
    idx = D._artifact_index(manifest)
    for prot in D.NEVER_READ_SPLITS[:1]:
        if D.ROWS_FILE.format(split=prot) not in idx:
            diags.append(D.Diag("PROTECTED_SPLIT_NOT_IN_MANIFEST", prot))
    train, tdiags = _verify_and_parse(dataset_dir, manifest, D.READ_SPLITS[0], vocabulary)
    val, vdiags = _verify_and_parse(dataset_dir, manifest, D.READ_SPLITS[1], vocabulary)
    diags += tdiags + vdiags
    diags += D.check_rows(train, vocabulary) + D.check_rows(val, vocabulary)
    diags += D.check_disjoint(train, val)
    return diags, train, val, manifest_sha


def gate_diagnostics(dataset_dir: str, *, recipe_path: str = DEFAULT_RECIPE,
                     authorization: str | None = None) -> list:
    """Diagnostic-only: every reason these examples are not consumable (empty = consumable). Returns no
    examples, and opens no rows/meta file when the access gate fails."""
    return _load_and_check(dataset_dir, recipe_path=recipe_path, authorization=authorization)[0]


def load_examples(dataset_dir: str, *, recipe_path: str = DEFAULT_RECIPE,
                  authorization: str | None = None) -> dict:
    """Return `{"TRAIN": [example…], "VALIDATION": [example…]}` ONLY when every gate/row check passes;
    otherwise raise `ExampleExchangeError` (no bypass). ONE capture: the examples returned are exactly the
    bytes that were hashed, parsed and verified (no re-read). Opens only TRAIN/VALIDATION rows+meta, and
    only after the access gate passes — never a protected-role file."""
    diags, train, val, manifest_sha = _load_and_check(
        dataset_dir, recipe_path=recipe_path, authorization=authorization)
    if diags:
        raise ExampleExchangeError(f"examples are not consumable: {sorted({d.code for d in diags})}")
    return {D.READ_SPLITS[0]: [_to_example(r, manifest_sha) for r in train],
            D.READ_SPLITS[1]: [_to_example(r, manifest_sha) for r in val]}


def main(argv=None) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Load / verify V5 TRAIN+VALIDATION examples (reader; no training)")
    ap.add_argument("--dataset", required=True, help="stage-4 generator output dir (manifest.json + rows.*.jsonl)")
    ap.add_argument("--recipe", default=DEFAULT_RECIPE)
    ap.add_argument("--authorization", default=None, help="required for a non-fixture (real/provisional) manifest")
    args = ap.parse_args(argv)
    diags = gate_diagnostics(args.dataset, recipe_path=args.recipe, authorization=args.authorization)
    if diags:
        print("NOT CONSUMABLE:")
        for d in diags:
            print(f"  {getattr(d, 'code', '?')}: {getattr(d, 'detail', '')}")
        return 1
    ex = load_examples(args.dataset, recipe_path=args.recipe, authorization=args.authorization)
    print("CONSUMABLE:", json.dumps({s: len(rows) for s, rows in ex.items()}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
