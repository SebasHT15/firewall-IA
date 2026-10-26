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
* Row eligibility is enforced: `label_status ∈ {VERIFIED, POLICY_DEFINED}`, or the explicitly authorized TRAINING_REFERENCE
  contract; not excluded/sliced, output in
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
      "label_status": "VERIFIED"|"POLICY_DEFINED"|"TRAINING_REFERENCE", # gated eligibility
      "label_basis": <str|None>,                             # provenance; NEVER a feature, NEVER ⇒ VERIFIED
      "row_contract": <str|None>,                            # D72-ratified contract; metadata only
      "audit_type": <str|None>,                              # #80 dataset provenance (manifest); metadata only
      "label_status_basis": <str|None>,                      # #80 per-row provenance; metadata, NEVER ⇒ VERIFIED
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


def _to_example(row: dict, manifest_sha: str, audit_type=None, row_contract=None) -> dict:
    meta = row["meta"]
    return {
        "split": row["split"],
        "row_index": row["index"],
        "text": row["text"],
        "output": row["output"],
        "label": meta.get("label"),
        "label_status": meta.get("label_status"),
        "label_basis": meta.get("label_basis"),
        # #80 provenance (additive; the fields above are UNCHANGED). `audit_type` is the dataset-level
        # provenance from the manifest (who audited); `label_status_basis` is the per-row provenance an
        # ai_audited dataset carries. Both are METADATA: never a feature, never promoted to VERIFIED. They
        # mirror what `v5_train_data.check_audit_rows` validates, so Model 2 reads the SAME provenance the
        # gate enforced instead of re-deriving it.
        "audit_type": audit_type,
        "row_contract": row_contract,
        "label_status_basis": meta.get("label_status_basis"),
        "text_sha256": meta.get("text_sha256"),
        "identities": {k: meta.get(k) for k in D.IDENTITY_KEYS},
        "manifest_sha256": manifest_sha,
        "eligibility": {"trainable": True},
    }


def _verify_and_parse(dataset_dir: str, manifest: dict, split: str, vocabulary=None) -> tuple:
    """SINGLE verified capture of one allowed split. Delegates to `v5_train_data.capture_and_parse_split`, so
    the trainer and this reader share ONE capture implementation (read bytes once, hash THOSE bytes against
    the manifest, parse the SAME bytes). Only TRAIN/VALIDATION are opened; a protected-role file never is."""
    return D.capture_and_parse_split(dataset_dir, manifest, split)


def _load_and_check(dataset_dir: str, *, recipe_path: str, authorization: str | None) -> tuple:
    """One pass: resolve the manifest/recipe, run the ACCESS gate (schema/spec + fixture-or-authorization)
    BEFORE opening any rows/meta, and only if access is granted do a single capture + verify + parse +
    eligibility/disjointness. Returns (diags, train_rows, val_rows, manifest_sha, audit_type, row_contract). `gate_diagnostics` and
    `load_examples` both go through here, so a consumed example is exactly the one that was verified."""
    # PATH PROTECTION ON ENTERING A PUBLIC READER: refuse a protected dataset dir (or a symlink to one)
    # before anything is opened.
    try:
        D.C.assert_not_protected(dataset_dir)
    except SystemExit as e:
        return [D.Diag("PROTECTED_PATH", str(e))], None, None, None, None, None
    try:
        manifest, manifest_sha = D.load_manifest(dataset_dir)
    except (OSError, ValueError) as e:
        return [D.Diag("MANIFEST_UNREADABLE", type(e).__name__)], None, None, None, None, None
    try:
        recipe, _ = D.load_recipe(recipe_path)
        vocabulary = D.recipe_vocabulary(recipe)
    except (OSError, ValueError) as e:
        return [D.Diag("RECIPE_UNREADABLE", type(e).__name__)], None, None, None, None, None

    # ── ACCESS gate FIRST: if this fails, STOP before opening any rows/meta file (defect 2). ──
    access = []
    if manifest.get("schema") != D.MANIFEST_SCHEMA:
        access.append(D.Diag("MANIFEST_SCHEMA", f"{manifest.get('schema')!r} != {D.MANIFEST_SCHEMA!r}"))
    if manifest.get("spec") not in D.SUPPORTED_SPECS:
        access.append(D.Diag("SPEC_UNSUPPORTED", f"{manifest.get('spec')!r}; supported {D.SUPPORTED_SPECS}"))
    # Fixture vs authorized-real (never inferred; a real manifest without authorization is refused here,
    # before any example bytes are read).
    experimental_cap = None if _is_fixture_manifest(manifest) else D._capture_record(authorization)
    access += D.gate_smoke(manifest) if _is_fixture_manifest(manifest) \
        else D.gate_experimental(manifest, manifest_sha, authorization, captured=experimental_cap)
    if access:
        return access, None, None, None, None, None

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
    diags += D.check_rows(train, vocabulary,row_contract=manifest.get('row_contract')) + D.check_rows(val, vocabulary,row_contract=manifest.get('row_contract'))
    diags += D.check_disjoint(train, val)
    # #80 row-level provenance (concept 3 ↔ 1): the reader enforces the SAME check the trainer gate runs,
    # so an ai_audit row can never ride in under a human/missing manifest and an ai_audit label can never be
    # VERIFIED. For a fixture/human dataset (audit_type None/"human") this is a no-op on BLOCK rows.
    audit_type = manifest.get("audit_type")
    diags += D.check_audit_rows(train + val, audit_type)
    # Category eligibility for an ai_audited PROVISIONAL (EXPERIMENTAL) dataset too — provisional is not a
    # bypass. Outcomes come from the authorization (bound to its audit); absent/non-PASS → refused.
    if audit_type == D.AUDIT_AI and not _is_fixture_manifest(manifest):
        diags += D.check_audit_category_outcomes(train + val, D.experimental_category_outcomes(authorization, captured=experimental_cap))
        diags += D.check_audit_pool_membership(train + val,experimental_cap[1].get('audit_evidence'))
    return diags, train, val, manifest_sha, audit_type, manifest.get('row_contract')


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
    diags, train, val, manifest_sha, audit_type, row_contract = _load_and_check(
        dataset_dir, recipe_path=recipe_path, authorization=authorization)
    if diags:
        raise ExampleExchangeError(f"examples are not consumable: {sorted({d.code for d in diags})}")
    return {D.READ_SPLITS[0]: [_to_example(r, manifest_sha, audit_type, row_contract) for r in train],
            D.READ_SPLITS[1]: [_to_example(r, manifest_sha, audit_type, row_contract) for r in val]}


def load_final_examples(dataset_dir: str, *, dataset_prereg: str | None, freeze_record: str | None,
                        ai_audit_authorization: str | None = None, recipe_path: str = DEFAULT_RECIPE) -> dict:
    """FINAL DATASET consumption for a model consumer (e.g. Model 2), on ONE verified capture.

    Returns `{"examples": {"TRAIN":[...],"VALIDATION":[...]}, "dataset_final_evidence": {...}}` or raises
    `ExampleExchangeError`. It runs the DATASET-level FINAL gates (`v5_train_data.gate_dataset_final`:
    schema/spec, REAL gated build, ratified generator values, attack-label basis, audit provenance, the
    ai-audit owner authorization, the committed dataset preregistration and the freeze record) plus the
    row-level checks (eligibility, TRAIN×VALIDATION disjointness, audit row provenance, and — for an
    ai_audited dataset — the category outcomes from the freeze record).

    It DELIBERATELY DOES NOT run the model-recipe gates (recipe sections, training preregistration, library
    pins, LoRA/TinyLlama): an eligible dataset is not an authorization to train any particular model. The
    consumer adds its own recipe/pins/training-permission gates. Only the output VOCABULARY is read from
    `recipe_path` (a dataset output contract, ratified by D71), never the model pins.

    Access runs BEFORE any row file is opened; the examples are the exact bytes verified (no verify-then-reread).
    Opens only TRAIN/VALIDATION; a protected-role file is never opened. FINAL consumption requires the spec to
    be in `SUPPORTED_SPECS` (owner r4 activation) and, for ai_audited data, a ratified ai-audit authorization
    schema (activated by D72); concrete owner records and eligible evidence remain mandatory."""
    # PATH PROTECTION ON ENTERING A PUBLIC READER (before anything is opened).
    try:
        D.C.assert_not_protected(dataset_dir)
    except SystemExit as e:
        raise ExampleExchangeError(f"dataset path is protected: {e}")
    try:
        manifest, manifest_sha = D.load_manifest(dataset_dir)
    except (OSError, ValueError) as e:
        raise ExampleExchangeError(f"manifest unreadable: {type(e).__name__}")
    try:
        recipe, _ = D.load_recipe(recipe_path)
        vocabulary = D.recipe_vocabulary(recipe)
    except (OSError, ValueError) as e:
        raise ExampleExchangeError(f"recipe/vocabulary unreadable: {type(e).__name__}")

    # ── SINGLE capture of the three dataset records (prereg / freeze / auth): the SAME bytes are used to
    # gate, decide categories and build the evidence (no re-read after verification, no TOCTOU). ──
    cap = D.capture_dataset_records(dataset_prereg, freeze_record, ai_audit_authorization)
    prereg_sha, prereg_obj, _ = cap["prereg"]
    freeze_sha, freeze_obj, _ = cap["freeze"]
    auth_sha, _auth_obj, _ = cap["auth"]
    audit = D.audit_item_of(freeze_obj) if freeze_obj is not None else {}
    category_outcomes = audit.get("category_outcomes")

    # ── ACCESS + DATASET gate FIRST (on the captured records): if it fails, no row/meta file is opened. ──
    access = []
    if manifest.get("schema") != D.MANIFEST_SCHEMA:
        access.append(D.Diag("MANIFEST_SCHEMA", f"{manifest.get('schema')!r} != {D.MANIFEST_SCHEMA!r}"))
    if manifest.get("spec") not in D.SUPPORTED_SPECS:
        access.append(D.Diag("SPEC_UNSUPPORTED", f"{manifest.get('spec')!r}; supported {D.SUPPORTED_SPECS}"))
    access += D.gate_dataset_final(manifest, manifest_sha, dataset_prereg=dataset_prereg,
                                   freeze_record=freeze_record, ai_audit_authorization=ai_audit_authorization,
                                   captured=cap)
    access += D.protected_split_declared_diags(manifest)
    # Bind the returned vocabulary to the DATASET contract: the recipe vocabulary id must equal the one the
    # preregistration ratified (otherwise the examples would carry a vocabulary the dataset did not fix).
    prereg_vocab = ((prereg_obj or {}).get("ratified") or {}).get("vocabulary_id") if isinstance(prereg_obj, dict) else None
    if prereg_vocab is None or prereg_vocab != recipe["vocabulary"]["id"]:
        access.append(D.Diag("VOCABULARY_NOT_BOUND",
                             f"recipe vocabulary {recipe['vocabulary']['id']!r} != dataset preregistration {prereg_vocab!r}"))
    if access:
        raise ExampleExchangeError(f"dataset is not FINAL-consumable: {sorted({d.code for d in access})}")

    # ── Authorized: ONE verified capture of TRAIN then VALIDATION; row-level checks on the SAME bytes. ──
    diags = []
    train, td = _verify_and_parse(dataset_dir, manifest, D.READ_SPLITS[0])
    val, vd = _verify_and_parse(dataset_dir, manifest, D.READ_SPLITS[1])
    diags += td + vd
    audit_type = manifest.get("audit_type")
    row_contract = manifest.get('row_contract')
    if not any(d.code in ("ARTIFACT_MISSING", "ARTIFACT_NOT_IN_MANIFEST") for d in diags):
        diags += D.check_rows(train, vocabulary,row_contract=manifest.get('row_contract')) + D.check_rows(val, vocabulary,row_contract=manifest.get('row_contract'))
        diags += D.check_disjoint(train, val)
        diags += D.check_audit_rows(train + val, audit_type)
        if audit_type == D.AUDIT_AI:
            if audit.get("components") is not None:
                # Multi-component dataset: per-component audit + per-row binding (derived category, identity,
                # committed-evidence gate, no combined-pool PASS). Supersedes the single-pool checks.
                diags += [D.Diag(code, det) for code, det in
                          D.CB.verify_components(train + val, audit, committed_checker=D.git_committed_unmodified)]
            else:
                diags += D.check_audit_category_outcomes(train + val, category_outcomes)   # from the captured freeze
                diags += D.check_audit_pool_membership(train + val,audit.get('audit_evidence'))
    if diags:
        raise ExampleExchangeError(f"FINAL examples are not consumable: {sorted({d.code for d in diags})}")

    evidence = {
        "mode": "FINAL",
        "row_contract": manifest.get('row_contract'),
        "manifest_sha256": manifest_sha,
        "spec": manifest.get("spec"),
        "audit_type": audit_type,
        "attack_label_basis": manifest.get("attack_label_basis"),
        "preregistration_sha256": prereg_sha,              # captured bytes' sha (== manifest.preregistration_sha256, gated by F4)
        "freeze_record_sha256": freeze_sha,                # captured bytes' sha
        "ai_audit_authorization_sha256": auth_sha,         # captured bytes' sha
        "category_outcomes": category_outcomes if audit_type == D.AUDIT_AI else None,   # from the captured freeze
        "vocabulary_id": recipe["vocabulary"]["id"],
        "vocabulary_bound_to_preregistration": prereg_vocab == recipe["vocabulary"]["id"] if prereg_vocab is not None else None,
        "token_budget_B": (manifest.get("token_budget") or {}).get("B"),
        "value_statuses": manifest.get("value_statuses"),
        "rows": {"TRAIN": len(train), "VALIDATION": len(val)},
        "splits_opened": list(D.READ_SPLITS),
        "splits_never_opened": list(D.NEVER_READ_SPLITS) + ["slices.*"],
        "identity_keys_checked_disjoint": list(D.IDENTITY_KEYS),
        # Explicitly NOT evaluated here — the consumer model owns these:
        "model_recipe_gates_not_run": ["F6_training_prereg", "F7_recipe_sections", "F8_recipe_token_budget",
                                       "F9_library_pins", "LoRA/TinyLlama_pins", "training_permission"],
    }
    return {
        "examples": {D.READ_SPLITS[0]: [_to_example(r, manifest_sha, audit_type, row_contract) for r in train],
                     D.READ_SPLITS[1]: [_to_example(r, manifest_sha, audit_type, row_contract) for r in val]},
        "dataset_final_evidence": evidence,
    }


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
