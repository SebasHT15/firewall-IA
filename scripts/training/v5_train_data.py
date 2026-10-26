#!/usr/bin/env python3
"""V5 training readiness — dataset gates, example construction and tokenization checks.

Used by `finetune_v5.py`. Imports no ML library: the tokenizer is passed in as an object, exactly as
`control_plane/v5_tokenization.py` expects, so the gates and the example builder are testable without
torch.

THREE MODES, never interchangeable
----------------------------------
* SMOKE — engineering check of the pipeline. Accepts ONLY a stage-4 synthetic fixture build
  (`manifest.status` FIXTURE, generator mode `fixture`, attack-label basis `fixture_synthetic`).
  A smoke run is NOT evidence of V5 model quality, whatever its loss.
* EXPERIMENTAL — provisional data the owner authorized in writing for one dataset manifest. Refuses
  fixtures (use SMOKE), refuses rows whose label is not VERIFIED / POLICY_DEFINED. Artifacts are
  provisional; no definitive performance claim.
* FINAL — the real V5 fine-tune. Refuses unless EVERY condition holds (see `gate_final`): REAL build,
  all generator values RATIFIED, attack labels from the post-filter audit, build gates passing, a
  committed dataset preregistration whose hash the manifest records, a committed dataset freeze record
  covering every item of spec §11.3, a committed training preregistration that pins this recipe and the
  template fingerprint, a RATIFIED recipe, a clean git tree and the pinned library versions. All failing
  conditions are reported together, then the run stops before any model is loaded.

All modes, always:
* only TRAIN and VALIDATION are opened. INTERNAL_TEST, E6_RESERVE, slices and every protected path
  (External Test, V4 eval, CSIC, V4-clean) are never read (D37–D40, D58, spec §9);
* artifact SHA-256 of every file read is verified against the manifest;
* row/meta line alignment, label status, vocabulary, and TRAIN × VALIDATION disjointness of every
  identity (text, pair, payload family, record, cluster, template, value entry) are re-checked;
* examples are tokenized with the FROZEN template-safe method (spec §5.4, `encode_prompt`), never by
  TRL; a row that would need truncation, carries a special id in its content, exceeds `B`, breaks the
  BOS/EOS layout or does not round-trip its output is a hard failure — nothing is silently dropped.

Nothing here modifies a dataset, a frozen contract or a decision record.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from dataclasses import dataclass, field

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))
for _p in (os.path.join(REPO_ROOT, "control_plane"), os.path.join(REPO_ROOT, "scripts", "dataset")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import v5_output_contract as OC  # noqa: E402
import v5_row_contract as RC
import v5_audit_evidence as AE
import v5_component_binding as CB  # noqa: E402  (per-component audit binding; backward compatible)
import v5_pools_common as C  # noqa: E402  (assert_not_protected: stdlib only)
import v5_tokenization as T  # noqa: E402

SMOKE, EXPERIMENTAL, FINAL = "SMOKE", "EXPERIMENTAL", "FINAL"
MODES = (SMOKE, EXPERIMENTAL, FINAL)
EVIDENCE_CLASS = {
    SMOKE: "ENGINEERING_SMOKE — pipeline check on synthetic fixtures; NOT evidence of V5 model quality",
    EXPERIMENTAL: "EXPERIMENTAL_PROVISIONAL — authorized provisional data; no definitive performance claim",
    FINAL: "FINAL — gated V5 fine-tune",
}

RECIPE_SCHEMA = "v5-training-recipe/v1"
MANIFEST_SCHEMA = "v5-generator-manifest/v1"
AUTH_SCHEMA = "v5-experimental-authorization/v1"
FREEZE_SCHEMA = "v5-dataset-freeze-record/v1"
TRAINING_PREREG_SCHEMA = "v5-training-preregistration/v1"

# D72 activates r4 with its explicit row-contract addendum. Both revisions still
# require their own provenance, freeze checklist and concrete authorization records.
SUPPORTED_SPECS = ("V5-DATA-SPEC-r3", "V5-DATA-SPEC-r4")  # D72
READ_SPLITS = ("TRAIN", "VALIDATION")
NEVER_READ_SPLITS = ("INTERNAL_TEST", "E6_RESERVE")
ROWS_FILE, META_FILE = "rows.{split}.jsonl", "rows.{split}.meta.jsonl"

TRAINABLE_LABEL_STATUSES = ("VERIFIED", "POLICY_DEFINED")
RATIFIED_STATUSES = ("RATIFIED", "APPROVED")
RECIPE_SECTIONS = ("base_model", "template", "vocabulary", "token_budget", "loss", "quantization", "lora",
                   "optimization", "seed", "library_pins")
LOSS_MODES = ("completion", "full_sequence")
DATASET_PREREG_DIR = os.path.join("reports", "v5", "dataset-preregistration-v1")
OUTPUT_ROOT = os.path.join(REPO_ROOT, "model-output-v5")

# Spec r3 §11.3, "Mandatory before the dataset freeze". The gate encodes r3 ONLY: a later revision
# (e.g. an r4 that replaces the human review) must update this list deliberately, never implicitly.
FREEZE_ITEMS = {
    "V5-DATA-SPEC-r3": (
        "human_review_prefilter_sample",   # 1. owner's human review of the 95-item pre-filter sample
        "post_filter_audit",               # 2. post-filter audit of every ML-trained category (§7)
        "blocking_checks",                 # 3. every BLOCKING check of §7, incl. byte-identical regeneration
        "dataset_preregistration",         # 4. preregistration of §11.2 values, committed before the build
        "stab_held_sealed",                # 5. STAB-HELD built and sealed
        "dataset_freeze_report",           # 6. the dataset freeze report (C §8)
    ),
    # D67 r4 checklist, activated under D72; individual dataset freeze evidence remains required.
    # Item 1 (`human_review_prefilter_sample`) is RETIRED by D67 and is removed HERE, explicitly, in this
    # table only; the r3 row above is untouched. Item 2 stays and is bound to the §7 AI-assisted protocol by
    # the audit-provenance gates below (F3a–F3d) — retiring item 1 does not relax anything else.
    "V5-DATA-SPEC-r4": (
        "post_filter_audit",
        "blocking_checks",
        "dataset_preregistration",
        "stab_held_sealed",
        "dataset_freeze_report",
    ),
}

# ── Audit provenance vs category outcome vs row status vs owner authorization: FOUR DISTINCT CONCEPTS ──
# (1) audit provenance — who audited. Manifest field `audit_type` (PROPOSED field; absent in every
#     manifest produced today -> FINAL refuses). Never inferred from `attack_label_basis`.
AUDIT_HUMAN, AUDIT_AI = "human", "ai_audited"
AUDIT_TYPES = (AUDIT_HUMAN, AUDIT_AI)
# Which provenance each spec revision's §11.3 allows. Anything else (unknown type, or a type that the
# spec revision does not define) is refused, not downgraded: r3 demands the human review, r4 is AI-assisted.
SPEC_AUDIT_TYPES = {"V5-DATA-SPEC-r3": (AUDIT_HUMAN,), "V5-DATA-SPEC-r4": (AUDIT_AI,)}
# (2) category audit outcome (r4 prereg `status_semantics`). Only PASS_AI_AUDITED makes a category eligible.
#     It is NOT a label_status and is never written to / compared as one.
OUTCOME_PASS = "PASS_AI_AUDITED"
AUDIT_OUTCOMES = (OUTCOME_PASS, "FAIL", "INSUFFICIENT_EVIDENCE")
AUDIT_OUTCOME_TOKENS = frozenset(AUDIT_OUTCOMES) | {"AI_AUDITED", "PENDING"}   # tokens that are NOT label statuses
# (3) row label_status: TRAINABLE_LABEL_STATUSES above. VERIFIED = independently established, never
#     conferred by an audit pass or by model agreement (r4 prereg `status_semantics.VERIFIED`).
#     PROPOSED per-row field `label_status_basis`, required on attack rows of an ai_audited dataset only.
LABEL_BASES = ("independent_evidence", "policy_defined", "ai_audit")
# D72 ratifies the explicit #80 row-contract addendum. IA references use the
# contract-bound TRAINING_REFERENCE status, never VERIFIED or a fictitious policy.
AI_AUDIT_ROW_STATUS_ALLOWED = (RC.TRAINING_REFERENCE,)
# These schema identifiers are retained verbatim for wire compatibility. The
# PROPOSED suffix is historical; D72 ratifies their definitions, not any record.
PROPOSED_AI_AUDIT_AUTH_SCHEMA = "v5-ai-audit-training-authorization/v1-PROPOSED"
AI_AUDIT_AUTH_SCHEMA = PROPOSED_AI_AUDIT_AUTH_SCHEMA

TEMPLATES = {"V5_CANDIDATE_TEMPLATE": T.V5_CANDIDATE_TEMPLATE}
VOCABULARIES = {"PILOT_VOCABULARY": OC.PILOT_VOCABULARY, "VOCABULARY_ALT_A": OC.VOCABULARY_ALT_A,
                "VOCABULARY_ALT_B": OC.VOCABULARY_ALT_B}

IDENTITY_KEYS = ("text_sha256", "pair_id", "payload_family_id", "payload_record_id", "struct_cluster_id",
                 "template_id", "value_entries")
MAX_EXAMPLES_PER_CODE = 5
# Per-row codes are capped in the report (one line per code summarises the rest); gate-level codes never are.
ROW_CODES = frozenset({"META_NOT_ALIGNED", "ROW_SCHEMA", "ROW_SPLIT_MISMATCH", "ROW_TEXT_HASH", "ROW_OUTPUT_MISMATCH",
                       "LABEL_NOT_TRAINABLE", "EXCLUDED_ROW_IN_SPLIT", "OUTPUT_NOT_IN_VOCABULARY",
                       "LABEL_OUTPUT_INCONSISTENT", "CONTENT_SPECIAL_IDS", "CONTENT_OVER_BUDGET",
                       "PROMPT_PREFIX_MISMATCH", "EOS_INVALID", "SPECIAL_LAYOUT", "TRUNCATION_REQUIRED",
                       "OUTPUT_ROUNDTRIP", "LABEL_STATUS_IS_AUDIT_OUTCOME", "AUDIT_ROW_BASIS_MISSING",
                       "AUDIT_ROW_BASIS_INCONSISTENT", "AUDIT_CONFERRED_VERIFIED", "AUDIT_ROW_BASIS_CONTRADICTS_MANIFEST",
                       "AUDIT_CATEGORY_OUTCOME_MISSING", "AUDIT_CATEGORY_NOT_PASSED", "AUDIT_ROW_STATUS_NOT_AUTHORIZED",
                       "BLOCK_ROW_WITHOUT_CATEGORY"})

# Gate codes that mean ACCESS to the dataset is not granted: when any is present, `prepare` does NOT open
# the TRAIN/VALIDATION row files (the access gate runs before the rows are read). Row-level checks only run
# once access is granted. Protected-role files are never opened in any case.
ACCESS_DENIED_CODES = frozenset({
    "MANIFEST_SCHEMA", "SPEC_UNSUPPORTED", "PROTECTED_PATH", "OUTPUT_DIR_NOT_EXCLUSIVE",
    "SMOKE_REQUIRES_FIXTURE", "EXPERIMENTAL_REFUSES_FIXTURE",
    "AUTHORIZATION_MISSING", "AUTHORIZATION_UNREADABLE", "AUTHORIZATION_SCHEMA", "AUTHORIZATION_SCOPE",
    "AUTHORIZATION_NOT_PROVISIONAL", "AUTHORIZATION_DATASET_MISMATCH", "AUTHORIZATION_INCOMPLETE",
    "AUTHORIZATION_LABEL_POLICY", "AUTHORIZATION_AUDIT_EVIDENCE", "AUTHORIZATION_NOT_COMMITTED", "F3_AUDIT_TYPE_UNKNOWN", "F3_AUDIT_TYPE_SPEC_MISMATCH",
    "F10_AI_AUDIT_AUTHORIZATION", "CALIBRATION_DATA_NOT_FOR_TRAINING",
})


# ───────────────────────────── diagnostics ─────────────────────────────
@dataclass(frozen=True)
class Diag:
    code: str
    detail: str

    def as_dict(self):
        return {"code": self.code, "detail": self.detail}


class GateRefused(Exception):
    """The mode's preconditions are not met. Carries every failing condition, not just the first."""

    def __init__(self, mode: str, diagnostics: list):
        self.mode = mode
        self.diagnostics = list(diagnostics)
        lines = "\n".join(f"  - [{d.code}] {d.detail}" for d in self.diagnostics)
        super().__init__(f"{mode} REFUSED — {len(self.diagnostics)} unmet condition(s); training NOT started:\n{lines}")


def _capped(diags: list) -> list:
    """Keep at most MAX_EXAMPLES_PER_CODE diagnostics per row-level code, plus one summary line per code."""
    out, seen = [], {}
    for d in diags:
        seen[d.code] = seen.get(d.code, 0) + 1
        if d.code not in ROW_CODES or seen[d.code] <= MAX_EXAMPLES_PER_CODE:
            out.append(d)
    for code, n in seen.items():
        if code in ROW_CODES and n > MAX_EXAMPLES_PER_CODE:
            out.append(Diag(code, f"... {n - MAX_EXAMPLES_PER_CODE} more of this code ({n} total)"))
    return out


# ───────────────────────────── hashing, git ─────────────────────────────
def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def canonical_json(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _git(*args, cwd=REPO_ROOT):
    return subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=False)


def git_state(repo: str = REPO_ROOT) -> dict:
    head = _git("rev-parse", "HEAD", cwd=repo)
    status = _git("status", "--porcelain", "--untracked-files=no", cwd=repo)
    branch = _git("rev-parse", "--abbrev-ref", "HEAD", cwd=repo)
    dirty = [ln[3:] for ln in status.stdout.splitlines() if ln.strip()]
    return {"commit": head.stdout.strip() or None, "branch": branch.stdout.strip() or None,
            "tracked_dirty_files": dirty, "clean": head.returncode == 0 and status.returncode == 0 and not dirty}


def git_committed_unmodified(path: str, repo: str = REPO_ROOT) -> bool:
    """True iff `path` is tracked and identical to HEAD (no staged or unstaged change)."""
    rel = os.path.relpath(os.path.realpath(path), os.path.realpath(repo))
    if rel.startswith(".."):
        return False
    tracked = _git("ls-files", "--error-unmatch", "--", rel, cwd=repo).returncode == 0
    clean = _git("diff", "--quiet", "HEAD", "--", rel, cwd=repo).returncode == 0
    return tracked and clean


# ───────────────────────────── recipe ─────────────────────────────
def load_recipe(path: str) -> tuple:
    try:C.assert_not_protected(path)
    except SystemExit as e:raise ValueError('protected recipe path') from e
    with open(path, "rb") as fh:
        data = fh.read()
    recipe = json.loads(data)
    if recipe.get("schema") != RECIPE_SCHEMA:
        raise ValueError(f"recipe schema {recipe.get('schema')!r} != {RECIPE_SCHEMA!r}")
    missing = [s for s in RECIPE_SECTIONS if s not in recipe]
    if missing:
        raise ValueError(f"recipe sections missing: {missing}")
    if recipe["template"]["id"] not in TEMPLATES:
        raise ValueError(f"unknown template id {recipe['template']['id']!r}")
    if recipe["vocabulary"]["id"] not in VOCABULARIES:
        raise ValueError(f"unknown vocabulary id {recipe['vocabulary']['id']!r}")
    if recipe["loss"]["on"] not in LOSS_MODES:
        raise ValueError(f"loss.on must be one of {LOSS_MODES}")
    OC.check_vocabulary(VOCABULARIES[recipe["vocabulary"]["id"]])
    return recipe, sha256_bytes(data)


def recipe_template(recipe):
    return TEMPLATES[recipe["template"]["id"]]


def recipe_vocabulary(recipe):
    return tuple(VOCABULARIES[recipe["vocabulary"]["id"]])


def template_fingerprint(recipe) -> str:
    return OC.fingerprint(recipe_template(recipe), recipe_vocabulary(recipe))[0]


def unratified_recipe_sections(recipe) -> list:
    out = []
    if recipe.get("status") not in RATIFIED_STATUSES:
        out.append(("recipe", recipe.get("status")))
    for s in RECIPE_SECTIONS:
        st = recipe[s].get("status")
        if st not in RATIFIED_STATUSES:
            out.append((s, st))
    return out


# ───────────────────────────── manifest and artifacts ─────────────────────────────
def load_manifest(dataset_dir: str) -> tuple:
    path = os.path.join(dataset_dir, "manifest.json")
    try:C.assert_not_protected(path)
    except SystemExit as e:raise ValueError('protected manifest path') from e
    with open(path, "rb") as fh:
        data = fh.read()
    return json.loads(data), sha256_bytes(data)


def _artifact_index(manifest) -> dict:
    return {a["path"]: a for a in manifest.get("artifacts", [])}


def verify_read_artifacts(dataset_dir: str, manifest: dict) -> list:
    """Every file this trainer reads must be listed in the manifest with a matching sha256 and size.
    INTERNAL_TEST files must be listed but are NEVER opened (not even to hash them)."""
    diags, idx = [], _artifact_index(manifest)
    for split in READ_SPLITS:
        for pat in (ROWS_FILE, META_FILE):
            name = pat.format(split=split)
            path = os.path.join(dataset_dir, name)
            art = idx.get(name)
            if art is None:
                diags.append(Diag("ARTIFACT_NOT_IN_MANIFEST", name))
                continue
            if not os.path.isfile(path):
                diags.append(Diag("ARTIFACT_MISSING", name))
                continue
            got = sha256_file(path)
            if got != art.get("sha256") or os.path.getsize(path) != art.get("bytes"):
                diags.append(Diag("ARTIFACT_HASH_MISMATCH", f"{name}: manifest {art.get('sha256')} file {got}"))
    for split in NEVER_READ_SPLITS[:1]:
        if ROWS_FILE.format(split=split) not in idx:
            diags.append(Diag("PROTECTED_SPLIT_NOT_IN_MANIFEST",
                              f"{split} is not declared in the manifest; the split may be incomplete"))
    return diags


def _jsonl_records(text: str) -> list:
    """Parse JSONL splitting on LF ONLY (accepting a trailing CR for CRLF). NOT `str.splitlines()`, which
    also breaks on U+0085 / U+2028 / U+2029 — characters that are valid, unescaped, inside a JSON string
    value, so splitlines() would wrongly cut a row in two. JSON strings never contain a literal LF/CR
    (those must be escaped), so LF is the only true record separator."""
    return [json.loads(line) for raw in text.split("\n") for line in (raw.rstrip("\r"),) if line.strip()]


def parse_split(rows_text: str, meta_text: str, split: str) -> tuple:
    """Pure parse of already-read TRAIN/VALIDATION rows+meta TEXT into rows (each {'text','output','meta'})
    plus alignment diagnostics. No I/O: an integrity-checking caller passes the EXACT text whose bytes it
    hashed, so the hashed bytes and the parsed bytes are the same (load_split reads then delegates here)."""
    rows = _jsonl_records(rows_text)
    metas = _jsonl_records(meta_text)
    diags, out = [], []
    if len(rows) != len(metas):
        diags.append(Diag("META_NOT_ALIGNED", f"{split}: {len(rows)} rows vs {len(metas)} meta lines"))
        return out, diags
    for i, (r, m) in enumerate(zip(rows, metas)):
        if set(r) != {"text", "output"}:
            diags.append(Diag("ROW_SCHEMA", f"{split}[{i}]: keys {sorted(r)}"))
            continue
        if m.get("split") != split or m.get("disposition") != "split":
            diags.append(Diag("ROW_SPLIT_MISMATCH", f"{split}[{i}]: meta split={m.get('split')} "
                                                     f"disposition={m.get('disposition')}"))
        if sha256_bytes(r["text"].encode("utf-8")) != m.get("text_sha256"):
            diags.append(Diag("ROW_TEXT_HASH", f"{split}[{i}]: text does not match meta.text_sha256"))
        if r["output"] != m.get("output"):
            diags.append(Diag("ROW_OUTPUT_MISMATCH", f"{split}[{i}]: output differs from meta.output"))
        out.append({"text": r["text"], "output": r["output"], "meta": m, "index": i, "split": split})
    return out, diags


def load_split(dataset_dir: str, split: str) -> tuple:
    """Rows of TRAIN or VALIDATION, each {'text', 'output', 'meta'}; plus alignment diagnostics. Reads the
    two files and delegates to the pure `parse_split`; only TRAIN/VALIDATION are ever read (single-run
    guard, spec §9)."""
    if split not in READ_SPLITS:
        raise PermissionError(f"{split} is never read by the trainer (single-run guard, spec §9)")
    with open(os.path.join(dataset_dir, ROWS_FILE.format(split=split)), encoding="utf-8") as fh:
        rows_text = fh.read()
    with open(os.path.join(dataset_dir, META_FILE.format(split=split)), encoding="utf-8") as fh:
        meta_text = fh.read()
    return parse_split(rows_text, meta_text, split)


def capture_and_parse_split(dataset_dir: str, manifest: dict, split: str) -> tuple:
    """SINGLE verified capture of one allowed split: read each of the rows+meta files' bytes ONCE, verify
    THOSE exact bytes against the manifest's recorded sha256/size, and parse the SAME bytes. Returns
    (rows, diags). No verify-then-reread: the bytes hashed are the bytes parsed. Only a READ split
    (TRAIN/VALIDATION) is ever opened (single-run guard, spec §9); a protected-role file is never touched.
    Both the trainer's `prepare` and the reader consume this, so neither re-reads what the other verified."""
    if split not in READ_SPLITS:
        raise PermissionError(f"{split} is never read (single-run guard, spec §9)")
    idx, diags, texts = _artifact_index(manifest), [], {}
    for pat in (ROWS_FILE, META_FILE):
        name = pat.format(split=split)
        full = os.path.join(dataset_dir, name)
        # PATH PROTECTION BEFORE OPENING: resolve symlinks and refuse a file whose real target is protected
        # material (External, V4 eval, INTERNAL_TEST, CSIC…) — a symlink to a protected role is never opened.
        try:
            C.assert_not_protected(full)
        except SystemExit as e:
            diags.append(Diag("PROTECTED_PATH", f"{name}: {e}"))
            texts[pat] = None
            continue
        try:
            with open(full, "rb") as fh:
                raw = fh.read()
        except OSError as e:
            diags.append(Diag("ARTIFACT_MISSING", f"{name}: {type(e).__name__}"))
            texts[pat] = None
            continue
        art = idx.get(name)
        if art is None:
            diags.append(Diag("ARTIFACT_NOT_IN_MANIFEST", name))
        elif sha256_bytes(raw) != art.get("sha256") or len(raw) != art.get("bytes"):
            diags.append(Diag("ARTIFACT_HASH_MISMATCH", f"{name}: manifest {art.get('sha256')} consumed {sha256_bytes(raw)}"))
        try:
            texts[pat] = raw.decode("utf-8")
        except UnicodeDecodeError as e:
            diags.append(Diag("ARTIFACT_UNDECODABLE", f"{name}: {type(e).__name__}"))
            texts[pat] = None
    if texts.get(ROWS_FILE) is None or texts.get(META_FILE) is None:
        return [], diags
    rows, pdiags = parse_split(texts[ROWS_FILE], texts[META_FILE], split)   # parses the SAME verified bytes
    return rows, diags + pdiags


def protected_split_declared_diags(manifest: dict) -> list:
    """INTERNAL_TEST must be DECLARED in the manifest (metadata inspection, no file open) so the split is not
    silently incomplete. Never opens the file."""
    idx = _artifact_index(manifest)
    return [Diag("PROTECTED_SPLIT_NOT_IN_MANIFEST", f"{split} is not declared in the manifest; the split may be incomplete")
            for split in NEVER_READ_SPLITS[:1] if ROWS_FILE.format(split=split) not in idx]


def check_rows(rows: list, vocabulary, *, row_contract=None) -> list:
    vocab = frozenset(vocabulary)
    diags = []
    for r in rows:
        m, where = r["meta"], f"{r['split']}[{r['index']}]"
        if m.get("label_status") not in TRAINABLE_LABEL_STATUSES and not RC.is_reference(m,contract=row_contract):
            diags.append(Diag("LABEL_NOT_TRAINABLE", f"{where}: label_status={m.get('label_status')!r}"))
        if m.get("label_status") in AUDIT_OUTCOME_TOKENS:
            # an audit outcome smuggled into the row-status field is a conflation of concepts (2) and (3)
            diags.append(Diag("LABEL_STATUS_IS_AUDIT_OUTCOME",
                              f"{where}: label_status={m.get('label_status')!r} is a category audit outcome, not a row status"))
        if m.get("exclusion_reason") is not None or m.get("slice") is not None:
            diags.append(Diag("EXCLUDED_ROW_IN_SPLIT", f"{where}: exclusion_reason={m.get('exclusion_reason')!r}"))
        if r["output"] not in vocab:
            diags.append(Diag("OUTPUT_NOT_IN_VOCABULARY", f"{where}: {r['output']!r}"))
        label = m.get("label")
        if label not in ("ALLOW", "BLOCK") or not r["output"].startswith(f"{label} | "):
            diags.append(Diag("LABEL_OUTPUT_INCONSISTENT", f"{where}: label={label!r} output={r['output']!r}"))
    return diags


def check_audit_rows(rows: list, audit_type) -> list:
    """Row-level provenance checks tying concept (3) to concept (1). PROPOSED field `label_status_basis`.

    * A row that says its label rests on `ai_audit` inside a dataset whose manifest does not declare
      `audit_type == ai_audited` is a provenance contradiction -> refused (an AI-audited row can never ride
      in under a `human` / missing manifest declaration).
    * In an ai_audited dataset every attack (BLOCK) row must name a known basis, and an audit-based label can
      NEVER be VERIFIED (D67: an audit pass confers no VERIFIED). `independent_evidence` <-> VERIFIED and
      `policy_defined` <-> POLICY_DEFINED must agree.
    Which row status an `ai_audit`-based attack label MAY carry (POLICY_DEFINED?) is an OPEN OWNER DECISION;
    nothing here grants it — the dataset-level authorization (F10) is required whatever the row statuses."""
    diags = []
    ai = audit_type == AUDIT_AI
    for r in rows:
        m, where = r["meta"], f"{r['split']}[{r['index']}]"
        basis, status, label = m.get("label_status_basis"), m.get("label_status"), m.get("label")
        # An `ai_audit` label can NEVER be VERIFIED — checked for EVERY label, so it cannot hide in an ALLOW
        # row (the old code only looked at BLOCK rows).
        if basis == "ai_audit" and status == "VERIFIED":
            diags.append(Diag("AUDIT_CONFERRED_VERIFIED",
                              f"{where}: an ai_audit-based label cannot be VERIFIED (label={label!r})"))
        # An `ai_audit` basis under a manifest that is not ai_audited is a provenance contradiction (any label).
        if basis == "ai_audit" and not ai:
            diags.append(Diag("AUDIT_ROW_BASIS_CONTRADICTS_MANIFEST",
                              f"{where}: label_status_basis='ai_audit' but manifest audit_type={audit_type!r}"))
        if not ai or label != "BLOCK":
            continue
        if basis not in LABEL_BASES:
            diags.append(Diag("AUDIT_ROW_BASIS_MISSING", f"{where}: label_status_basis={basis!r} not in {LABEL_BASES}"))
        elif basis == "ai_audit":
            # D72 permits only the contract-bound training-reference status.
            # VERIFIED and ai_audit + POLICY_DEFINED remain rejected.
            if status not in AI_AUDIT_ROW_STATUS_ALLOWED:
                diags.append(Diag("AUDIT_ROW_STATUS_NOT_AUTHORIZED",
                                  f"{where}: ai_audit label_status={status!r} is not an authorized row status "
                                  f"(allowed by D72={AI_AUDIT_ROW_STATUS_ALLOWED})"))
        elif (basis, status) in (("independent_evidence", "POLICY_DEFINED"), ("policy_defined", "VERIFIED")):
            diags.append(Diag("AUDIT_ROW_BASIS_INCONSISTENT", f"{where}: basis={basis!r} with label_status={status!r}"))
    return diags


def check_audit_category_outcomes(rows: list, outcomes) -> list:
    """ai_audited FINAL: every attack category that has rows in TRAIN/VALIDATION needs a recorded category
    outcome of exactly PASS_AI_AUDITED. FAIL / INSUFFICIENT_EVIDENCE / unknown / missing -> refused.

    A BLOCK row whose `attack_category` is absent, empty or mistyped is REFUSED here (the old code dropped
    `None` from the category set, so such a row slipped through with an empty outcomes map). The category
    key must be a non-empty string before any PASS comparison."""
    diags, outcomes = [], (outcomes if isinstance(outcomes, dict) else {})
    cats = set()
    for r in rows:
        if r["meta"].get("label") != "BLOCK":
            continue
        cat = r["meta"].get("attack_category")
        if not isinstance(cat, str) or not cat.strip():
            diags.append(Diag("BLOCK_ROW_WITHOUT_CATEGORY",
                              f"{r['split']}[{r['index']}]: BLOCK row attack_category={cat!r} (absent/empty/mistyped)"))
            continue
        cats.add(cat)
    for cat in sorted(cats):
        if cat not in outcomes:
            diags.append(Diag("AUDIT_CATEGORY_OUTCOME_MISSING", f"{cat}: no category audit outcome recorded"))
        elif outcomes[cat] != OUTCOME_PASS:
            diags.append(Diag("AUDIT_CATEGORY_NOT_PASSED", f"{cat}: outcome {outcomes[cat]!r}; only {OUTCOME_PASS!r} is eligible"))
    return diags


def _identity_set(rows, key) -> set:
    s = set()
    for r in rows:
        v = r["meta"].get(key)
        if v is None:
            continue
        if isinstance(v, list):
            s.update(tuple(x) if isinstance(x, list) else x for x in v)
        else:
            s.add(v)
    return s


def check_disjoint(train: list, validation: list) -> list:
    """TRAIN × VALIDATION must share no identity (spec §4.6 SPL gates, re-checked at training time)."""
    diags = []
    for key in IDENTITY_KEYS:
        shared = _identity_set(train, key) & _identity_set(validation, key)
        if shared:
            diags.append(Diag("SPLIT_LEAKAGE", f"{key}: {len(shared)} value(s) in both TRAIN and VALIDATION"))
    return diags


# ───────────────────────────── mode gates ─────────────────────────────
def gate_common(dataset_dir: str, manifest: dict, mode: str, out_dir: str) -> list:
    diags = []
    for label, p in (("dataset", dataset_dir), ("output", out_dir)):
        try:
            C.assert_not_protected(p)
        except SystemExit as e:
            diags.append(Diag("PROTECTED_PATH", f"{label}: {e}"))
    expected_root = os.path.realpath(os.path.join(OUTPUT_ROOT, mode.lower()))
    real_out = os.path.realpath(out_dir)
    if not real_out.startswith(expected_root + os.sep):
        diags.append(Diag("OUTPUT_DIR_NOT_EXCLUSIVE", f"{out_dir} is not under {expected_root}/"))
    if manifest.get("schema") != MANIFEST_SCHEMA:
        diags.append(Diag("MANIFEST_SCHEMA", f"{manifest.get('schema')!r} != {MANIFEST_SCHEMA!r}"))
    if manifest.get("spec") not in SUPPORTED_SPECS:
        diags.append(Diag("SPEC_UNSUPPORTED", f"manifest spec {manifest.get('spec')!r}; this trainer encodes "
                                              f"{SUPPORTED_SPECS} only"))
    return diags


def gate_smoke(manifest: dict) -> list:
    diags = []
    if not str(manifest.get("status", "")).startswith("FIXTURE") or manifest.get("fixture") is not True:
        diags.append(Diag("SMOKE_REQUIRES_FIXTURE", f"manifest status {str(manifest.get('status'))[:60]!r}; SMOKE "
                                                    "accepts only stage-4 synthetic fixture builds"))
    if manifest.get("generator_config", {}).get("mode") != "fixture":
        diags.append(Diag("SMOKE_REQUIRES_FIXTURE", "generator_config.mode is not 'fixture'"))
    if manifest.get("attack_label_basis") != "fixture_synthetic":
        diags.append(Diag("SMOKE_REQUIRES_FIXTURE", f"attack_label_basis={manifest.get('attack_label_basis')!r}"))
    return diags


def is_calibration_manifest(manifest):
    return (manifest.get('calibration_only') is True or manifest.get('status') == 'PROVISIONAL_PILOT'
            or manifest.get('build_purpose') == 'PILOT_BUILD')


def gate_experimental(manifest: dict, manifest_sha: str, authorization_path: str | None, *, captured=None) -> list:
    diags = []
    if is_calibration_manifest(manifest):
        diags.append(Diag('CALIBRATION_DATA_NOT_FOR_TRAINING','pilot calibration outputs cannot feed an EXPERIMENTAL trainer'))
    if str(manifest.get("status", "")).startswith("FIXTURE") or manifest.get("generator_config", {}).get("mode") == "fixture":
        diags.append(Diag("EXPERIMENTAL_REFUSES_FIXTURE", "fixture builds are SMOKE material only"))
    if manifest.get("attack_label_basis") == "fixture_synthetic":
        diags.append(Diag("EXPERIMENTAL_REFUSES_FIXTURE", "attack_label_basis=fixture_synthetic"))
    # audit_type/spec coherence applies in EXPERIMENTAL too: an experimental authorization must NOT turn an
    # r4 (ai_audited) provenance into an r3 (human) one, or vice versa. Provenance must be explicit,
    # known AND allowed by the manifest's spec revision; an authorization never substitutes for this.
    at = manifest.get('audit_type')
    if at not in AUDIT_TYPES:
        diags.append(Diag('F3_AUDIT_TYPE_UNKNOWN','EXPERIMENTAL requires explicit known audit provenance'))
    elif at not in SPEC_AUDIT_TYPES.get(manifest.get('spec'),()):
        diags.append(Diag('F3_AUDIT_TYPE_SPEC_MISMATCH',f'audit_type={at!r} is not allowed under this spec'))
    if not authorization_path:
        diags.append(Diag("AUTHORIZATION_MISSING", "--authorization is required: a v5-experimental-authorization/v1 "
                                                   "record naming this dataset manifest"))
        return diags
    cap = captured if captured is not None else _capture_record(authorization_path)
    auth_sha, auth, err = cap
    if err or not isinstance(auth, dict):
        return diags + [Diag("AUTHORIZATION_UNREADABLE", str(err or 'not a JSON object'))]
    if auth.get("schema") != AUTH_SCHEMA:
        diags.append(Diag("AUTHORIZATION_SCHEMA", f"{auth.get('schema')!r} != {AUTH_SCHEMA!r}"))
    if auth.get("scope") != EXPERIMENTAL:
        diags.append(Diag("AUTHORIZATION_SCOPE", f"scope={auth.get('scope')!r}; must be 'EXPERIMENTAL'"))
    if auth.get("provisional") is not True:
        diags.append(Diag("AUTHORIZATION_NOT_PROVISIONAL", "the record must state provisional: true"))
    if auth.get("dataset_manifest_sha256") != manifest_sha:
        diags.append(Diag("AUTHORIZATION_DATASET_MISMATCH",
                          f"authorized {auth.get('dataset_manifest_sha256')} != manifest {manifest_sha}"))
    for k in ("authorized_by", "date", "reference", "purpose"):
        if not str(auth.get(k, "")).strip():
            diags.append(Diag("AUTHORIZATION_INCOMPLETE", f"field {k!r} is empty"))
    if auth.get("uses_pending_labels_as_verified") is not False:
        diags.append(Diag("AUTHORIZATION_LABEL_POLICY",
                          "the record must state uses_pending_labels_as_verified: false"))
    if manifest.get('audit_type') == AUDIT_AI:
        if not git_committed_unmodified(authorization_path):
            diags.append(Diag('AUTHORIZATION_NOT_COMMITTED','AI experimental authorization must be committed and unchanged'))
        try:
            pool_sha = manifest.get('attack_pool_sha256')
            if not AE.valid_hash(pool_sha):
                raise ValueError('manifest does not pin an attack pool')
            AE.verify(auth.get('audit_evidence'), expected_pool_sha256=pool_sha,
                      expected_outcomes=auth.get('category_outcomes'),committed_checker=git_committed_unmodified)
        except (OSError, ValueError, TypeError) as e:
            diags.append(Diag('AUTHORIZATION_AUDIT_EVIDENCE',str(e)))
    return diags


def _committed_hashed_file(path, expected_sha, code, what, under=None, actual_sha=None) -> list:
    if not path:
        return [Diag(code, f"{what}: not provided")]
    if not os.path.isfile(path):
        return [Diag(code, f"{what}: {path} does not exist")]
    diags = []
    if under:
        root = os.path.realpath(os.path.join(REPO_ROOT, under))
        if not os.path.realpath(path).startswith(root + os.sep):
            diags.append(Diag(code, f"{what}: {path} is not under {under}/"))
    if not git_committed_unmodified(path):
        diags.append(Diag(code, f"{what}: {path} is not committed or has local modifications"))
    # Prefer the already-captured bytes' sha (single capture, no re-hash) when the caller supplies it.
    got = actual_sha if actual_sha is not None else (sha256_file(path) if expected_sha is not None else None)
    if expected_sha is not None and got != expected_sha:
        diags.append(Diag(code, f"{what}: sha256 {got} != expected {expected_sha}"))
    return diags


def _capture_record(path):
    """Read one JSON record's bytes ONCE: returns (sha256, parsed_obj, err_diag_or_None). A later check uses
    THESE bytes/obj, so the bytes hashed are the bytes parsed (no verify-then-reread / TOCTOU). `err_diag`
    carries a (code, detail) tuple on a read/parse failure; the caller maps it to its own code."""
    if not path:
        return None, None, ("MISSING", "not provided")
    try:
        C.assert_not_protected(path)
        with open(path, "rb") as fh:
            raw = fh.read()
    except (OSError,SystemExit) as e:
        return None, None, ("UNREADABLE", f"{path}: {type(e).__name__}")
    sha = sha256_bytes(raw)
    try:
        obj = json.loads(raw)
    except ValueError as e:
        return sha, None, ("UNREADABLE", f"{path}: {e}")
    return sha, obj, None


def capture_dataset_records(dataset_prereg, freeze_record, ai_audit_authorization):
    """Single capture of the three dataset-level records (prereg, freeze, ai-audit authorization). Each is
    read ONCE; the returned (sha, obj) pairs are what gate_dataset_final and the FINAL reader both use to
    check, decide categories and report evidence — so no record is re-read after it was verified."""
    return {
        "prereg": _capture_record(dataset_prereg),
        "freeze": _capture_record(freeze_record),
        "auth": _capture_record(ai_audit_authorization),
    }


def _prereg_token_budget_B(prereg_obj):
    """B recorded in the DATASET preregistration (ratified.token_budget.B, or a top-level token_budget.B)."""
    if not isinstance(prereg_obj, dict):
        return None
    for block in (prereg_obj.get("ratified") or {}, prereg_obj):
        tb = block.get("token_budget") if isinstance(block, dict) else None
        if isinstance(tb, dict) and "B" in tb:
            return tb["B"]
    return None


def gate_dataset_final(manifest: dict, manifest_sha: str, *, dataset_prereg: str | None,
                       freeze_record: str | None, ai_audit_authorization: str | None = None,
                       other_record_paths=(), captured=None) -> list:
    """DATASET-level FINAL conditions ONLY — independent of any model's training recipe. Empty list = the
    DATASET is FINAL-grade. Covers F1 (real gated build), F2 (generator values ratified), F3 (attack label
    basis), F3a/F3b (audit provenance known + allowed by the spec), F10 (ai-audit owner authorization),
    F4 (dataset preregistration committed + hash in manifest) and F5 (freeze record, §11.3).

    It DELIBERATELY EXCLUDES the consumer-model conditions — F6 training preregistration, F7 recipe sections,
    the recipe token budget, F9 library pins / clean tree — because an eligible dataset is not an authorization
    to train any particular model. Model 2 / V5 add those gates themselves; this function never imposes LoRA
    or TinyLlama pins on dataset eligibility. It DOES include F8′ (dataset-level): the manifest token budget B
    must equal the DATASET preregistration's B (a dataset fact, not a model recipe). `other_record_paths` lets
    the caller assert the ai-audit record is a file of its own (defaults to the dataset prereg + freeze record).
    `captured` (from `capture_dataset_records`) is the single read of the prereg/freeze/auth records; when
    given, nothing here re-reads those files."""
    cap = captured if captured is not None else capture_dataset_records(dataset_prereg, freeze_record,
                                                                        ai_audit_authorization)
    prereg_sha_cap, prereg_obj, _ = cap["prereg"]
    freeze_sha_cap, freeze_obj, _ = cap["freeze"]
    auth_sha_cap, auth_obj, _ = cap["auth"]
    d = []
    if is_calibration_manifest(manifest):
        d.append(Diag('CALIBRATION_DATA_NOT_FOR_TRAINING','pilot calibration outputs cannot feed a FINAL trainer'))
    # F1 — a real, gated build (not a fixture, not provisional).
    if manifest.get("status") != "REAL" or manifest.get("generator_config", {}).get("mode") != "real":
        d.append(Diag("F1_NOT_A_REAL_BUILD", f"manifest status {str(manifest.get('status'))[:60]!r}, generator mode "
                                             f"{manifest.get('generator_config', {}).get('mode')!r}"))
    if (manifest.get("gates") or {}).get("ok") is not True:
        d.append(Diag("F1_BUILD_GATES_NOT_PASSED", "manifest gates.ok is not true"))
    # F2 — every generator configuration value ratified (no PROPOSED / PENDING / BLOCKED / FIXTURE).
    for k, st in sorted((manifest.get("value_statuses") or {}).items()):
        if st not in RATIFIED_STATUSES:
            d.append(Diag("F2_VALUE_NOT_RATIFIED", f"generator value {k}: {st}"))
    if not manifest.get("value_statuses"):
        d.append(Diag("F2_VALUE_NOT_RATIFIED", "manifest records no value statuses"))
    # F3 — attack labels from the passed post-filter audit, never from a fixture basis.
    if manifest.get("attack_label_basis") != "post_filter_audit":
        d.append(Diag("F3_LABEL_BASIS", f"attack_label_basis={manifest.get('attack_label_basis')!r}; FINAL requires "
                                        "'post_filter_audit' (spec §7)"))
    # F3a–F3b — audit PROVENANCE is its own fact (concept 1): declared, known, and allowed by the spec revision.
    # `attack_label_basis` says WHERE labels come from, never WHO audited; it is not consulted for provenance.
    audit_type = manifest.get("audit_type")
    if audit_type not in AUDIT_TYPES:
        d.append(Diag("F3_AUDIT_TYPE_UNKNOWN", f"manifest audit_type={audit_type!r}; must be one of {AUDIT_TYPES} (missing or "
                                               "unknown provenance is refused, never defaulted)"))
    elif audit_type not in SPEC_AUDIT_TYPES.get(manifest.get("spec"), ()):
        d.append(Diag("F3_AUDIT_TYPE_SPEC_MISMATCH", f"audit_type={audit_type!r} is not allowed under spec "
                                                     f"{manifest.get('spec')!r} (allowed: {SPEC_AUDIT_TYPES.get(manifest.get('spec'), ())})"))
    # F10 — a SEPARATE owner authorization (concept 4) whenever the audit was AI-assisted.
    if audit_type == AUDIT_AI:
        d += _check_ai_audit_authorization(ai_audit_authorization, manifest_sha, freeze_record,
                                           other_record_paths or (dataset_prereg, freeze_record),
                                           rec=auth_obj, freeze_sha=freeze_sha_cap)
    # F4 — dataset preregistration, committed, hash recorded in the manifest (captured bytes' sha).
    prereg_sha = manifest.get("preregistration_sha256")
    if not prereg_sha:
        d.append(Diag("F4_DATASET_PREREG", "the manifest records no preregistration_sha256"))
    d += _committed_hashed_file(dataset_prereg, prereg_sha, "F4_DATASET_PREREG", "dataset preregistration",
                                under=DATASET_PREREG_DIR, actual_sha=prereg_sha_cap)
    # F8′ — DATASET-level token-budget consistency: manifest B must equal the preregistration's B. This is a
    # dataset fact (NOT the model recipe's B, which stays in gate_final F8).
    if dataset_prereg and prereg_obj is not None:
        man_B = (manifest.get("token_budget") or {}).get("B")
        pre_B = _prereg_token_budget_B(prereg_obj)
        if pre_B is None:
            d.append(Diag("F8_DATASET_TOKEN_BUDGET_MISMATCH", "the dataset preregistration records no token_budget.B"))
        elif man_B != pre_B:
            d.append(Diag("F8_DATASET_TOKEN_BUDGET_MISMATCH", f"manifest B={man_B} != preregistration B={pre_B}"))
    # F5 — dataset freeze record covering every §11.3 item of the manifest's spec revision.
    d += _check_freeze_record(freeze_record, manifest, manifest_sha, rec=freeze_obj)
    if audit_type == AUDIT_AI:
        try:
            aud = audit_item_of(freeze_obj)
            pool_sha = manifest.get('attack_pool_sha256')
            if not AE.valid_hash(pool_sha):
                raise ValueError('manifest does not pin an attack pool')
            if aud.get('components') is not None:
                # Each component carries its own audit evidence + pool; verify them all (per-component pools
                # mean the manifest's single attack_pool_sha256 is not the sole pin).
                for comp in CB.component_bindings(aud):
                    AE.verify(comp.get('audit_evidence'), expected_outcomes=comp.get('category_outcomes'),
                              committed_checker=git_committed_unmodified)
            else:
                AE.verify(aud.get('audit_evidence'),expected_pool_sha256=pool_sha,
                          expected_outcomes=aud.get('category_outcomes'),committed_checker=git_committed_unmodified)
        except (OSError, ValueError, TypeError) as e:
            d.append(Diag('F5_DATASET_FREEZE', 'audit evidence: '+str(e)))
    return d


def gate_final(manifest: dict, manifest_sha: str, recipe: dict, recipe_sha: str, *,
               dataset_prereg: str | None, freeze_record: str | None, training_prereg: str | None,
               installed_versions: dict, git: dict, code_paths=(), ai_audit_authorization: str | None = None,
               captured_dataset_records=None) -> list:
    """Every unmet FINAL condition. Empty list = FINAL may start. = the DATASET gates (gate_dataset_final)
    PLUS the consumer-model gates F6–F9 (training preregistration, recipe ratification, token-budget
    consistency, reproducibility)."""
    # DATASET eligibility (F1–F5, F3a/b, F10). The ai-audit record must be its own file, separate from ALL
    # three FINAL records (prereg, freeze, training prereg).
    d = gate_dataset_final(manifest, manifest_sha, dataset_prereg=dataset_prereg, freeze_record=freeze_record,
                           ai_audit_authorization=ai_audit_authorization,
                           other_record_paths=(dataset_prereg, freeze_record, training_prereg),
                           captured=captured_dataset_records)
    # F6 — training preregistration pinning this recipe, template, vocabulary and dataset.
    d += _check_training_prereg(training_prereg, recipe, recipe_sha, manifest_sha)
    # F7 — the recipe itself ratified, section by section.
    for section, st in unratified_recipe_sections(recipe):
        d.append(Diag("F7_RECIPE_NOT_RATIFIED", f"{section}: {st}"))
    # F8 — consistency of the token budget between the dataset build and the recipe.
    tb = manifest.get("token_budget") or {}
    if tb.get("B") != recipe["token_budget"]["B"]:
        d.append(Diag("F8_TOKEN_BUDGET_MISMATCH", f"manifest B={tb.get('B')} recipe B={recipe['token_budget']['B']}"))
    # F9 — reproducibility: clean tree, pinned libraries.
    if not git.get("clean"):
        d.append(Diag("F9_GIT_NOT_CLEAN", f"commit={git.get('commit')} tracked changes={git.get('tracked_dirty_files')}"))
    for p in code_paths:
        if not git_committed_unmodified(p):
            d.append(Diag("F9_CODE_NOT_COMMITTED", f"{os.path.relpath(p, REPO_ROOT)} is untracked or modified"))
    for lib, pin in sorted(recipe["library_pins"].items()):
        if lib in ("status", "source"):
            continue
        got = installed_versions.get(lib)
        if got is None or not str(got).startswith(str(pin)):
            d.append(Diag("F9_LIBRARY_PIN", f"{lib}: installed {got!r}, pinned {pin!r}"))
    return d


def _load_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _check_freeze_record(path, manifest, manifest_sha, *, rec=None) -> list:
    code = "F5_DATASET_FREEZE"
    d = _committed_hashed_file(path, None, code, "dataset freeze record")
    if d and not (path and os.path.isfile(path)):
        return d
    if rec is None:   # no pre-captured snapshot supplied: read once here
        try:
            rec = _load_json(path)
        except ValueError as e:
            return d + [Diag(code, f"unreadable: {e}")]
    if not isinstance(rec, dict):
        return d + [Diag(code, "unreadable: not a JSON object")]
    spec = manifest.get("spec")
    if rec.get("schema") != FREEZE_SCHEMA:
        d.append(Diag(code, f"schema {rec.get('schema')!r} != {FREEZE_SCHEMA!r}"))
    if rec.get("status") != "FROZEN":
        d.append(Diag(code, f"status {rec.get('status')!r}; must be FROZEN"))
    if rec.get("spec") != spec:
        d.append(Diag(code, f"record spec {rec.get('spec')!r} != manifest spec {spec!r}"))
    if rec.get("dataset_manifest_sha256") != manifest_sha:
        d.append(Diag(code, f"record names manifest {rec.get('dataset_manifest_sha256')}, dataset has {manifest_sha}"))
    if not str(rec.get("owner_decision", "")).strip():
        d.append(Diag(code, "no owner_decision reference (DECISIONS.md entry)"))
    required = FREEZE_ITEMS.get(spec)
    if required is None:
        d.append(Diag(code, f"no §11.3 item list encoded for spec {spec!r}; the gate must be updated deliberately"))
        return d
    items = rec.get("items") or {}
    for item in required:
        it = items.get(item)
        if not it or it.get("status") != "DONE":
            d.append(Diag(code, f"§11.3 item {item!r}: {(it or {}).get('status', 'MISSING')}"))
            continue
        evidence = it.get("evidence") or []
        if not evidence:
            d.append(Diag(code, f"§11.3 item {item!r}: DONE without evidence"))
        for ev in evidence:
            p = os.path.join(REPO_ROOT, ev.get("path", ""))
            if not os.path.isfile(p) or sha256_file(p) != ev.get("sha256"):
                d.append(Diag(code, f"§11.3 item {item!r}: evidence {ev.get('path')!r} missing or hash mismatch"))
    # Audit provenance must be stated by the freeze record's audit item too, and must AGREE with the manifest
    # (a manifest cannot claim `human` while the signed-off audit evidence says ai_audited, or vice versa).
    aud = items.get("post_filter_audit") or {}
    if aud.get("audit_type") not in AUDIT_TYPES or aud.get("audit_type") != manifest.get("audit_type"):
        d.append(Diag(code, f"post_filter_audit.audit_type {aud.get('audit_type')!r} != manifest audit_type "
                            f"{manifest.get('audit_type')!r} (both must be a known, equal provenance)"))
    if aud.get("audit_type") == AUDIT_AI:
        # A multi-component record carries category_outcomes per component; a legacy record carries one map.
        if aud.get("components") is not None:
            try:
                outcome_maps = [(c["component_id"], c.get("category_outcomes")) for c in CB.component_bindings(aud)]
            except (ValueError, TypeError, KeyError) as e:
                outcome_maps = []
                d.append(Diag(code, f"post_filter_audit.components invalid: {e}"))
        else:
            outcome_maps = [("default", aud.get("category_outcomes"))]
        for cid, outs in outcome_maps:
            if not isinstance(outs, dict) or not outs:
                d.append(Diag(code, f"post_filter_audit[{cid}].category_outcomes missing for an ai_audited record"))
                continue
            for cat, o in sorted(outs.items()):
                if o not in AUDIT_OUTCOMES:
                    d.append(Diag(code, f"[{cid}] category {cat!r}: unknown audit outcome {o!r}; allowed {AUDIT_OUTCOMES}"))
    return d


def audit_item(freeze_record_path) -> dict:
    """The freeze record's `post_filter_audit` item, or {} if unreadable (callers report that elsewhere)."""
    try:
        return (_load_json(freeze_record_path).get("items") or {}).get("post_filter_audit") or {}
    except (OSError, ValueError, TypeError, AttributeError):
        return {}


def audit_item_of(freeze_obj) -> dict:
    """The `post_filter_audit` item of an ALREADY-CAPTURED freeze record object (no file read)."""
    try:
        return (freeze_obj.get("items") or {}).get("post_filter_audit") or {}
    except (TypeError, AttributeError):
        return {}


def experimental_category_outcomes(authorization_path, *, captured=None):
    """Outcomes derived from the exact report pinned by the captured authorization."""
    try:
        _, auth, err = captured if captured is not None else _capture_record(authorization_path)
        if err or not isinstance(auth, dict):
            return {}
        return AE.verify(auth.get('audit_evidence'), expected_outcomes=auth.get('category_outcomes'),committed_checker=git_committed_unmodified)['category_outcomes']
    except (OSError, ValueError, TypeError, AttributeError):
        return {}


def check_audit_pool_membership(rows, binding):
    """Every consumed attack row must name a record in the pinned audited pool."""
    try:
        ids=[r['meta'].get('payload_record_id') for r in rows if r['meta'].get('label') == 'BLOCK']
        AE.verify(binding,record_ids=ids,committed_checker=git_committed_unmodified)
        return []
    except (OSError, ValueError, TypeError) as e:
        return [Diag('AUDIT_POOL_MEMBERSHIP',str(e))]


def _check_ai_audit_authorization(path, manifest_sha, freeze_record, other_record_paths, *,
                                  rec=None, freeze_sha=None) -> list:
    """D72-ratified authorization contract. A separate committed record is still mandatory.
    `rec` is the already-captured authorization object and `freeze_sha` the already-captured freeze-record
    sha (single capture — no re-read of either file) when the caller supplies them."""
    code, d = "F10_AI_AUDIT_AUTHORIZATION", []
    if AI_AUDIT_AUTH_SCHEMA is None:
        d.append(Diag(code, "no ratified ai-audit training-authorization schema exists; ai_audited data cannot "
                            "feed FINAL until the owner ratifies one (this refusal holds even if a record is supplied)"))
    if not path:
        return d + [Diag(code, "ai_audited dataset: --ai-audit-authorization (a record separate from the dataset "
                               "preregistration, freeze record and training preregistration) is required")]
    if not os.path.isfile(path):
        return d + [Diag(code, f"{path} does not exist")]
    real = os.path.realpath(path)
    if any(o and os.path.realpath(o) == real for o in other_record_paths):
        d.append(Diag(code, "the authorization must be its own record, not one of the other FINAL records"))
    if not git_committed_unmodified(path):
        d.append(Diag(code, f"{path} is not committed or has local modifications"))
    if rec is None:
        try:
            rec = _load_json(path)
        except ValueError as e:
            return d + [Diag(code, f"unreadable: {e}")]
    if not isinstance(rec, dict):
        return d + [Diag(code, "unreadable: not a JSON object")]
    if AI_AUDIT_AUTH_SCHEMA is not None and rec.get("schema") != AI_AUDIT_AUTH_SCHEMA:
        d.append(Diag(code, f"schema {rec.get('schema')!r} != {AI_AUDIT_AUTH_SCHEMA!r}"))
    if rec.get("scope") != FINAL:
        d.append(Diag(code, f"scope {rec.get('scope')!r}; must be 'FINAL'"))
    if rec.get("audit_type") != AUDIT_AI:
        d.append(Diag(code, f"audit_type {rec.get('audit_type')!r}; must be {AUDIT_AI!r}"))
    if rec.get("dataset_manifest_sha256") != manifest_sha:
        d.append(Diag(code, f"authorized dataset {rec.get('dataset_manifest_sha256')} != {manifest_sha}"))
    # Bind to the freeze record by its CAPTURED sha (same bytes verified above), not a fresh re-hash.
    fsha = freeze_sha if freeze_sha is not None else (sha256_file(freeze_record)
                                                      if freeze_record and os.path.isfile(freeze_record) else None)
    if fsha is None or rec.get("freeze_record_sha256") != fsha:
        d.append(Diag(code, "freeze_record_sha256 does not name the supplied freeze record (audit evidence not bound)"))
    for k in ("authorized_by", "date", "owner_decision"):
        if not str(rec.get(k, "")).strip():
            d.append(Diag(code, f"field {k!r} is empty"))
    for k in ("authorizes_ai_audited_final_training", "acknowledges_not_human_validation"):
        if rec.get(k) is not True:
            d.append(Diag(code, f"{k} must be true"))
    return d


def _check_training_prereg(path, recipe, recipe_sha, manifest_sha) -> list:
    code = "F6_TRAINING_PREREG"
    d = _committed_hashed_file(path, None, code, "training preregistration")
    if d and not (path and os.path.isfile(path)):
        return d
    try:
        rec = _load_json(path)
    except ValueError as e:
        return d + [Diag(code, f"unreadable: {e}")]
    if rec.get("schema") != TRAINING_PREREG_SCHEMA:
        d.append(Diag(code, f"schema {rec.get('schema')!r} != {TRAINING_PREREG_SCHEMA!r}"))
    if rec.get("status") != "RATIFIED":
        d.append(Diag(code, f"status {rec.get('status')!r}; must be RATIFIED"))
    if rec.get("recipe_sha256") != recipe_sha:
        d.append(Diag(code, f"preregistered recipe {rec.get('recipe_sha256')} != recipe {recipe_sha}"))
    if rec.get("template_fingerprint") != template_fingerprint(recipe):
        d.append(Diag(code, "preregistered template/vocabulary fingerprint differs from the recipe's"))
    if rec.get("dataset_manifest_sha256") != manifest_sha:
        d.append(Diag(code, f"preregistered dataset {rec.get('dataset_manifest_sha256')} != {manifest_sha}"))
    if not str(rec.get("owner_decision", "")).strip():
        d.append(Diag(code, "no owner_decision reference"))
    return d


# ───────────────────────────── tokenization contract and examples ─────────────────────────────
@dataclass(frozen=True)
class TokenContract:
    overhead: int
    label_budget: int
    max_length: int
    margin: int
    B: int
    template_max_B: int
    bos_id: int
    eos_id: int


def measure_contract(tok, recipe) -> tuple:
    """Re-measure the template overhead and label budget with the loaded tokenizer (spec §5.5)."""
    template, vocab = recipe_template(recipe), recipe_vocabulary(recipe)
    tb = recipe["token_budget"]
    overhead = T.template_overhead(tok, template)
    label = T.label_budget(tok, template, vocab)
    max_b = T.token_budget(tb["max_length"], overhead, label, tb["margin"])
    contract = TokenContract(overhead, label, tb["max_length"], tb["margin"], tb["B"], max_b,
                             tok.bos_token_id, tok.eos_token_id)
    diags = []
    if tb["B"] > max_b:
        diags.append(Diag("TOKEN_BUDGET_EXCEEDS_TEMPLATE", f"recipe B={tb['B']} > {max_b} = max_length - overhead "
                                                           f"{overhead} - label {label} - margin {tb['margin']}"))
    if tok.bos_token_id is None or tok.eos_token_id is None or tok.bos_token_id == tok.eos_token_id:
        diags.append(Diag("TOKENIZER_SPECIALS", f"bos={tok.bos_token_id} eos={tok.eos_token_id}"))
    return contract, diags


def build_example(tok, recipe, contract: TokenContract, text: str, output: str) -> tuple:
    """(example, None) or (None, Diag). Never truncates."""
    template = recipe_template(recipe)
    try:
        T.check_content_has_no_special_ids(tok, template, text)
    except ValueError as e:
        return None, Diag("CONTENT_SPECIAL_IDS", str(e))
    prompt = T.encode_prompt(tok, template, text)
    content_tokens = len(prompt) - contract.overhead
    if content_tokens > contract.B:
        return None, Diag("CONTENT_OVER_BUDGET", f"{content_tokens} content tokens > B={contract.B}")
    full = T.encode_prompt(tok, template, text, output)
    if full[:len(prompt)] != prompt:
        return None, Diag("PROMPT_PREFIX_MISMATCH", "training ids do not start with the inference prompt ids")
    completion = full[len(prompt):]
    if not completion or completion[-1] != contract.eos_id or completion.count(contract.eos_id) != 1:
        return None, Diag("EOS_INVALID", "the completion must end with exactly one EOS")
    if full[0] != contract.bos_id or full.count(contract.bos_id) != 1 or full.count(contract.eos_id) != 3:
        return None, Diag("SPECIAL_LAYOUT", f"bos={full.count(contract.bos_id)} eos={full.count(contract.eos_id)}")
    if len(full) > contract.max_length:
        return None, Diag("TRUNCATION_REQUIRED", f"{len(full)} tokens > max_length {contract.max_length}")
    decoded = tok.decode(completion[:-1], skip_special_tokens=False)
    if decoded.strip(" \t\r\n") != output:
        return None, Diag("OUTPUT_ROUNDTRIP", f"decoded {decoded!r} != {output!r}")
    if recipe["loss"]["on"] == "completion":
        mask = [0] * len(prompt) + [1] * len(completion)
    else:
        mask = [1] * len(full)
    return {"input_ids": full, "completion_mask": mask, "prompt_len": len(prompt),
            "content_tokens": content_tokens, "completion_tokens": len(completion)}, None


def build_examples(tok, recipe, contract: TokenContract, rows: list) -> tuple:
    examples, diags = [], []
    for r in rows:
        ex, err = build_example(tok, recipe, contract, r["text"], r["output"])
        if err is not None:
            diags.append(Diag(err.code, f"{r['split']}[{r['index']}]: {err.detail}"))
            continue
        ex["text_sha256"] = r["meta"]["text_sha256"]
        ex["output"] = r["output"]
        examples.append(ex)
    return examples, diags


# ───────────────────────────── one call for the trainer ─────────────────────────────
@dataclass
class PreparedData:
    mode: str
    manifest: dict
    manifest_sha256: str
    train_rows: list
    validation_rows: list
    gate_evidence: dict = field(default_factory=dict)


def prepare(mode: str, dataset_dir: str, out_dir: str, recipe: dict, recipe_sha: str, *,
            authorization: str | None = None, dataset_prereg: str | None = None,
            freeze_record: str | None = None, training_prereg: str | None = None,
            installed_versions: dict | None = None, git: dict | None = None, code_paths=(),
            ai_audit_authorization: str | None = None) -> PreparedData:
    """Run every gate for `mode` and load TRAIN / VALIDATION. Raises GateRefused with ALL failures."""
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}")
    manifest_path = os.path.join(dataset_dir, "manifest.json")
    try:
        C.assert_not_protected(dataset_dir)
        C.assert_not_protected(manifest_path)
    except SystemExit as e:
        raise GateRefused(mode,[Diag('PROTECTED_PATH',str(e))]) from e
    if not os.path.isfile(manifest_path):
        raise GateRefused(mode, [Diag("MANIFEST_MISSING", f"{manifest_path} does not exist")])
    manifest, msha = load_manifest(dataset_dir)
    git = git if git is not None else git_state()
    diags = gate_common(dataset_dir, manifest, mode, out_dir)
    experimental_cap = _capture_record(authorization) if mode == EXPERIMENTAL else None
    final_cap = capture_dataset_records(dataset_prereg, freeze_record, ai_audit_authorization) if mode == FINAL else None
    if mode == SMOKE:
        diags += gate_smoke(manifest)
    elif mode == EXPERIMENTAL:
        diags += gate_experimental(manifest, msha, authorization, captured=experimental_cap)
    else:
        diags += gate_final(manifest, msha, recipe, recipe_sha, dataset_prereg=dataset_prereg,
                            freeze_record=freeze_record, training_prereg=training_prereg,
                            installed_versions=installed_versions or {}, git=git, code_paths=code_paths,
                            ai_audit_authorization=ai_audit_authorization, captured_dataset_records=final_cap)
    # INTERNAL_TEST must be DECLARED (no file open); the split must not be silently incomplete.
    diags += protected_split_declared_diags(manifest)
    train, validation = [], []
    # ACCESS GATE BEFORE ROWS: if the dataset is not accessible (bad schema/spec/path or a missing/invalid
    # authorization), DO NOT open any row/meta file. Only once access is granted do we take ONE verified
    # capture of TRAIN/VALIDATION (no verify-then-reread) and run the row-level checks on those same bytes.
    if not any(x.code in ACCESS_DENIED_CODES for x in diags):
        train, d1 = capture_and_parse_split(dataset_dir, manifest, "TRAIN")
        validation, d2 = capture_and_parse_split(dataset_dir, manifest, "VALIDATION")
        diags += d1 + d2
        if not any(x.code in ("ARTIFACT_MISSING", "ARTIFACT_NOT_IN_MANIFEST") for x in diags):
            vocab = recipe_vocabulary(recipe)
            diags += check_rows(train, vocab,row_contract=manifest.get('row_contract')) + check_rows(validation, vocab,row_contract=manifest.get('row_contract'))
            diags += check_disjoint(train, validation)
            audit_type = manifest.get("audit_type")
            diags += check_audit_rows(train + validation, audit_type)
            # Category eligibility for ai_audited data in BOTH FINAL and EXPERIMENTAL (provisional is not a
            # bypass): each attack category must be admitted (PASS_AI_AUDITED). FINAL sources the outcomes
            # from the freeze record; EXPERIMENTAL from the authorization (bound to its audit).
            if audit_type == AUDIT_AI and mode in (FINAL, EXPERIMENTAL):
                final_aud = audit_item_of(final_cap['freeze'][1]) if mode == FINAL else None
                if mode == FINAL and isinstance(final_aud, dict) and final_aud.get("components") is not None:
                    # Multi-component dataset (component-evidence contract): verify each component's audit and
                    # bind every row to exactly one component — category DERIVED from the pinned pool record,
                    # row identity/content checked, committed-evidence gate enforced, no combined-pool PASS.
                    diags += [Diag(code, det) for code, det in
                              CB.verify_components(train + validation, final_aud,
                                                   committed_checker=git_committed_unmodified)]
                else:
                    outcomes = (final_aud.get("category_outcomes") if mode == FINAL
                                else experimental_category_outcomes(authorization, captured=experimental_cap))
                    diags += check_audit_category_outcomes(train + validation, outcomes)
                    owner_audit = (final_aud if mode == FINAL else experimental_cap[1])
                    diags += check_audit_pool_membership(train + validation, owner_audit.get('audit_evidence'))
            if not train:
                diags.append(Diag("EMPTY_SPLIT", "TRAIN has no rows"))
            if not validation:
                diags.append(Diag("EMPTY_SPLIT", "VALIDATION has no rows"))
    if diags:
        raise GateRefused(mode, _capped(diags))
    return PreparedData(mode, manifest, msha, train, validation, gate_evidence={
        "manifest_sha256": msha, "manifest_status": str(manifest.get("status"))[:120],
        "spec": manifest.get("spec"), "attack_label_basis": manifest.get("attack_label_basis"),
        "value_statuses": manifest.get("value_statuses"), "audit_type": manifest.get("audit_type"),
        "ai_audit_authorization_supplied": bool(ai_audit_authorization),
        "artifacts_verified": [a for a in manifest.get("artifacts", [])
                               if a["path"] in {p.format(split=s) for s in READ_SPLITS for p in (ROWS_FILE, META_FILE)}],
        "splits_never_opened": list(NEVER_READ_SPLITS) + ["slices.*"],
        "rows": {"TRAIN": len(train), "VALIDATION": len(validation)},
        "identity_keys_checked_disjoint": list(IDENTITY_KEYS),
    })
