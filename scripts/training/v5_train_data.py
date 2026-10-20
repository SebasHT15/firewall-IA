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

SUPPORTED_SPECS = ("V5-DATA-SPEC-r3",)
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
}

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
                       "OUTPUT_ROUNDTRIP"})


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


def load_split(dataset_dir: str, split: str) -> tuple:
    """Rows of TRAIN or VALIDATION, each {'text', 'output', 'meta'}; plus alignment diagnostics."""
    if split not in READ_SPLITS:
        raise PermissionError(f"{split} is never read by the trainer (single-run guard, spec §9)")
    rows_path = os.path.join(dataset_dir, ROWS_FILE.format(split=split))
    meta_path = os.path.join(dataset_dir, META_FILE.format(split=split))
    with open(rows_path, encoding="utf-8") as fh:
        rows = [json.loads(ln) for ln in fh if ln.strip()]
    with open(meta_path, encoding="utf-8") as fh:
        metas = [json.loads(ln) for ln in fh if ln.strip()]
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


def check_rows(rows: list, vocabulary) -> list:
    vocab = frozenset(vocabulary)
    diags = []
    for r in rows:
        m, where = r["meta"], f"{r['split']}[{r['index']}]"
        if m.get("label_status") not in TRAINABLE_LABEL_STATUSES:
            diags.append(Diag("LABEL_NOT_TRAINABLE", f"{where}: label_status={m.get('label_status')!r}"))
        if m.get("exclusion_reason") is not None or m.get("slice") is not None:
            diags.append(Diag("EXCLUDED_ROW_IN_SPLIT", f"{where}: exclusion_reason={m.get('exclusion_reason')!r}"))
        if r["output"] not in vocab:
            diags.append(Diag("OUTPUT_NOT_IN_VOCABULARY", f"{where}: {r['output']!r}"))
        label = m.get("label")
        if label not in ("ALLOW", "BLOCK") or not r["output"].startswith(f"{label} | "):
            diags.append(Diag("LABEL_OUTPUT_INCONSISTENT", f"{where}: label={label!r} output={r['output']!r}"))
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


def gate_experimental(manifest: dict, manifest_sha: str, authorization_path: str | None) -> list:
    diags = []
    if str(manifest.get("status", "")).startswith("FIXTURE") or manifest.get("generator_config", {}).get("mode") == "fixture":
        diags.append(Diag("EXPERIMENTAL_REFUSES_FIXTURE", "fixture builds are SMOKE material only"))
    if manifest.get("attack_label_basis") == "fixture_synthetic":
        diags.append(Diag("EXPERIMENTAL_REFUSES_FIXTURE", "attack_label_basis=fixture_synthetic"))
    if not authorization_path:
        diags.append(Diag("AUTHORIZATION_MISSING", "--authorization is required: a v5-experimental-authorization/v1 "
                                                   "record naming this dataset manifest"))
        return diags
    try:
        with open(authorization_path, encoding="utf-8") as fh:
            auth = json.load(fh)
    except (OSError, ValueError) as e:
        return diags + [Diag("AUTHORIZATION_UNREADABLE", str(e))]
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
    return diags


def _committed_hashed_file(path, expected_sha, code, what, under=None) -> list:
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
    if expected_sha is not None and sha256_file(path) != expected_sha:
        diags.append(Diag(code, f"{what}: sha256 {sha256_file(path)} != expected {expected_sha}"))
    return diags


def gate_final(manifest: dict, manifest_sha: str, recipe: dict, recipe_sha: str, *,
               dataset_prereg: str | None, freeze_record: str | None, training_prereg: str | None,
               installed_versions: dict, git: dict, code_paths=()) -> list:
    """Every unmet FINAL condition. Empty list = FINAL may start."""
    d = []
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
    # F4 — dataset preregistration, committed, hash recorded in the manifest.
    prereg_sha = manifest.get("preregistration_sha256")
    if not prereg_sha:
        d.append(Diag("F4_DATASET_PREREG", "the manifest records no preregistration_sha256"))
    d += _committed_hashed_file(dataset_prereg, prereg_sha, "F4_DATASET_PREREG", "dataset preregistration",
                                under=DATASET_PREREG_DIR)
    # F5 — dataset freeze record covering every §11.3 item of the manifest's spec revision.
    d += _check_freeze_record(freeze_record, manifest, manifest_sha)
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


def _check_freeze_record(path, manifest, manifest_sha) -> list:
    code = "F5_DATASET_FREEZE"
    d = _committed_hashed_file(path, None, code, "dataset freeze record")
    if d and not (path and os.path.isfile(path)):
        return d
    try:
        rec = _load_json(path)
    except ValueError as e:
        return d + [Diag(code, f"unreadable: {e}")]
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
            installed_versions: dict | None = None, git: dict | None = None, code_paths=()) -> PreparedData:
    """Run every gate for `mode` and load TRAIN / VALIDATION. Raises GateRefused with ALL failures."""
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}")
    manifest_path = os.path.join(dataset_dir, "manifest.json")
    if not os.path.isfile(manifest_path):
        raise GateRefused(mode, [Diag("MANIFEST_MISSING", f"{manifest_path} does not exist")])
    manifest, msha = load_manifest(dataset_dir)
    git = git if git is not None else git_state()
    diags = gate_common(dataset_dir, manifest, mode, out_dir)
    if mode == SMOKE:
        diags += gate_smoke(manifest)
    elif mode == EXPERIMENTAL:
        diags += gate_experimental(manifest, msha, authorization)
    else:
        diags += gate_final(manifest, msha, recipe, recipe_sha, dataset_prereg=dataset_prereg,
                            freeze_record=freeze_record, training_prereg=training_prereg,
                            installed_versions=installed_versions or {}, git=git, code_paths=code_paths)
    diags += verify_read_artifacts(dataset_dir, manifest)
    train, validation = [], []
    if not any(x.code in ("ARTIFACT_MISSING", "ARTIFACT_NOT_IN_MANIFEST") for x in diags):
        train, d1 = load_split(dataset_dir, "TRAIN")
        validation, d2 = load_split(dataset_dir, "VALIDATION")
        diags += d1 + d2
        vocab = recipe_vocabulary(recipe)
        diags += check_rows(train, vocab) + check_rows(validation, vocab)
        diags += check_disjoint(train, validation)
        if not train:
            diags.append(Diag("EMPTY_SPLIT", "TRAIN has no rows"))
        if not validation:
            diags.append(Diag("EMPTY_SPLIT", "VALIDATION has no rows"))
    if diags:
        raise GateRefused(mode, _capped(diags))
    return PreparedData(mode, manifest, msha, train, validation, gate_evidence={
        "manifest_sha256": msha, "manifest_status": str(manifest.get("status"))[:120],
        "spec": manifest.get("spec"), "attack_label_basis": manifest.get("attack_label_basis"),
        "value_statuses": manifest.get("value_statuses"),
        "artifacts_verified": [a for a in manifest.get("artifacts", [])
                               if a["path"] in {p.format(split=s) for s in READ_SPLITS for p in (ROWS_FILE, META_FILE)}],
        "splits_never_opened": list(NEVER_READ_SPLITS) + ["slices.*"],
        "rows": {"TRAIN": len(train), "VALIDATION": len(validation)},
        "identity_keys_checked_disjoint": list(IDENTITY_KEYS),
    })
