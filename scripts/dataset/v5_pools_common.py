"""Shared helpers for the V5 source pools (stage 2, issue: V5 dataset foundation).

Stdlib only. Used by `build_v5_benign_pools.py` and `build_v5_attack_pool.py`.

Pool files are JSON Lines, one record per line, UTF-8, keys sorted, records sorted by a
stable key, no timestamps: two runs over the same pinned inputs produce byte-identical
files. Generated pools live under `datasets/v5_sources/` (gitignored); only small summaries
and the committed lexicons are versioned.

Identity used here (frozen by D62, spec §4.6): `value_entry_id = sha256(pool_id NUL NFC(v))`.
Nothing in this module assigns a split, a family or a label.
"""

import hashlib
import json
import os
import subprocess
import sys
import unicodedata

SCHEMA = "v5-pools/v1"
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DEFAULT_OUT_DIR = os.path.join(REPO_ROOT, "datasets", "v5_sources")

# Status vocabulary shared by all pools (benign and attack).
EXTRACTED = "EXTRACTED"            # read from the source, nothing decided yet
ACCEPTED = "ACCEPTED"              # passed the structural / licence / privacy filters
EXCLUDED = "EXCLUDED"              # removed, with an exclusion_reason
# Label status of attack payloads. VERIFIED needs the post-filter audit and the human review of
# spec §7 / §11.3; no stage-2 code path can produce it.
LABEL_PENDING = "PENDING_ADJUDICATION"
LABEL_VERIFIED = "VERIFIED"


def nfc(text):
    return unicodedata.normalize("NFC", text)


def value_entry_id(pool_id, element):
    """Spec §4.6: sha256(pool_id NUL NFC(element)), hex."""
    return hashlib.sha256(f"{pool_id}\0{nfc(element)}".encode("utf-8")).hexdigest()


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def dumps(record):
    return json.dumps(record, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def write_jsonl(path, records, key):
    """Write records sorted by `key(record)`; return {path, sha256, bytes, records}."""
    rows = sorted(records, key=key)
    data = "".join(dumps(r) + "\n" for r in rows).encode("utf-8")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)
    return {"path": os.path.relpath(path, REPO_ROOT), "sha256": sha256_bytes(data),
            "bytes": len(data), "records": len(rows)}


def read_jsonl(path):
    with open(path, encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def write_json(path, obj):
    data = (json.dumps(obj, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)
    return sha256_bytes(data)


def code_fingerprint(paths):
    """sha256 of each code file that produced an artifact (manifest field, spec §8)."""
    return {os.path.relpath(p, REPO_ROOT): sha256_file(p) for p in sorted(paths)}


def environment():
    return {"python": sys.version.split()[0], "implementation": sys.implementation.name}


# ─────────────── protected material: never an input of a pool builder ───────────────
def assert_not_protected(path):
    """Refuse External v1/v2, V4 eval, INTERNAL TEST material and CSIC (D37-D40, D58)."""
    p = os.path.realpath(path)
    parts = [x.lower() for x in p.split(os.sep) if x]
    base = os.path.basename(p).lower()
    bad = []
    if any(x.startswith("external_v") or x.startswith("external-v") for x in parts):
        bad.append("external test")
    if any(parts[i] == "reports" and parts[i + 1] == "external" for i in range(len(parts) - 1)):
        bad.append("reports/external")
    if base == "eval.jsonl" or any("internal_test" in x or "internal-test" in x for x in parts):
        bad.append("eval / internal test")
    if any("csic" in x for x in parts):
        bad.append("CSIC (never TRAIN, D58)")
    if "v4_clean" in parts:
        bad.append("V4-clean dataset (not reused, D58)")
    if bad:
        raise SystemExit(f"REFUSED: {path} is protected material ({', '.join(bad)})")
    return p


# ─────────────── provenance, interpreter control and the D59 mapping (stage-2 closure) ───────────────
# Bump when a filter, a record field or a selection rule changes meaning (manifest field).
GENERATOR_VERSION = "v5-pools/1.1"

# Interpreters on which every pool artifact was rebuilt byte-identical (2026-10-14: CPython 3.12.15
# and 3.14.4). Another minor version may change stdlib-derived behaviour (`unicodedata`,
# `html.entities`), so it is refused unless explicitly allowed; the override is recorded.
VERIFIED_PYTHON = ("3.12", "3.14")
PYTHON_OVERRIDE_ENV = "V5_POOLS_ALLOW_UNVERIFIED_PYTHON"


def check_python():
    minor = f"{sys.version_info.major}.{sys.version_info.minor}"
    override = os.environ.get(PYTHON_OVERRIDE_ENV) == "1"
    if minor not in VERIFIED_PYTHON and not override:
        raise SystemExit(f"REFUSED: Python {minor} is not in the verified set {VERIFIED_PYTHON}; "
                         f"set {PYTHON_OVERRIDE_ENV}=1 to build anyway (recorded in the manifest)")
    return {"python": sys.version.split()[0], "verified_minors": list(VERIFIED_PYTHON),
            "verified": minor in VERIFIED_PYTHON, "override_used": minor not in VERIFIED_PYTHON}


def provenance(code_paths):
    """Generator version, source commit and working-tree state (read-only git queries)."""
    def git(*args):
        try:
            return subprocess.run(["git", "-C", REPO_ROOT, *args], capture_output=True, text=True,
                                  check=True, timeout=30).stdout
        except (OSError, subprocess.SubprocessError):
            return None
    commit = git("rev-parse", "HEAD")
    status = git("status", "--porcelain", "--untracked-files=all")
    rel = {os.path.relpath(p, REPO_ROOT) for p in code_paths}
    dirty = None if status is None else sorted(line[3:] for line in status.splitlines() if line[3:] in rel)
    return {"generator_version": GENERATOR_VERSION,
            "source_commit": commit.strip() if commit else None,
            "working_tree_clean": None if status is None else status.strip() == "",
            "code_files_modified_or_untracked": dirty}


# D59 `exclusion_reason` vocabulary (spec §4.5 M-2). Pool-level reasons are mapped, never replaced:
# records keep their original reason and gain `d59_exclusion_reason`. None = pool hygiene that never
# becomes a dataset row (duplicates, parse failures, other languages). Mapping status: PROPOSED.
D59_REASONS = ("AMBIGUOUS", "INSUFFICIENT_CONTEXT", "ORACLE_REJECT", "AUDIT_REJECT", "OUT_OF_SCOPE", "OVER_LIMIT")
_D59_PREFIX = {"v4_filter:": "AUDIT_REJECT", "structural:": "AUDIT_REJECT"}
_D59_EXACT = {
    # attack pool
    "category_not_extracted_v5": "OUT_OF_SCOPE", "third_party_file": "OUT_OF_SCOPE",
    "duplicate_exact": None, "duplicate_canonical": None,
    # benign pools: oracle
    "oracle_exact_collision": "ORACLE_REJECT",
    # benign pools: privacy and value hygiene (not a value the pool is meant to hold)
    "email_like": "OUT_OF_SCOPE", "at_sign": "OUT_OF_SCOPE", "url_like": "OUT_OF_SCOPE",
    "digit_run_ge6": "OUT_OF_SCOPE", "phone_like": "OUT_OF_SCOPE", "dated_event": "OUT_OF_SCOPE",
    "possible_full_name": "OUT_OF_SCOPE", "too_short": "OUT_OF_SCOPE", "too_long": "OUT_OF_SCOPE",
    "empty": "OUT_OF_SCOPE", "control_char": "OUT_OF_SCOPE", "contains_digit": "OUT_OF_SCOPE",
    "parenthesis_or_disambiguation": "OUT_OF_SCOPE", "at_or_url": "OUT_OF_SCOPE",
    "contains_colon": "OUT_OF_SCOPE", "non_name_char": "OUT_OF_SCOPE", "looks_like_full_name": "OUT_OF_SCOPE",
    "too_many_tokens": "OUT_OF_SCOPE", "descriptive_label": "OUT_OF_SCOPE", "not_capitalised": "OUT_OF_SCOPE",
    # pool hygiene
    "duplicate_value": None, "malformed_row": None, "invalid_utf8": None,
}


def d59_exclusion_reason(reason):
    """Map a stage-2 exclusion reason to D59's vocabulary (or None). Unknown reasons fail loudly."""
    for prefix, mapped in _D59_PREFIX.items():
        if reason.startswith(prefix):
            return mapped
    if reason not in _D59_EXACT:
        raise KeyError(f"exclusion reason {reason!r} has no D59 mapping; add it to v5_pools_common")
    return _D59_EXACT[reason]


def d59_mapping_table():
    return {"prefix": dict(_D59_PREFIX), "exact": dict(sorted(_D59_EXACT.items())), "status": "PROPOSED"}
