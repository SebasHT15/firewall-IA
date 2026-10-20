#!/usr/bin/env python3
"""V5 attack-payload pool builder (dataset foundation, stage 2). Stdlib only.

Reads PayloadsAllTheThings (PATT) at the pinned commit, re-runs the V4 extraction loop with
provenance, and applies the controlled-reuse rules of V5-DATA-SPEC r3 section 3.1 and the
negative structural rules R1 of freeze-prep/E_attack_pool_audit:

    a. extraction      V4 `extract_sources` loop, now recording source_file, source_kind and
                       position; V4 `quality_filter` reject reasons are kept
    b. category list   JWT, CSRF, HPP, request smuggling, insecure deserialization, LDAP,
                       GraphQL, XXE are counted but EXCLUDED `category_not_extracted_v5`
    c. file deny-list  `v5_lexicon/patt_third_party_denylist_v1.json` -> EXCLUDED `third_party_file`
    d. structural      `audit_v5_attack_pool.structural_flags` -> EXCLUDED `structural:<rule>`;
                       SSTI trailing documentation comments are STRIPPED, not dropped
    e0. identity       a record whose D16 `canonical_key` is empty cannot receive a payload family
                       (V5-DATA-SPEC-r3 §4.6) -> EXCLUDED `identity_undefined:empty_canonical_key`
                       (owner ruling D-4, stage 3; not a statement that the payload is benign)
    e1-e3. admissibility  stage-3 owner ruling (round 3, issue #72), applied to the payload family key of
                       V5-DATA-SPEC-r3 §4.6 (`v5_identities.family_key`, imported, not re-implemented):
                       e1 a SQL result-table border (`+---+---+`) -> `not_a_payload:result_table_border`;
                       e2 records reviewed one by one whose identity degenerated -> their recorded reason;
                       e3 any other key shorter than the SPL-9 n-gram (4 code points) cannot be compared
                       by SPL-9 -> `identity_unobservable_spl9`. Applied before duplicates, so no duplicate
                       of an excluded record can take its place. None of these says a payload is benign
    e. duplicates      exact / V4 `canonical_key` duplicates inside one dedup scope
    f. derived fields  payload_logical, payload_wire_form, native_forms, canonical_key, ...

What this script does NOT do (by design):
  * no positive attack-keyword signature (audit F6 circularity);
  * no per-source-file cap (the value is PENDING, spec section 11.2): shares are only reported;
  * no payload_family_id, no split, no label: every ACCEPTED record is PENDING_ADJUDICATION.
    No category is declared fit; that needs the post-filter audit (spec section 7) and the human
    review (section 11.3);
  * no protected set is read (v5_pools_common.assert_not_protected).

    python3 scripts/dataset/build_v5_attack_pool.py --patt ~/PayloadsAllTheThings \
        [--out datasets/v5_sources] [--summary reports/v5/dataset-foundation/attack_pool_summary.md]

Output (deterministic: no timestamps, no absolute paths, sorted keys): <out>/attack/attack_pool.jsonl,
attack_excluded.jsonl, manifest.json.
"""
from __future__ import annotations

import argparse
import hashlib
import html.entities
import inspect
import json
import os
import re
import subprocess
import sys
import tempfile
from collections import Counter, OrderedDict, defaultdict
from urllib.parse import unquote

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(REPO_ROOT, "data_plane"))

import audit_v5_attack_pool as audit  # noqa: E402  (structural_flags: imported, never edited)
import hybrid_contracts  # noqa: E402  (ANALYZER_CATEGORIES: read only)
import parse_dataset_v4 as p4  # noqa: E402  (V4 extraction / filter: imported, never edited)
import v5_pools_common as C  # noqa: E402
import v5_identities as I  # noqa: E402  (stage-3 family key: imported, never re-implemented)

BUILDER_SCHEMA = "v5-attack-pool/v1"
PINNED_PATT_COMMIT = "e961fef231d8327bae83b563fab50aec2e6b77c0"
DEFAULT_PATT = os.path.expanduser("~/PayloadsAllTheThings")
# v2 APPROVED by the owner on 2026-10-19 (D66); v1 stays in the repository as the superseded PROPOSED list.
DEFAULT_DENYLIST = os.path.join(HERE, "v5_lexicon", "patt_third_party_denylist_v2.json")
POOL_NAME, EXCLUDED_NAME, MANIFEST_NAME = "attack_pool.jsonl", "attack_excluded.jsonl", "manifest.json"

LICENSE_PATT = "MIT (PATT, assumed for unattributed content)"
LICENSE_PROJECT = "MIT (project-authored)"

# ───────────────────────────── category plan (spec 2.3 / 3.1; tiering is PROPOSED) ─────────────────────────────
PRIMARY, REPORT_ONLY, OUT_OF_SCOPE = "primary_PROPOSED", "report_only_PROPOSED", "out_of_scope_v5"
# category_v4 -> (tier, D47 category). D47 vocabulary: hybrid_contracts.ANALYZER_CATEGORIES.
PLAN = OrderedDict([
    ("SQL Injection", (PRIMARY, "sql_injection")),
    ("XSS Injection", (PRIMARY, "xss")),
    ("Directory Traversal", (PRIMARY, "path_file_access")),
    ("File Inclusion", (PRIMARY, "path_file_access")),
    ("Command Injection", (PRIMARY, "command_injection")),
    ("Server Side Template Injection", (PRIMARY, "ssti")),
    ("Server Side Request Forgery", (REPORT_ONLY, "ssrf")),
    ("Open Redirect", (REPORT_ONLY, "open_redirect")),
    ("NoSQL Injection", (REPORT_ONLY, "other_attack")),
    ("CRLF Injection", (REPORT_ONLY, "other_attack")),      # project-authored hardcoded list
    ("XPath Injection", (REPORT_ONLY, "other_attack")),     # project-authored hardcoded list
])
# Spec 3.1 item 4: counted, EXCLUDED, never extracted for V5 (all are PATT directories).
DENIED_CATEGORIES = ("Cross-Site Request Forgery", "GraphQL Injection", "Insecure Deserialization",
                     "JSON Web Token", "LDAP Injection", "Request Smuggling", "XXE Injection")
# HPP and the smuggling variants of build_hardcoded_sources are project-authored but also deny-listed:
# they are not built at all.
HARDCODED_USED = ("CRLF Injection", "XPath Injection")
HARDCODED_NOT_USED = ("HTTP Parameter Pollution", "Request Smuggling")
HARDCODED_SOURCES = {"CRLF Injection": "hardcoded:CRLF_PAYLOADS", "XPath Injection": "hardcoded:XPATH_PAYLOADS"}
SSTI = "Server Side Template Injection"
PATH_SCOPE = "path_file_access"      # D49: directory traversal + file inclusion are ONE category


def d47_of(category):
    if category in PLAN:
        return PLAN[category][1]
    return None


def tier_of(category):
    return PLAN[category][0] if category in PLAN else OUT_OF_SCOPE


def dedup_scope(category):
    """Duplicates are searched inside a scope: the V4 category, except traversal + inclusion (D49)."""
    return PATH_SCOPE if category in ("Directory Traversal", "File Inclusion") else category


for _cat, (_tier, _d47) in PLAN.items():
    assert _d47 in hybrid_contracts.ANALYZER_CATEGORIES, (_cat, _d47)

# ───────────────────────────── native held-out forms (D15) and wire form ─────────────────────────────
PCT_RE = re.compile(r"%[0-9A-Fa-f]{2}")
DOUBLE_RE = re.compile(r"%25[0-9A-Fa-f]{2}")
UNICODE_RE = re.compile(r"\\u[0-9A-Fa-f]{4}")
NUM_ENTITY_RE = re.compile(r"&#(?:[0-9]{1,7}|[xX][0-9A-Fa-f]{1,6});")
NAME_ENTITY_RE = re.compile(r"&([A-Za-z][A-Za-z0-9]{1,31});")
IFS_LITERAL = "${IFS}"
NATIVE_FORM_ORDER = ("double_encoding", "unicode_escape", "html_entity", "ifs", "mixed_case_hex")
NATIVE_FORMS_NOT_DETECTED = {
    "param_fragmentation": "splitting one payload over several parameters is a property of the carrier "
                           "placement, not of a payload string: it cannot be defined unambiguously on a single "
                           "source payload, so it is never reported as native here."}


def hex_case_profile(wire):
    toks = PCT_RE.findall(wire)
    if not toks:
        return "none"
    up = lo = False
    for t in toks:
        letters = [c for c in t[1:] if c.isalpha()]
        u = any(c.isupper() for c in letters)
        l = any(c.islower() for c in letters)
        if u and l:
            return "mixed_within_token"
        up, lo = up or u, lo or l
    if up and lo:
        return "mixed_across_tokens"
    return "upper" if up else ("lower" if lo else "digits_only")


def native_forms(wire):
    found = []
    if DOUBLE_RE.search(wire):
        found.append("double_encoding")
    if UNICODE_RE.search(wire):
        found.append("unicode_escape")
    if NUM_ENTITY_RE.search(wire) or any((m.group(1) + ";") in html.entities.html5
                                         for m in NAME_ENTITY_RE.finditer(wire)):
        found.append("html_entity")
    if IFS_LITERAL in wire:
        found.append("ifs")
    if hex_case_profile(wire) == "mixed_within_token":
        found.append("mixed_case_hex")
    return found


def wire_form(wire):
    return "pre_encoded" if PCT_RE.search(wire) else "plain"


def logical_of(wire):
    """ENC-1: plain -> itself; pre_encoded -> ONE strict UTF-8 percent-decode (`unquote`, no `+` rule)."""
    if not PCT_RE.search(wire):
        return wire, "plain"
    try:
        return unquote(wire, encoding="utf-8", errors="strict"), "decoded_once"
    except UnicodeDecodeError:
        return wire, "invalid_utf8_kept_verbatim"


# ───────────────────────────── SSTI trailing documentation comment (strip, not drop) ─────────────────────────────
DOC_COMMENT_RE = re.compile(r"\s+(?://|#)\s+[A-Z][\w-]*(?:\s+[\w-]+){0,4}\s*$")


def strip_doc_comment(payload):
    """Remove trailing documentation comments (the shape audit rule `trailing_doc_comment` detects)."""
    s = payload
    for _ in range(3):
        if "trailing_doc_comment" not in audit.structural_flags(s, SSTI):
            break
        new = DOC_COMMENT_RE.sub("", s).rstrip()
        if new == s:
            break
        s = new
    return s


# ───────────────────────────── guards ─────────────────────────────
def check_patt(patt, pinned=PINNED_PATT_COMMIT):
    """Refuse a PATT clone that is not at the pinned commit or not clean."""
    def git(*args):
        return subprocess.run(["git", "-C", patt, *args], capture_output=True, text=True, check=True).stdout.strip()
    head = git("rev-parse", "HEAD")
    if head != pinned:
        raise SystemExit(f"REFUSED: PATT HEAD {head} != pinned {pinned}")
    dirty = git("status", "--porcelain")
    if dirty:
        raise SystemExit("REFUSED: PATT working tree is not clean:\n" + dirty[:500])
    return {"commit": head, "clean": True}


# A deny-list is PROPOSED or APPROVED as a whole (spec §3.1: "the final list is reviewed file by file and
# hashed in the manifest"). An APPROVED list records who approved it, when, and the decision reference;
# a list mixing entry statuses is refused, so a partial approval cannot pass as a final list.
DENYLIST_STATUSES = ("PROPOSED", "APPROVED")
DENYLIST_APPROVAL_FIELDS = ("approved_by", "date", "decision_ref")


def load_denylist(path):
    C.assert_not_protected(path)
    with open(path, "rb") as fh:
        data = fh.read()
    doc = json.loads(data.decode("utf-8"))
    if doc.get("schema") != "v5-patt-third-party-denylist/v1":
        raise SystemExit(f"REFUSED: unknown deny-list schema {doc.get('schema')!r}")
    status = doc.get("status")
    if status not in DENYLIST_STATUSES:
        raise SystemExit(f"REFUSED: deny-list status {status!r} not in {DENYLIST_STATUSES}")
    if status == "APPROVED":
        appr = doc.get("approval")
        if not isinstance(appr, dict) or any(not str(appr.get(k) or "").strip() for k in DENYLIST_APPROVAL_FIELDS):
            raise SystemExit(f"REFUSED: an APPROVED deny-list needs approval.{'/'.join(DENYLIST_APPROVAL_FIELDS)}")
    denied = {}
    for e in doc["denied"]:
        if e.get("status") != status:
            raise SystemExit(f"REFUSED: deny-list entry status differs from the list status {status}: {e['path']}")
        if e["path"] in denied:
            raise SystemExit(f"REFUSED: duplicate deny-list path {e['path']}")
        denied[e["path"]] = e
    return doc, denied, C.sha256_bytes(data)


# ───────────────────────────── a. extraction with provenance ─────────────────────────────
def extract_patt(patt):
    """V4 `extract_sources` loop with provenance. Returns (candidates, files).

    candidate = {category, source_file, source_kind, block_index, line_index, block_level, raw}
    Order, line splitting, fence handling and error handling are those of V4 (sorted dirs/files,
    `FENCE_RE`, BLOCK_LEVEL_CATEGORIES, `splitlines()`, `errors="ignore"`, OSError -> skip).
    `line_index` is the index in `splitlines()` (not necessarily the physical line number);
    for a whole-block payload it is 0 and `block_level` is True. `block_index` is the ordinal of
    the fenced block among ALL fenced blocks of the file (None for .txt files).
    """
    cands, files = [], {}
    for category in sorted(p4.CATEGORY_SHAPES):
        cat_dir = os.path.join(patt, category)
        if not os.path.isdir(cat_dir):
            raise SystemExit(f"FATAL: category directory not found: {cat_dir}")
        for root, dirs, fnames in os.walk(cat_dir):
            dirs.sort()
            for fname in sorted(fnames):
                fpath = os.path.join(root, fname)
                rel = os.path.relpath(fpath, patt).replace(os.sep, "/")
                if fname.endswith(".md"):
                    kind = "md"
                elif fname.endswith(".txt"):
                    kind = "txt"
                else:
                    continue
                info = {"category": category, "kind": kind, "bytes": None, "sha256": None,
                        "readable": True, "candidates": 0}
                files[rel] = info
                try:
                    with open(fpath, encoding="utf-8", errors="ignore") as fh:
                        content = fh.read()
                    with open(fpath, "rb") as bf:
                        raw_bytes = bf.read()
                    info["bytes"], info["sha256"] = len(raw_bytes), C.sha256_bytes(raw_bytes)
                except OSError:
                    info["readable"] = False
                    continue
                if kind == "md":
                    for bi, blk in enumerate(p4.FENCE_RE.findall(content)):
                        if category in p4.BLOCK_LEVEL_CATEGORIES and blk.count("\n") > 1:
                            items, block_level = [blk.strip()], True
                        else:
                            items, block_level = blk.splitlines(), False
                        for li, raw in enumerate(items):
                            cands.append({"category": category, "source_file": rel, "source_kind": "md",
                                          "block_index": bi, "line_index": li, "block_level": block_level,
                                          "raw": raw})
                else:
                    for li, raw in enumerate(content.splitlines()):
                        cands.append({"category": category, "source_file": rel, "source_kind": "txt",
                                      "block_index": None, "line_index": li, "block_level": False, "raw": raw})
    for c in cands:
        files[c["source_file"]]["candidates"] += 1
    return cands, files


def hardcoded_candidates():
    """Project-authored CRLF / XPath lists from V4 `build_hardcoded_sources` (HPP / smuggling are not used)."""
    per_source = Counter()
    out = []
    for row in p4.build_hardcoded_sources():
        if row["category"] not in HARDCODED_USED:
            continue
        src = row["source"]
        out.append({"category": row["category"], "source_file": src, "source_kind": "hardcoded",
                    "block_index": None, "line_index": per_source[src], "block_level": False,
                    "raw": row["payload"]})
        per_source[src] += 1
    return out


def v4_reference(patt):
    """Run the real V4 `extract_sources` for the equivalence check (no side effects on PATT)."""
    saved = p4.PAYLOADS_REPO
    p4.PAYLOADS_REPO = patt
    try:
        stats = {"reject_reasons": Counter(), "candidates_per_category": Counter()}
        rows = p4.extract_sources(stats)
    finally:
        p4.PAYLOADS_REPO = saved
    return rows, stats


def sort_key(r):
    return (r["source_file"], -1 if r["block_index"] is None else r["block_index"], r["line_index"])


def make_record_id(c):
    bi = "" if c["block_index"] is None else str(c["block_index"])
    h = hashlib.sha256("\0".join([c["source_file"], c["source_kind"], bi, str(c["line_index"]),
                                  c["raw"]]).encode("utf-8", "surrogatepass")).hexdigest()
    return h[:16]


# ───────────────────────────── pipeline ─────────────────────────────
RECORD_KEYS = ("record_id", "category_v4", "d47_category", "reason_string", "tier", "dedup_scope",
               "source_file", "source_kind", "block_index", "line_index", "block_level",
               "payload_raw", "v4_filter_reason", "payload_v4", "payload_wire", "payload_logical",
               "logical_decode", "payload_wire_form", "native_forms", "hex_case_profile", "canonical_key",
               "transform", "structural_flags", "status", "exclusion_reason", "duplicate_of",
               "denylist_reason", "also_in_categories", "label_status", "license", "d59_exclusion_reason")


def reason_string_of(category):
    if category in p4.CATEGORY_SHAPES:
        return p4.CATEGORY_SHAPES[category][0]
    return p4.HARDCODED_SHAPES[category][0]


def process(cands, denied):
    """Apply steps a-f to candidates (V4 order). Returns the list of records (ACCEPTED + EXCLUDED)."""
    recs = []
    for c in cands:
        cat = c["category"]
        r = dict.fromkeys(RECORD_KEYS)
        r.update(record_id=make_record_id(c), category_v4=cat, d47_category=d47_of(cat),
                 reason_string=reason_string_of(cat), tier=tier_of(cat), dedup_scope=dedup_scope(cat),
                 source_file=c["source_file"], source_kind=c["source_kind"], block_index=c["block_index"],
                 line_index=c["line_index"], block_level=c["block_level"], payload_raw=c["raw"],
                 structural_flags=[], native_forms=[], also_in_categories=[],
                 license=LICENSE_PROJECT if c["source_kind"] == "hardcoded" else LICENSE_PATT)
        recs.append(r)
        # a. V4 quality filter (PATT rows only; V4 did not filter the project-authored lists)
        if c["source_kind"] == "hardcoded":
            payload, reason = c["raw"], "not_applied_project_authored"
        else:
            payload, reason = p4.quality_filter(c["raw"], cat)
            if payload is None:
                r.update(v4_filter_reason=reason, status=C.EXCLUDED, exclusion_reason=f"v4_filter:{reason}")
                continue
            reason = "accepted"
        r.update(v4_filter_reason=reason, payload_v4=payload)
        # derived fields on the V4-accepted payload (replaced below if the SSTI comment is stripped)
        work = payload
        # b. category deny-list
        if cat in DENIED_CATEGORIES:
            _fill(r, work)
            r.update(status=C.EXCLUDED, exclusion_reason=C_DENY_CATEGORY)
            continue
        # c. third-party file deny-list
        if c["source_file"] in denied:
            _fill(r, work)
            r.update(status=C.EXCLUDED, exclusion_reason="third_party_file",
                     denylist_reason=denied[c["source_file"]]["reason"])
            continue
        # d. negative structural filters (SSTI: strip trailing documentation comments first)
        if cat == SSTI and "trailing_doc_comment" in audit.structural_flags(work, cat):
            stripped = strip_doc_comment(work)
            if stripped != work:
                r["transform"] = "stripped_doc_comment"
                work = stripped
        _fill(r, work)
        if len(work) < p4.MIN_LEN:
            r.update(status=C.EXCLUDED, exclusion_reason="structural:too_short_after_strip")
            continue
        flags = audit.structural_flags(work, cat)
        r["structural_flags"] = flags
        if flags:
            r.update(status=C.EXCLUDED, exclusion_reason=f"structural:{flags[0]}")
            continue
        # e0. identity: an empty D16 canonical_key leaves no payload_family_id (§4.6, owner ruling D-4)
        if r["canonical_key"] == "":
            r.update(status=C.EXCLUDED, exclusion_reason=IDENTITY_EMPTY)
            continue
        # e1-e3. admissibility of the family identity (owner ruling, stage 3 round 3)
        inadmissible = admissibility_reason(r)
        if inadmissible:
            r.update(status=C.EXCLUDED, exclusion_reason=inadmissible)
            continue
        r["status"] = "CANDIDATE"          # survives a-e3; duplicates decided below
    _dedupe(recs)
    _check_no_readmission(recs)
    _cross_category(recs)
    for r in recs:
        if r["status"] == C.ACCEPTED:
            r["label_status"] = C.LABEL_PENDING
    return recs


C_DENY_CATEGORY = "category_not_extracted_v5"
IDENTITY_EMPTY = "identity_undefined:empty_canonical_key"

# e1-e3 (owner ruling, stage 3 round 3, issue #72). Methodological admissibility of the data, not a
# security claim: an excluded record is never declared benign and keeps its provenance in the ledger.
NOT_A_PAYLOAD_TABLE_BORDER = "not_a_payload:result_table_border"
IDENTITY_UNOBSERVABLE, is_inadmissible = C.IDENTITY_UNOBSERVABLE, C.is_inadmissible   # one vocabulary
_TABLE_BORDER = re.compile(r"\+(?:-+\+)+")          # a MySQL client result-table rule line, nothing else
# e2: records reviewed individually in round 3 (the accepted record and every duplicate of it), with the
# family key they were reviewed under. A reviewed record whose key changes stops the build; a record
# not listed here never inherits these reasons (a short key then falls to e3).
REVIEWED_DEGENERATE = {
    # `1/*'*/`, `1/*!1111'*/`: the D16 comment collapse leaves digits only
    "375a6a10bcf137a3": ("0", "identity_degenerate:digits_only_key"),
    "5ed636c938fe1826": ("0", "identity_degenerate:digits_only_key"),
    # `%0Aid`, `%0Aid%0A`, `%0a id %0a`: the LF command separator is removed with the whitespace
    "40e435d53f53c46b": ("id", "identity_degenerate:command_separator_lost"),
    "1c1f8a6e308ca42e": ("id", "identity_degenerate:command_separator_lost"),
    "6b556c01ad5bd7fd": ("id", "identity_degenerate:command_separator_lost"),
    "1c43843b62d09e77": ("id", "identity_degenerate:command_separator_lost"),
    "d9e8783e0b37b4aa": ("id", "identity_degenerate:command_separator_lost"),
    "72dc0fab507ede36": ("id", "identity_degenerate:command_separator_lost"),
    # `7 * 7`: an isolated arithmetic expression, no template delimiter that would justify BLOCK
    "722c3ef462f5c8bc": ("0*0", "not_a_payload:isolated_arithmetic"),
}


def admissibility_reason(r):
    """e1-e3 for a record that survived a-e0; None when admissible."""
    if _TABLE_BORDER.fullmatch(r["payload_wire"].strip()):
        return NOT_A_PAYLOAD_TABLE_BORDER
    key = I.family_key(r["payload_wire"])
    reviewed = REVIEWED_DEGENERATE.get(r["record_id"])
    if reviewed is not None:
        if key != reviewed[0]:
            raise SystemExit(f"REFUSED: reviewed record {r['record_id']} now has family key {key!r}, "
                             f"reviewed under {reviewed[0]!r}; review it again")
        return reviewed[1]
    if I.is_unobservable(key):
        return IDENTITY_UNOBSERVABLE
    return None


def _check_no_readmission(recs):
    """No ACCEPTED record, in any scope or from any source, carries the family key of a record excluded
    by e1-e3: an excluded identity cannot come back through another file."""
    keys = {I.family_key(r["payload_wire"]) for r in recs
            if r["status"] == C.EXCLUDED and is_inadmissible(r["exclusion_reason"])}
    back = sorted(r["record_id"] for r in recs if r["status"] == C.ACCEPTED and I.family_key(r["payload_wire"]) in keys)
    if back:
        raise SystemExit(f"REFUSED: ACCEPTED records share a family key with an inadmissible record: {back}")




def _fill(r, work):
    wire = work
    logical, dec = logical_of(wire)
    r.update(payload_wire=wire, payload_logical=logical, logical_decode=dec, payload_wire_form=wire_form(wire),
             native_forms=native_forms(wire), hex_case_profile=hex_case_profile(wire),
             canonical_key=p4.canonical_key(wire))


def _dedupe(recs):
    """e. Keep the first by (source_file, block_index, line_index) among survivors of a-d."""
    cand = sorted((r for r in recs if r["status"] == "CANDIDATE"), key=sort_key)
    canon_keeper, exact_seen = {}, set()
    for r in cand:
        scope = r["dedup_scope"]
        kc = (scope, r["canonical_key"])
        ke = (scope, r["payload_wire"])
        if kc in canon_keeper:
            keeper = canon_keeper[kc]
            r.update(status=C.EXCLUDED, duplicate_of=keeper["record_id"],
                     exclusion_reason="duplicate_exact" if ke in exact_seen else "duplicate_canonical")
        else:
            canon_keeper[kc] = r
            r["status"] = C.ACCEPTED
        exact_seen.add(ke)


def _cross_category(recs):
    """Same canonical_key accepted in two dedup scopes: listed, never excluded, never relabelled."""
    scopes = defaultdict(set)
    for r in recs:
        if r["status"] == C.ACCEPTED:
            scopes[r["canonical_key"]].add(r["dedup_scope"])
    for r in recs:
        if r["status"] == C.ACCEPTED:
            r["also_in_categories"] = sorted(scopes[r["canonical_key"]] - {r["dedup_scope"]})


# ───────────────────────────── counts, shares, manifest ─────────────────────────────
AUDIT_R6 = {   # E_attack_pool_audit section 7 R6 (in-sample, optimistic): pool, est. clean V+P, range
    "SQL Injection": (1278, 1021, (802, 1133)), "XSS Injection": (2238, 881, (578, 1144)),
    "Directory Traversal": (10219, 3161, (1865, 4322)), "File Inclusion": (3321, 2836, (2408, 3010)),
    "Command Injection": (453, 410, (348, 423)), "Server Side Template Injection": (369, 257, (198, 287)),
    "Server Side Request Forgery": (202, 133, (100, 148)), "Open Redirect": (242, 219, (192, 219)),
    "NoSQL Injection": (83, 56, (39, 61)), "CRLF Injection": (22, 22, (18, 22)),
    "XPath Injection": (31, 27, (19, 30))}
SPEC_AFTER_DENYLIST = {"SQL Injection": 1000, "XSS Injection": 705, PATH_SCOPE: 2828}   # spec 2.3 (initial 20 files)
SHARE_FLAG = 0.25      # audit R2 suggestion; the cap VALUE is PENDING (spec 11.2), nothing is capped


def compute_counts(recs):
    cats = list(PLAN) + [c for c in sorted(DENIED_CATEGORIES)]
    table = OrderedDict()
    for cat in cats:
        rs = [r for r in recs if r["category_v4"] == cat]
        by_reason = Counter(r["exclusion_reason"] for r in rs if r["status"] == C.EXCLUDED)
        v4 = sum(n for k, n in by_reason.items() if k.startswith("v4_filter:"))
        struct = sum(n for k, n in by_reason.items() if k.startswith("structural:"))
        ident = sum(n for k, n in by_reason.items() if k.startswith("identity_undefined:"))
        inadm = sum(n for k, n in by_reason.items() if is_inadmissible(k))
        table[cat] = {
            "tier": tier_of(cat), "d47_category": d47_of(cat),
            "extracted": len(rs),
            "v4_filter_rejected": v4,
            "category_denied": by_reason.get(C_DENY_CATEGORY, 0),
            "third_party_denied": by_reason.get("third_party_file", 0),
            "structural_excluded": struct,
            "identity_undefined": ident,
            "identity_inadmissible": inadm,
            "duplicate_exact": by_reason.get("duplicate_exact", 0),
            "duplicate_canonical": by_reason.get("duplicate_canonical", 0),
            "accepted": sum(1 for r in rs if r["status"] == C.ACCEPTED),
            "ssti_comment_stripped_accepted": sum(1 for r in rs if r["status"] == C.ACCEPTED and r["transform"]),
            "by_reason": dict(sorted(by_reason.items())),
        }
        t = table[cat]
        assert t["extracted"] == (t["v4_filter_rejected"] + t["category_denied"] + t["third_party_denied"]
                                  + t["structural_excluded"] + t["identity_undefined"] + t["identity_inadmissible"]
                                  + t["duplicate_exact"] + t["duplicate_canonical"]
                                  + t["accepted"]), cat
    return table


def compute_shares(recs):
    """g. Per-source-file share of each dedup scope's ACCEPTED pool. Reported only; no cap is applied."""
    out = OrderedDict()
    acc = [r for r in recs if r["status"] == C.ACCEPTED]
    for scope in sorted({r["dedup_scope"] for r in acc}):
        rs = [r for r in acc if r["dedup_scope"] == scope]
        n = len(rs)
        cnt = Counter(r["source_file"] for r in rs)
        files = [{"source_file": f, "accepted": k, "share": round(k / n, 6), "above_25pct": k / n > SHARE_FLAG}
                 for f, k in sorted(cnt.items(), key=lambda kv: (-kv[1], kv[0]))]
        out[scope] = {"accepted": n, "files": files, "flagged_files": [x["source_file"] for x in files
                                                                         if x["above_25pct"]]}
    return out


def unique_canonical(recs, pred):
    scopes = defaultdict(set)
    for r in recs:
        if r["canonical_key"] is not None and pred(r):
            scopes[r["dedup_scope"]].add(r["canonical_key"])
    return {s: len(v) for s, v in sorted(scopes.items())}


def filter_rules_fingerprint():
    mats = OrderedDict([
        ("v4_quality_filter_source", inspect.getsource(p4.quality_filter)),
        ("v4_constants", [p4.PLACEHOLDER_RE.pattern, list(p4.PLACEHOLDER_LITERALS), list(p4.MARKDOWN_START),
                          list(p4.REFERENCE_HOSTS), list(p4.ATTACK_HINTS), p4.PROSE_RE.pattern, p4.MIN_LEN,
                          p4.MAX_LEN, p4.FENCE_RE.pattern, sorted(p4.BLOCK_LEVEL_CATEGORIES)]),
        ("v4_canonical_key_source", inspect.getsource(p4.canonical_key)),
        ("structural_flags_source", inspect.getsource(audit.structural_flags)),
        ("structural_constants", [audit._HEX_ESC.pattern, sorted(audit._URLENC_CATS), sorted(audit._PATH_CATS),
                                  audit._CODE_START.pattern, audit._ASSIGN.pattern, audit._TOOL_START.pattern,
                                  audit._PROSE_WORD.pattern]),
        ("ssti_strip_regex", DOC_COMMENT_RE.pattern),
        ("category_plan", [[k, v[0], v[1]] for k, v in PLAN.items()]),
        ("denied_categories", list(DENIED_CATEGORIES)),
        ("native_form_regexes", [PCT_RE.pattern, DOUBLE_RE.pattern, UNICODE_RE.pattern, NUM_ENTITY_RE.pattern,
                                 NAME_ENTITY_RE.pattern, IFS_LITERAL]),
    ])
    return C.sha256_bytes(json.dumps(mats, sort_keys=True, ensure_ascii=False).encode("utf-8"))


def build(patt, out_dir=C.DEFAULT_OUT_DIR, denylist_path=DEFAULT_DENYLIST, *, patt_guard=check_patt,
          strict_denylist=True):
    """Run the whole pipeline; write <out_dir>/attack/*; return the manifest dict."""
    python_info = C.check_python()
    C.assert_not_protected(patt)
    C.assert_not_protected(out_dir)
    patt_info = patt_guard(patt)
    doc, denied, deny_sha = load_denylist(denylist_path)

    cands, files = extract_patt(patt)
    # Equivalence with the V4 loop (accepted rows in order, per-reason counts, candidate counts).
    v4_rows, v4_stats = v4_reference(patt)
    mine_acc, mine_reasons, mine_cand = [], Counter(), Counter()
    for c in cands:
        mine_cand[c["category"]] += 1
        payload, reason = p4.quality_filter(c["raw"], c["category"])
        mine_reasons[reason] += 1
        if payload is not None:
            mine_acc.append((c["category"], payload, c["source_file"]))
    v4_acc = [(r["category"], r["payload"], r["source"]) for r in v4_rows]
    equivalence = {
        "v4_accepted_rows": len(v4_acc), "v5_loop_accepted_rows": len(mine_acc),
        "multiset_equal": Counter(v4_acc) == Counter(mine_acc),
        "ordered_equal": v4_acc == mine_acc,
        "reject_reason_counts_equal": mine_reasons == Counter(v4_stats["reject_reasons"]),
        "candidate_counts_equal": mine_cand == Counter(v4_stats["candidates_per_category"]),
    }
    if not (equivalence["multiset_equal"] and equivalence["ordered_equal"]
            and equivalence["reject_reason_counts_equal"] and equivalence["candidate_counts_equal"]):
        raise SystemExit(f"FATAL: V5 extraction loop diverges from V4 extract_sources: {equivalence}")

    missing = sorted(p for p in denied if p not in files)
    if missing and strict_denylist:
        raise SystemExit(f"FATAL: deny-list paths not present in PATT (stale deny-list?): {missing}")

    cands = cands + hardcoded_candidates()
    recs = process(cands, denied)
    ids = [r["record_id"] for r in recs]
    if len(set(ids)) != len(ids):
        raise SystemExit("FATAL: record_id collision")
    assert all(r["label_status"] in (None, C.LABEL_PENDING) for r in recs)   # nothing is ever VERIFIED
    accepted = [r for r in recs if r["status"] == C.ACCEPTED]
    excluded = [r for r in recs if r["status"] == C.EXCLUDED]
    for r in recs:   # D59 mapping added beside the original reason, which is never changed
        r["d59_exclusion_reason"] = (C.d59_exclusion_reason(r["exclusion_reason"])
                                     if r["status"] == C.EXCLUDED else None)
    assert len(accepted) + len(excluded) == len(recs)

    attack_dir = os.path.join(out_dir, "attack")
    key = lambda r: sort_key(r) + (r["record_id"],)           # noqa: E731
    arts = []
    for name, rows in ((POOL_NAME, accepted), (EXCLUDED_NAME, excluded)):
        a = C.write_jsonl(os.path.join(attack_dir, name), rows, key)
        a["path"] = name
        arts.append(a)

    counts = compute_counts(recs)
    shares = compute_shares(recs)
    # per-file table
    per_file = OrderedDict()
    for rel in sorted(files):
        f = files[rel]
        rs = [r for r in recs if r["source_file"] == rel]
        per_file[rel] = {"category": f["category"], "kind": f["kind"], "bytes": f["bytes"], "sha256": f["sha256"],
                         "readable": f["readable"], "candidates": f["candidates"],
                         "v4_accepted": sum(1 for r in rs if r["v4_filter_reason"] == "accepted"),
                         "accepted": sum(1 for r in rs if r["status"] == C.ACCEPTED),
                         "third_party_denied": rel in denied}
    for rel in sorted({r["source_file"] for r in recs if r["source_kind"] == "hardcoded"}):
        rs = [r for r in recs if r["source_file"] == rel]
        per_file[rel] = {"category": rs[0]["category_v4"], "kind": "hardcoded", "bytes": None, "sha256": None,
                         "readable": True, "candidates": len(rs), "v4_accepted": len(rs),
                         "accepted": sum(1 for r in rs if r["status"] == C.ACCEPTED), "third_party_denied": False}

    # review coverage: every file read in a planned PATT category is decided in the deny-list file
    planned_patt = [c for c in PLAN if c in p4.CATEGORY_SHAPES]
    decided = set(denied) | {e["path"] for e in doc["reviewed_not_denied"]}
    unreviewed = sorted(rel for rel, f in files.items() if f["category"] in planned_patt and rel not in decided)

    structural_first = Counter(r["exclusion_reason"] for r in excluded if r["exclusion_reason"].startswith("structural:"))
    structural_any = Counter(fl for r in recs for fl in r["structural_flags"])
    # cross-category listing
    cross = defaultdict(list)
    for r in accepted:
        if r["also_in_categories"]:
            cross[tuple(sorted([r["dedup_scope"]] + r["also_in_categories"]))].append(r)
    cross_summary = [{"scopes": list(k), "accepted_records": len(v),
                      "examples": [{"record_id": x["record_id"], "payload_wire": x["payload_wire"][:80]}
                                   for x in sorted(v, key=lambda z: z["record_id"])[:5]]}
                     for k, v in sorted(cross.items())]

    spec_initial = {p for p, e in denied.items() if e["basis"] == "spec_initial_list"}
    v4_unique = unique_canonical(recs, lambda r: r["v4_filter_reason"] in ("accepted", "not_applied_project_authored"))
    spec_repro = unique_canonical(recs, lambda r: r["v4_filter_reason"] in ("accepted", "not_applied_project_authored")
                                  and r["source_file"] not in spec_initial)
    after_deny = unique_canonical(recs, lambda r: r["v4_filter_reason"] in ("accepted", "not_applied_project_authored")
                                  and r["source_file"] not in denied)
    audit_cmp = OrderedDict()
    for cat, (pool, est, rng) in AUDIT_R6.items():
        audit_cmp[cat] = {"audit_pool_unique_canonical": pool, "audit_est_clean_VP": est,
                          "audit_est_range": list(rng), "builder_accepted": counts[cat]["accepted"]}
    # informational typographic-corruption counter (NOT a filter; the 15 rules do not detect it)
    typo = Counter(r["category_v4"] for r in accepted if re.search("[–—′‘’“”]",
                                                                  r["payload_wire"]))

    code = C.code_fingerprint([os.path.abspath(__file__), audit.__file__, p4.__file__, C.__file__,
                               hybrid_contracts.__file__, I.__file__])
    manifest = OrderedDict([
        ("schema", BUILDER_SCHEMA), ("pool_schema", C.SCHEMA),
        ("status", "STAGE2_UNAUDITED: no category is declared fit; no payload is VERIFIED (post-filter audit "
                   "spec section 7 and human review section 11.3 pending)"),
        ("tiering", "PROPOSED"),
        ("patt", {"commit": patt_info["commit"], "clean": patt_info["clean"], "pinned": PINNED_PATT_COMMIT,
                  "license": "MIT (LICENSE: Copyright (c) 2019 Swissky)"}),
        ("denylist", {"path": os.path.relpath(denylist_path, REPO_ROOT) if
                      os.path.abspath(denylist_path).startswith(REPO_ROOT) else os.path.basename(denylist_path),
                      "sha256": deny_sha, "status": doc["status"], "denied_files": len(denied),
                      "denied_by_basis": dict(sorted(Counter(e["basis"].split(" ")[0] for e in denied.values()).items())),
                      "reviewed_not_denied": len(doc["reviewed_not_denied"]),
                      "denied_paths_missing_from_patt": missing, "unreviewed_files_read": unreviewed,
                      **({"approval": doc["approval"]} if doc["status"] == "APPROVED" else {})}),
        ("project_authored_lists", {"used": list(HARDCODED_USED), "not_used": list(HARDCODED_NOT_USED),
                                    "sha256": C.sha256_bytes(json.dumps(
                                        {"CRLF_PAYLOADS": p4.CRLF_PAYLOADS, "XPATH_PAYLOADS": p4.XPATH_PAYLOADS},
                                        sort_keys=True).encode("utf-8"))}),
        ("filter_rules_fingerprint", filter_rules_fingerprint()),
        ("code_fingerprint", code),
        ("environment", C.environment()),
        ("python", python_info),
        ("provenance", C.provenance([os.path.abspath(__file__), audit.__file__, p4.__file__, C.__file__,
                                     hybrid_contracts.__file__, I.__file__, os.path.abspath(denylist_path)])),
        ("identity_admissibility", {
            "ruling": "stage 3 round 3 owner ruling (issue #72): data admissibility, not a security claim",
            "pfid_rules_version": I.PFID_RULES_VERSION, "spl9_ngram": I.NEAR_DUP_N,
            "table_border_pattern": _TABLE_BORDER.pattern,
            "reviewed_degenerate_records": {k: list(v) for k, v in sorted(REVIEWED_DEGENERATE.items())},
            # a reviewed id absent from this build (stale list, or a changed source) is shown, never silent
            "reviewed_records_not_seen": sorted(set(REVIEWED_DEGENERATE) - {r["record_id"] for r in recs}),
            "excluded_by_reason": dict(sorted(Counter(r["exclusion_reason"] for r in excluded
                                                      if is_inadmissible(r["exclusion_reason"])).items()))}),
        ("d59_mapping", C.d59_mapping_table()),
        ("d59_exclusion_counts", dict(sorted(Counter(str(r["d59_exclusion_reason"]) for r in excluded).items()))),
        ("v4_equivalence", equivalence),
        ("category_plan", {c: {"tier": t, "d47_category": d} for c, (t, d) in PLAN.items()}),
        ("denied_categories", list(DENIED_CATEGORIES)),
        ("counts", counts),
        ("v4_reject_reasons", {cat: dict(sorted(Counter(r["v4_filter_reason"] for r in recs if r["category_v4"] == cat
                                                         and r["v4_filter_reason"] not in ("accepted", "not_applied_project_authored")).items()))
                               for cat in counts}),
        ("structural_rules", {"first_flag_partition": dict(sorted(structural_first.items())),
                              "fires_any_on_rows_reaching_step": dict(sorted(structural_any.items()))}),
        ("per_source_file_share", {"suggested_flag_threshold": SHARE_FLAG,
                                   "cap_applied": False, "cap_value": "PENDING (spec section 11.2)",
                                   "scopes": shares}),
        ("per_file", per_file),
        ("unique_canonical", {"v4_accepted_before_denylist": v4_unique, "after_spec_initial_denylist": spec_repro,
                              "after_full_proposed_denylist": after_deny,
                              "spec_2_3_after_denylist": SPEC_AFTER_DENYLIST}),
        ("audit_comparison", audit_cmp),
        ("cross_category_canonical_duplicates", cross_summary),
        ("native_forms_not_detected", NATIVE_FORMS_NOT_DETECTED),
        ("native_form_counts_accepted", dict(sorted(Counter(f for r in accepted for f in r["native_forms"]).items()))),
        ("wire_form_counts_accepted", dict(sorted(Counter(r["payload_wire_form"] for r in accepted).items()))),
        ("typographic_corruption_not_filtered_accepted", dict(sorted(typo.items()))),
        ("artifacts", arts),
        ("known_limitations", [
            "Unattributed PATT content is used under PATT's MIT licence as an ASSUMPTION, not a verified fact; "
            "PATT has many contributors and a missing header does not prove authorship.",
            "The third-party deny-list is PROPOSED and was reviewed offline; no upstream licence was re-verified.",
            "The category tiering (primary / report-only) is PROPOSED.",
            "The 15 structural rules are negative and were designed on the audit sample (in-sample); the "
            "post-filter audit (spec section 7) and the blind human review (section 11.3) have NOT been run.",
            "label_status is PENDING_ADJUDICATION for every record; wrong-category contamination cannot be "
            "filtered structurally.",
            "The per-source-file cap value is PENDING (spec section 11.2); shares above 25% are reported only.",
            "Typographic corruption (en-dash / prime / curly quotes) and `0x`/`\\x` mutation text outside the "
            "scoped categories are not detected by the 15 rules.",
            "param_fragmentation cannot be detected on a single payload string and is never reported as native.",
            "Duplicates are searched inside one scope; directory traversal and file inclusion share a scope "
            "(D49). Cross-scope canonical duplicates are listed, not excluded and never relabelled.",
            "`.fuzz` / extensionless FuzzDB-style PATT lists are not read by the V4 extraction loop.",
        ]),
    ])
    C.write_json(os.path.join(attack_dir, MANIFEST_NAME), manifest)
    return manifest


# ───────────────────────────── determinism and summary ─────────────────────────────
def artifact_hashes(out_dir):
    d = os.path.join(out_dir, "attack")
    return {n: C.sha256_file(os.path.join(d, n)) for n in (POOL_NAME, EXCLUDED_NAME, MANIFEST_NAME)}


def verify_determinism(patt, out_dir, denylist_path, **kw):
    first = artifact_hashes(out_dir)
    with tempfile.TemporaryDirectory(prefix="v5_attack_det_") as tmp:
        build(patt, tmp, denylist_path, **kw)
        second = artifact_hashes(tmp)
    return {"run1": first, "run2": second, "identical": first == second}


def render_summary(m, det=None, doc=None):
    cnt, L = m["counts"], []
    pct = lambda x: f"{100 * x:.1f}%"                                                   # noqa: E731
    L += ["# V5 attack pool: stage-2 summary (generated by `build_v5_attack_pool.py`)", "",
          "Status: **STAGE2_UNAUDITED**. No category is declared fit and no payload is VERIFIED: every ACCEPTED "
          "record is `PENDING_ADJUDICATION`. The post-filter audit (spec section 7) and the blind human review "
          "(section 11.3) are pending. Tiering and deny-list are PROPOSED. Nothing is capped (cap value PENDING).", "",
          f"PATT `{m['patt']['commit'][:12]}` (clean={m['patt']['clean']}); deny-list sha256 `{m['denylist']['sha256'][:16]}`; "
          f"filter-rules fingerprint `{m['filter_rules_fingerprint'][:16]}`.",
          f"V4 equivalence on the real PATT: accepted rows {m['v4_equivalence']['v4_accepted_rows']} (V4) vs "
          f"{m['v4_equivalence']['v5_loop_accepted_rows']} (V5 loop), multiset equal={m['v4_equivalence']['multiset_equal']}, "
          f"ordered equal={m['v4_equivalence']['ordered_equal']}, reject-reason counts equal="
          f"{m['v4_equivalence']['reject_reason_counts_equal']}."]
    if det:
        L.append(f"Determinism: two runs, artifacts identical={det['identical']}; attack_pool.jsonl sha256 "
                 f"`{det['run1'][POOL_NAME][:16]}` / `{det['run2'][POOL_NAME][:16]}`, manifest `{det['run1'][MANIFEST_NAME][:16]}`.")
    L += ["", "## Pipeline counts per category (each row sums: extracted = v4 + cat + 3rd + struct + identity + inadmissible + dups + accepted)", "",
          "| Category | Tier | Extracted | V4-rejected | Category-denied | 3rd-party | Structural | Identity undefined | Identity inadmissible | Dup exact/canon | Accepted |",
          "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for cat, t in cnt.items():
        L.append(f"| {cat} | {t['tier'].replace('_PROPOSED', '*')} | {t['extracted']} | {t['v4_filter_rejected']} | "
                 f"{t['category_denied']} | {t['third_party_denied']} | {t['structural_excluded']} | {t['identity_undefined']} | {t['identity_inadmissible']} | "
                 f"{t['duplicate_exact']}/{t['duplicate_canonical']} | {t['accepted']} |")
    L += ["", "`*` = PROPOSED tiering. SSTI rows with a stripped trailing comment (kept, `transform`): "
          f"{cnt[SSTI]['ssti_comment_stripped_accepted']}. Hardcoded CRLF/XPath rows skip the V4 filter (as in V4). "
          "Directory traversal + file inclusion share one duplicate scope (D49).", "",
          "## Structural rules (first-flag partition of excluded rows)", ""]
    sp = m["structural_rules"]["first_flag_partition"]
    L.append(", ".join(f"`{k.split(':')[1]}` {v}" for k, v in sorted(sp.items(), key=lambda kv: -kv[1])) or "none")
    L += ["", "## Third-party file deny-list (PROPOSED; `v5_lexicon/patt_third_party_denylist_v1.json`)", "",
          f"{m['denylist']['denied_files']} files denied ({m['denylist']['denied_by_basis']}); "
          f"{m['denylist']['reviewed_not_denied']} reviewed and kept; unreviewed files read: "
          f"{len(m['denylist']['unreviewed_files_read'])}.", "",
          "| Denied file | V4-accepted rows | Basis |", "|---|---:|---|"]
    doc = doc or {"denied": []}
    for e in doc["denied"]:
        pf = m["per_file"].get(e["path"], {})
        L.append(f"| `{e['path'].split('/', 1)[1] if '/' in e['path'] else e['path']}` | {pf.get('v4_accepted', 0)} | "
                 f"{e['basis'].split(' ')[0].replace('spec_initial_list', 'spec').replace('stage2_file_review', 'NEW stage-2')} |")
    L += ["", "Adjudication of the files the spec only noted: `XSSDetection.txt` DENIED (RSnake vectors and ha.ckers.org "
          "lines in content), `IntrudersXSS.txt` DENIED (108 of 180 lines identical to BRUTELOGIC-XSS-STRINGS), "
          "`jsonp_endpoint.txt` KEPT unknown origin (flagged: real third-party hostnames inside payloads), "
          "`Auth_Bypass.txt` / `Auth_Bypass2.txt` KEPT unknown origin (the audit's fuzzdb claim has no cited evidence; "
          "flagged). NEW denial found in review: `File Inclusion/Intruders/Traversal.txt` (header names its third-party "
          "author). Unknown-origin content stays under the PATT MIT assumption.", "",
          "## Per-source-file share of the ACCEPTED pool (cap NOT applied; flag threshold 25%)", ""]
    any_flag = False
    for scope, s in m["per_source_file_share"]["scopes"].items():
        for f in s["files"]:
            if f["above_25pct"]:
                any_flag = True
                L.append(f"- {scope}: `{f['source_file']}` {f['accepted']}/{s['accepted']} = {pct(f['share'])}")
    if not any_flag:
        L.append("- no file above 25%")
    L += ["", "## Comparison with the audit (R6, in-sample) and the spec", "",
          "| Category | Audit pool | Audit est. clean V+P [range] | Builder accepted |", "|---|---:|---|---:|"]
    for cat, a in m["audit_comparison"].items():
        L.append(f"| {cat} | {a['audit_pool_unique_canonical']} | {a['audit_est_clean_VP']} "
                 f"[{a['audit_est_range'][0]}, {a['audit_est_range'][1]}] | {a['builder_accepted']} |")
    uc = m["unique_canonical"]
    L += ["", "Unique canonical payloads after the spec's initial 20-file deny-list (spec 2.3 says): "
          + ", ".join(f"{k} {uc['after_spec_initial_denylist'].get(k, '-')} (spec {v})"
                      for k, v in uc["spec_2_3_after_denylist"].items()) + ".", "",
          "Not in the V5 pool by design: JWT, CSRF, HPP, request smuggling, insecure deserialization, LDAP, GraphQL, "
          "XXE (counted above as category-denied; HPP and smuggling hardcoded lists are not built).", "",
          "## Limitations", ""]
    L += [f"- {x}" for x in m["known_limitations"][:7]]
    return "\n".join(L) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--patt", default=DEFAULT_PATT, help="PayloadsAllTheThings clone at the pinned commit")
    ap.add_argument("--out", default=C.DEFAULT_OUT_DIR, help="output root (default datasets/v5_sources)")
    ap.add_argument("--denylist", default=DEFAULT_DENYLIST)
    ap.add_argument("--summary", default=None, help="write the markdown summary to this path")
    ap.add_argument("--check-determinism", action="store_true", help="rebuild into a temp dir and compare sha256")
    a = ap.parse_args(argv)
    patt = os.path.abspath(os.path.expanduser(a.patt))
    m = build(patt, os.path.abspath(a.out), a.denylist)
    det = verify_determinism(patt, os.path.abspath(a.out), a.denylist) if a.check_determinism else None
    if det and not det["identical"]:
        print(json.dumps(det, indent=2))
        raise SystemExit("FATAL: two runs differ")
    if a.summary:
        os.makedirs(os.path.dirname(os.path.abspath(a.summary)), exist_ok=True)
        with open(a.summary, "w", encoding="utf-8") as fh:
            fh.write(render_summary(m, det, load_denylist(a.denylist)[0]))
    print(json.dumps({"accepted": {c: t["accepted"] for c, t in m["counts"].items()},
                      "artifacts": m["artifacts"], "determinism": det and det["identical"]}, indent=1))


if __name__ == "__main__":
    main()
