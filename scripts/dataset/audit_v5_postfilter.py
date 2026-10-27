#!/usr/bin/env python3
"""firewall-IA — V5 attack-pool POST-FILTER audit (D58 acceptance condition, V5-DATA-SPEC-r3 §7).  Stdlib only.

The pre-filter audit (`audit_v5_attack_pool.py`, freeze-prep E) sampled the V4 extraction BEFORE the deny-list and
the structural filters. It is exploratory evidence only (D58) and does not satisfy the §7 gate. This tool audits the
stage-2 pool AFTER the filters and the APPROVED deny-list (`build_v5_attack_pool.py` output) and reuses the
pre-filter helpers (label classes, failure modes, Wilson interval, annotation validation, agreement).

§7 contract implemented here (gate APPROVED; every number PROPOSED, §11.2 — see PARAMS):
  * population  = ACCEPTED records of the stage-2 pool built with an APPROVED deny-list (refused otherwise);
                  category = stage-2 `dedup_scope` (traversal ∪ file inclusion = `path_file_access`, D49)
  * sample      = fresh, NEW seed (never a seed used before), stratified by source file within the category,
                  n_c = min(pool_c, 50); the whole pool when smaller
  * annotation  = two LLM annotators of DIFFERENT models, kept in separate files, never merged
  * adjudication= every non-trivial disagreement adjudicated by an identified coordinator or owner
  * human       = independent, BLIND human review of a stratified subsample of >= 20 per category (drawn at
                  sample time, before any LLM label exists); on that subsample human labels prevail
  * pass        = Wilson-95 upper(INCORRECT) <= 20% AND Wilson-95 upper(UNCERTAIN + INCORRECT) <= 35% AND human
                  INCORRECT share <= 20% (point); fail -> category excluded from V5 TRAIN (D58)
  * re-audit    = at most one, after a documented filter change, new seed, failed categories only

Nothing here labels a payload VERIFIED: a PASS makes a category eligible, the owner decides. LLM agreement is never
reported as human validation. Missing inputs are reported PENDING, never filled in.

Sub-commands (the round directory is <out-root>/round-<k>):
    plan            counts and per-file quotas of the current pool (no draw, no payloads); allowed on a PROPOSED list
    sample          draw the round sample + blind human subsample; refuses a PROPOSED deny-list
    annotation-packets  write the two blind LLM-annotator packets (same items, independent orders) + instructions
    agreement       LLM-vs-LLM agreement + discrepancy sheet (interim if an annotator is incomplete; resolves nothing)
    adjudication-workbook  CSV for the adjudicator (part 1 now; part 2 = items under blind human review, only after it)
    adjudication-import    validate the filled workbooks -> adjudication.jsonl
    adjudication-sheet  list the disagreements of the two annotators that need an identified adjudicator
    human-sheet     turn the empty human_labels.csv into a self-contained blind review sheet (context columns)
    human-batch     print one label-blind human batch (wire + logical form); creates human_labels.csv once
    report          per-category gate status (PASS / FAIL / PENDING_*) with Wilson bounds -> report.json + report.md

    python3 scripts/dataset/audit_v5_postfilter.py plan
    python3 scripts/dataset/audit_v5_postfilter.py sample --round 1 --seed <new seed>
    python3 scripts/dataset/audit_v5_postfilter.py report --round 1
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import sys
from collections import Counter, OrderedDict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import audit_v5_attack_pool as PRE  # noqa: E402  (pre-filter helpers, reused, not re-implemented)
import v5_pools_common as C  # noqa: E402
import v5_audit_evidence as AE  # noqa: E402

SCHEMA = "v5-postfilter-audit/v1"
DEFAULT_ATTACK_DIR = os.path.join(C.DEFAULT_OUT_DIR, "attack")
DEFAULT_OUT_ROOT = os.path.join(C.REPO_ROOT, "reports", "v5", "postfilter-audit")
FIXTURE = "FIXTURE"
REAL = "REAL"

# Every value is PROPOSED (V5-DATA-SPEC-r3 §7 / §11.2); ratified only in the dataset preregistration. Recorded in
# the round state so a later change is visible.
PARAMS = OrderedDict([
    ("n_min_per_category", 50),
    ("human_min_per_category", 20),
    ("max_wilson_upper_incorrect", 0.20),
    ("max_wilson_upper_uncertain_or_incorrect", 0.35),
    ("max_human_incorrect_share", 0.20),
    ("max_rounds", 2),                       # round 1 + at most one re-audit
    ("wilson_z", PRE.Z95),
])
PARAMS_STATUS = "PROPOSED (V5-DATA-SPEC-r3 §11.2; ratified in the dataset preregistration)"
# Seeds already consumed by the pre-filter audit; a post-filter round must use a new one (§7 "a new seed").
USED_SEEDS = frozenset({PRE.DEFAULT_SEED, PRE.HUMAN_REVIEW_SEED})
ADJUDICATOR_ROLES = ("coordinator", "owner")
HUMAN_FIELDS = ["batch", "sample_id", "reviewer", "label_class", "failure_mode", "better_category", "justification"]
SAMPLE_FIELDS = ("sample_id", "record_id", "category", "category_v4", "source_file", "line_index", "block_index",
                 "payload_wire", "payload_logical", "payload_wire_sha256")

# Gate statuses, in the order a category moves through them.
PENDING_ANNOTATION = "PENDING_ANNOTATION"
PENDING_ADJUDICATION = "PENDING_ADJUDICATION"
PENDING_HUMAN_REVIEW = "PENDING_HUMAN_REVIEW"
PASS = "PASS"
FAIL = "FAIL"


class AuditError(SystemExit):
    """Refusal: the audit cannot proceed on these inputs."""


def _h(*parts: str) -> str:
    return hashlib.sha256("\x00".join(parts).encode("utf-8")).hexdigest()


# ───────────────────────────── allocation (pure) ─────────────────────────────
def _largest_remainder(weights: "OrderedDict[str, int]", total: int) -> dict:
    """Hamilton apportionment of `total` over `weights`; ties broken by key (code-point order)."""
    s = sum(weights.values())
    if total <= 0 or s <= 0:
        return {k: 0 for k in weights}
    raw = {k: total * w / s for k, w in weights.items()}
    out = {k: int(v) for k, v in raw.items()}
    rest = total - sum(out.values())
    for k in sorted(weights, key=lambda k: (-(raw[k] - out[k]), k))[:rest]:
        out[k] += 1
    return out


def allocate_by_file(file_sizes: dict, n: int) -> dict:
    """Quota per source file for a stratum of size n. Whole pool when n >= pool. Otherwise every file gets 1 when
    there are no more files than n, and the remainder is apportioned to the files' remaining sizes (so no quota
    exceeds its file); with more files than n, plain proportional apportionment."""
    sizes = OrderedDict(sorted((f, int(c)) for f, c in file_sizes.items() if c > 0))
    pool = sum(sizes.values())
    if n >= pool:
        return dict(sizes)
    if len(sizes) <= n:
        extra = _largest_remainder(OrderedDict((f, c - 1) for f, c in sizes.items()), n - len(sizes))
        return {f: 1 + extra[f] for f in sizes}
    return _largest_remainder(sizes, n)


def _stratified_pick(rows: list, n: int, seed: str, category: str, salt: str = "") -> list:
    """Pick n rows stratified by source file; within a file rank by sha256(seed, salt, category, record_id)."""
    by_file: dict = {}
    for r in rows:
        by_file.setdefault(r["source_file"], []).append(r)
    quota = allocate_by_file({f: len(v) for f, v in by_file.items()}, n)
    out = []
    for f in sorted(by_file):
        ranked = sorted(by_file[f], key=lambda r: _h(seed, salt, category, r["record_id"]))
        out.extend(ranked[:quota[f]])
    return out


# ───────────────────────────── inputs and their checks ─────────────────────────────
def load_pool(attack_dir: str, denylist: str | None = None, require_approved: bool = True) -> dict:
    """Read the stage-2 pool, verify it against its manifest and the deny-list it was built with.

    Refuses: a pool whose sha256 differs from its manifest; a deny-list whose sha256 differs from the one hashed
    in the manifest; a PROPOSED deny-list when `require_approved`; any non-ACCEPTED or already-adjudicated record;
    a pool mixing synthetic fixture records and real ones."""
    import build_v5_attack_pool as B  # heavy import (PATT extraction code), only needed here
    C.assert_not_protected(attack_dir)
    pool_path = os.path.join(attack_dir, "attack_pool.jsonl")
    man_path = os.path.join(attack_dir, "manifest.json")
    C.assert_not_protected(man_path)
    C.assert_not_protected(pool_path)
    with open(man_path,'rb') as fh:man_raw=fh.read()
    man = json.loads(man_raw)
    art = {a["path"]: a for a in man["artifacts"]}.get("attack_pool.jsonl")
    with open(pool_path,'rb') as fh:pool_raw=fh.read()
    pool_sha = C.sha256_bytes(pool_raw)
    if not art or art["sha256"] != pool_sha:
        raise AuditError("REFUSED: attack_pool.jsonl does not match the sha256 recorded in its manifest")
    md = man["denylist"]
    dl_path = denylist or os.path.join(C.REPO_ROOT, md["path"])
    C.assert_not_protected(dl_path)
    doc, denied, dl_sha = B.load_denylist(dl_path)
    if dl_sha != md["sha256"]:
        raise AuditError(f"REFUSED: deny-list {dl_path} is not the one the pool was built with (sha256 differs)")
    if md.get("status") != doc["status"]:
        raise AuditError("REFUSED: manifest deny-list status differs from the deny-list file")
    if require_approved and doc["status"] != "APPROVED":
        raise AuditError("REFUSED: the post-filter audit consumes only a pool built with an APPROVED deny-list "
                         f"(current status {doc['status']}); use `plan` for counts")
    records = [json.loads(line) for line in pool_raw.split(b'\n') if line.strip()]
    if len(records) != art["records"]:
        raise AuditError("REFUSED: record count differs from the manifest")
    bad = [r.get("record_id") for r in records
           if r.get("status") != C.ACCEPTED or r.get("label_status") != C.LABEL_PENDING]
    if bad:
        raise AuditError(f"REFUSED: {len(bad)} records are not ACCEPTED + PENDING_ADJUDICATION: {bad[:5]}")
    ids = [r["record_id"] for r in records]
    if len(set(ids)) != len(ids):
        raise AuditError("REFUSED: duplicate record_id in the pool")
    synth = {bool(r.get("synthetic")) for r in records}
    if len(synth) > 1:
        raise AuditError("REFUSED: pool mixes synthetic fixture records and real records")
    return {"records": records, "mode": FIXTURE if synth == {True} else REAL,
            "pool": {"path": os.path.relpath(pool_path, C.REPO_ROOT), "sha256": pool_sha, "records": len(records)},
            "manifest_sha256": C.sha256_bytes(man_raw),
            "denylist": {"path": md["path"], "sha256": dl_sha, "status": doc["status"],
                         "approval": doc.get("approval"), "denied_files": len(denied)}}


def _by_category(records: list) -> "OrderedDict[str, list]":
    cats: dict = {}
    for r in records:
        cats.setdefault(r["dedup_scope"], []).append(r)
    return OrderedDict(sorted(cats.items()))


def plan(records: list, params=PARAMS) -> "OrderedDict[str, dict]":
    """Per category: pool size, sample size, per-file pool/quota, human subsample size. No draw."""
    out = OrderedDict()
    for cat, rows in _by_category(records).items():
        files = Counter(r["source_file"] for r in rows)
        n = min(len(rows), params["n_min_per_category"])
        q = allocate_by_file(files, n)
        out[cat] = {"pool": len(rows), "sample": n, "whole_pool": n == len(rows),
                    "human": min(n, params["human_min_per_category"]),
                    "by_file": {f: {"pool": files[f], "sample": q[f]} for f in sorted(files)}}
    return out


# ───────────────────────────── rounds ─────────────────────────────
def round_dir(out_root: str, k: int) -> str:
    return os.path.join(out_root, f"round-{k}")


def _read_json(path: str):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def _round_states(out_root: str) -> dict:
    out = {}
    if os.path.isdir(out_root):
        for name in sorted(os.listdir(out_root)):
            p = os.path.join(out_root, name, "audit_state.json")
            if name.startswith("round-") and os.path.isfile(p):
                out[int(name.split("-", 1)[1])] = _read_json(p)
    return out


def check_round(out_root: str, k: int, seed: str, pool_sha: str, filter_change_doc: str | None,
                params=PARAMS, *, prior_r4_binding=None, categories=None) -> list | None:
    """Enforce §7: a new seed; round 1 first; at most one re-audit, only after a documented filter change, on a
    changed pool and for the categories that FAILED round 1. Returns the categories to audit (None = all)."""
    if not seed or not seed.strip():
        raise AuditError("REFUSED: an explicit, new --seed is required")
    if not 1 <= k <= params["max_rounds"]:
        raise AuditError(f"REFUSED: round {k}; at most {params['max_rounds'] - 1} re-audit is allowed (§7)")
    if os.path.exists(round_dir(out_root, k)):
        raise AuditError(f"REFUSED: {round_dir(out_root, k)} exists; a round is never redrawn")
    states = _round_states(out_root)
    used = set(USED_SEEDS) | {s["seed"] for s in states.values()} | {s["human_seed"] for s in states.values()}
    if seed in used or human_seed(seed) in used:
        raise AuditError("REFUSED: seed already used by an earlier audit; §7 requires a new seed")
    if k == 1:
        if prior_r4_binding is not None or categories is not None:
            raise AuditError('REFUSED: continuation evidence/categories require round 2')
        return None
    prev = states.get(k - 1)
    rep_path = os.path.join(round_dir(out_root, k - 1), "report.json")
    if prev is None or not os.path.isfile(rep_path):
        raise AuditError(f"REFUSED: round {k} needs round {k - 1} sampled and reported")
    if filter_change_doc:
        C.assert_not_protected(filter_change_doc)
    if not (filter_change_doc and os.path.isfile(filter_change_doc) and os.path.getsize(filter_change_doc) > 0):
        raise AuditError("REFUSED: a re-audit needs --filter-change-doc documenting the filter change")
    if prev["pool"]["sha256"] == pool_sha:
        raise AuditError("REFUSED: the pool is unchanged since the previous round; a re-audit follows a filter change")
    if prior_r4_binding is not None:
        try:
            evidence = AE.verify(prior_r4_binding)
        except (OSError,ValueError,TypeError) as exc:
            raise AuditError(f'REFUSED: invalid prior r4 evidence: {exc}') from exc
        state_path = os.path.join(round_dir(out_root,k-1),'audit_state.json')
        if (evidence['sha256']['state'] != C.sha256_file(state_path)
                or evidence['pool_sha256'] != prev['pool']['sha256']):
            raise AuditError('REFUSED: r4 evidence is not bound to this round history')
        if (not isinstance(categories,list) or not categories
                or any(not isinstance(c,str) or not c for c in categories)
                or len(set(categories)) != len(categories)):
            raise AuditError('REFUSED: explicit nonempty unique continuation categories required')
        allowed = {'FAIL','INSUFFICIENT_EVIDENCE'}
        if any(evidence['category_outcomes'].get(c) not in allowed for c in categories):
            raise AuditError('REFUSED: continuation categories must have FAIL/INSUFFICIENT_EVIDENCE in authoritative r4')
        return sorted(categories)
    if categories is not None:
        raise AuditError('REFUSED: explicit category selection needs bound r4 evidence')
    failed = sorted(c for c, v in _read_json(rep_path)["categories"].items() if v["status"] == FAIL)
    if not failed:
        raise AuditError("REFUSED: no category FAILED the previous round; nothing to re-audit")
    return failed


def human_seed(seed: str) -> str:
    return seed + "/human"


def draw(records: list, seed: str, k: int, categories: list | None = None, params=PARAMS) -> tuple:
    """-> (sample rows, human subsample rows). Deterministic and independent of input order."""
    cats = _by_category(records)
    if categories is not None:
        missing = sorted(set(categories) - set(cats))
        if missing:
            raise AuditError(f"REFUSED: categories not in the pool: {missing}")
        cats = OrderedDict((c, cats[c]) for c in categories)
    picked = []
    for cat, rows in cats.items():
        picked.extend(_stratified_pick(rows, min(len(rows), params["n_min_per_category"]), seed, cat))
    # interleave categories and files so nothing in the order hints at the stratum
    picked.sort(key=lambda r: _h(seed, "order", r["record_id"]))
    sample = []
    for i, r in enumerate(picked, start=1):
        row = OrderedDict((f, r.get(f)) for f in SAMPLE_FIELDS)
        row["sample_id"] = f"PF{k}-{i:04d}"
        row["category"] = r["dedup_scope"]
        row["payload_wire_sha256"] = C.sha256_bytes(r["payload_wire"].encode("utf-8"))
        sample.append(row)
    hs = human_seed(seed)
    human = []
    for cat in cats:
        rows = [s for s in sample if s["category"] == cat]
        human.extend(_stratified_pick(rows, min(len(rows), params["human_min_per_category"]), hs, cat))
    human.sort(key=lambda r: _h(hs, "order", r["sample_id"]))
    return sample, human


def write_round(out_root: str, k: int, seed: str, pool: dict, sample: list, human: list,
                categories: list | None, filter_change_doc: str | None, params=PARAMS, *, prior_r4_binding=None) -> str:
    if prior_r4_binding is not None and len(sample)>200:
        raise AuditError('REFUSED: this r4 continuation requires an explicitly fixed R3 population; frame exceeds 200')
    d = round_dir(out_root, k)
    os.makedirs(os.path.join(d, "human_review"))          # fails if it exists: a round is never redrawn
    sample_info = C.write_jsonl(os.path.join(d, "sample.jsonl"), sample, key=lambda r: r["sample_id"])
    hpath = os.path.join(d, "human_review", "human_review_sample.csv")
    with open(hpath, "w", encoding="utf-8", newline="") as fh:
        w = csv.writer(fh, quoting=csv.QUOTE_ALL, lineterminator="\n")
        w.writerow(["sample_id", "category", "source_file", "payload", "payload_logical"])
        for r in human:
            w.writerow([r["sample_id"], r["category"], r["source_file"], r["payload_wire"], r["payload_logical"]])
    state = OrderedDict([
        ("schema", SCHEMA), ("mode", pool["mode"]), ("round", k), ("seed", seed), ("human_seed", human_seed(seed)),
        ("categories_audited", categories or sorted({s["category"] for s in sample})),
        ("pool", pool["pool"]), ("pool_manifest_sha256", pool["manifest_sha256"]), ("denylist", pool["denylist"]),
        ("params", dict(params)), ("params_status", PARAMS_STATUS),
        ("filter_change_doc", None if filter_change_doc is None else
         {"path": os.path.relpath(filter_change_doc, C.REPO_ROOT), "sha256": C.sha256_file(filter_change_doc)}),
        ("sample", {"path": "sample.jsonl", "sha256": sample_info["sha256"], "rows": len(sample)}),
        ("human_sample", {"path": "human_review/human_review_sample.csv", "sha256": C.sha256_file(hpath),
                          "rows": len(human)}),
        ("per_category", {c: {"sample": sum(1 for s in sample if s["category"] == c),
                              "human": sum(1 for h in human if h["category"] == c),
                              "by_file": dict(sorted(Counter(s["source_file"] for s in sample
                                                             if s["category"] == c).items()))}
                          for c in sorted({s["category"] for s in sample})}),
        ("code", C.code_fingerprint([os.path.abspath(__file__), PRE.__file__])),
        ("method", "stratified by source file within category; within a file rank by sha256(seed NUL '' NUL "
                   "category NUL record_id); human subsample drawn from the sample with human_seed before any "
                   "annotation exists"),
    ])
    if prior_r4_binding is not None:
        state['review_method'] = 'D67_R4_AI_ONLY_CONTINUATION'
        state['r3_preselected_sample'] = {'path':'sample.jsonl','sha256':sample_info['sha256'],
            'rows':len(sample),'rule':'entire continuation frame (at most 200), fixed before annotations'}
        prereg = os.path.join(C.REPO_ROOT,'reports','v5','postfilter-audit','preregistration','v5-postfilter-prereg-r4.json')
        state['r4_preregistration'] = {'path':os.path.relpath(prereg,C.REPO_ROOT),'sha256':C.sha256_file(prereg)}
        state['human_validation_performed'] = False
        state['legacy_human_sample_is_not_r3_selection'] = True
        state['prior_r4_evidence'] = prior_r4_binding
        state['continuation_scope'] = 'documented filter correction; no category results inherited'
    C.write_json(os.path.join(d, "audit_state.json"), state)
    return d


# ───────────────────────────── annotations, adjudication, human labels ─────────────────────────────
def _annotators(d: str) -> dict | None:
    p = os.path.join(d, "annotators.json")
    if not os.path.isfile(p):
        return None
    meta = _read_json(p)
    for a in ("a1", "a2"):
        if not str((meta.get(a) or {}).get("model") or "").strip():
            raise AuditError(f"REFUSED: annotators.json needs {a}.model")
    if meta["a1"]["model"].strip().lower() == meta["a2"]["model"].strip().lower():
        raise AuditError("REFUSED: annotator 1 and annotator 2 must be different models (D58)")
    return meta


def _annotation_labels(d: str, name: str, sample: list) -> tuple:
    """-> (labels dict or None, issues). A missing or invalid file is PENDING, never repaired."""
    p = os.path.join(d, f"annotations_{name}.jsonl")
    if not os.path.isfile(p):
        return None, [f"annotations_{name}.jsonl missing"]
    rows = C.read_jsonl(p)
    errs = PRE.validate_annotations(sample, rows)
    if errs:
        return None, [f"annotations_{name}.jsonl: {e}" for e in errs]
    return {r["sample_id"]: r for r in rows}, []


VP_RULE_ID = "vp_split_to_probably_correct/v1"


def vp_rule_approved(d: str) -> bool:
    """The V/P -> PROBABLY_CORRECT rule is PROPOSED; it applies only when adjudication_rules.json records an owner
    approval {"vp_split_to_probably_correct": {"approved": true, "approved_by": ..., "date": ...}}."""
    p = os.path.join(d, "adjudication_rules.json")
    if not os.path.isfile(p):
        return False
    r = (_read_json(p).get("vp_split_to_probably_correct") or {})
    if r.get("approved") is True and not (str(r.get("approved_by") or "").strip() and str(r.get("date") or "").strip()):
        raise AuditError("REFUSED: an approved V/P rule needs approved_by and date")
    return r.get("approved") is True


def adjudicate(sample: list, a1: dict, a2: dict, adjudications: list, vp_rule: bool = False) -> tuple:
    """-> (final {sid: (label, basis, adjudicator)}, pending sids). Agreement keeps the label. A VERIFIABLE /
    PROBABLY_CORRECT split resolves to the conservative PROBABLY_CORRECT only when `vp_rule` (owner-approved; it
    changes neither gate rate); otherwise it needs an adjudication row like every other disagreement. A row for an
    item the annotators agree on is refused: agreed labels are not overridden here."""
    adj = {}
    for r in adjudications:
        sid = r.get("sample_id")
        if sid in adj:
            raise AuditError(f"REFUSED: duplicate adjudication for {sid}")
        if r.get("label_class") not in PRE.LABEL_CLASSES:
            raise AuditError(f"REFUSED: adjudication {sid}: bad label_class {r.get('label_class')!r}")
        if not str(r.get("adjudicator") or "").strip() or r.get("adjudicator_role") not in ADJUDICATOR_ROLES:
            raise AuditError(f"REFUSED: adjudication {sid} needs an identified adjudicator and a role in "
                             f"{ADJUDICATOR_ROLES}")
        if not str(r.get("rationale") or "").strip():
            raise AuditError(f"REFUSED: adjudication {sid} needs a rationale")
        adj[sid] = r
    final, pending = {}, []
    for s in sample:
        sid = s["sample_id"]
        x, y = a1[sid]["label_class"], a2[sid]["label_class"]
        if x == y:
            if sid in adj:
                raise AuditError(f"REFUSED: adjudication row for {sid}, where the annotators agree")
            final[sid] = (x, "agreement", None)
        elif vp_rule and {x, y} == set(PRE.USABLE) and sid not in adj:
            final[sid] = ("PROBABLY_CORRECT", "rule:conservative_v_p", None)
        elif sid in adj:
            final[sid] = (adj[sid]["label_class"], "adjudicated",
                          f"{adj[sid]['adjudicator']} ({adj[sid]['adjudicator_role']})")
        else:
            pending.append(sid)
    unknown = sorted(set(adj) - {s["sample_id"] for s in sample})
    if unknown:
        raise AuditError(f"REFUSED: adjudication rows for unknown sample ids {unknown[:5]}")
    return final, pending


def _human_labels(d: str, human_ids: list) -> tuple:
    """-> ({sid: label} for COMPLETE, valid rows, issues). Rows need a reviewer identity; an empty label is
    'not reviewed yet' (PENDING), never a default."""
    p = os.path.join(d, "human_review", "human_labels.csv")
    if not os.path.isfile(p):
        return {}, ["human_labels.csv missing"]
    with open(p, encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    errs = [e for e in PRE.validate_human_labels(human_ids, rows) if not e.endswith("not reviewed yet")]
    if errs:
        raise AuditError("REFUSED: invalid human_labels.csv:\n  " + "\n  ".join(errs[:20]))
    out, issues = {}, []
    for r in rows:
        lc = (r.get("label_class") or "").strip()
        if not lc:
            issues.append(f"{r['sample_id']}: not reviewed yet")
            continue
        if not (r.get("reviewer") or "").strip():
            raise AuditError(f"REFUSED: human label {r['sample_id']} has no reviewer identity")
        out[r["sample_id"]] = lc
    return out, issues


# ───────────────────────────── gate ─────────────────────────────
def category_gate(sample_cat: list, human_cat: list, a1: dict | None, a2: dict | None, final: dict | None,
                  pending_adj: list, human: dict, params=PARAMS) -> dict:
    """Status and numbers of one category. Human labels prevail on the human subsample (§7)."""
    sids = [s["sample_id"] for s in sample_cat]
    hids = [h["sample_id"] for h in human_cat]
    res = OrderedDict([("n_sample", len(sids)), ("n_human_required", len(hids))])
    if a1 is None or a2 is None:
        res["status"] = PENDING_ANNOTATION
        return res
    agree = sum(1 for i in sids if a1[i]["label_class"] == a2[i]["label_class"])
    res["resolved_by_vp_rule"] = sum(1 for i in sids if final and i in final and final[i][1] == "rule:conservative_v_p")
    res["llm_agreement_not_human_validation"] = {
        "exact": agree, "n": len(sids),
        "incorrect_vs_not": PRE.binary_agreement([a1[i]["label_class"] for i in sids],
                                                 [a2[i]["label_class"] for i in sids],
                                                 lambda c: c == "INCORRECT")}
    pend = [i for i in sids if i in set(pending_adj)]
    if pend:
        res["status"] = PENDING_ADJUDICATION
        res["pending_adjudication"] = pend
        return res
    labels = {i: final[i][0] for i in sids}
    done_h = {i: human[i] for i in hids if i in human}
    res["n_human_reviewed"] = len(done_h)
    for i, lab in done_h.items():
        labels[i] = lab                                           # human labels prevail on the subsample
    counts = Counter(labels.values())
    n, z = len(sids), params["wilson_z"]
    inc, bad = counts["INCORRECT"], counts["INCORRECT"] + counts["UNCERTAIN"]
    res["counts"] = {c: counts[c] for c in PRE.LABEL_CLASSES}
    res["labels_basis"] = "LLM-adjudicated, human labels substituted on the reviewed human subsample"
    res["incorrect"] = {"k": inc, "n": n, "wilson95": list(PRE.wilson_interval(inc, n, z))}
    res["uncertain_or_incorrect"] = {"k": bad, "n": n, "wilson95": list(PRE.wilson_interval(bad, n, z))}
    c1 = res["incorrect"]["wilson95"][1] <= params["max_wilson_upper_incorrect"]
    c2 = res["uncertain_or_incorrect"]["wilson95"][1] <= params["max_wilson_upper_uncertain_or_incorrect"]
    res["criterion_1_incorrect_upper"] = c1
    res["criterion_2_uncertain_or_incorrect_upper"] = c2
    if len(done_h) < len(hids):
        res["criterion_3_human_incorrect_share"] = None
        res["status"] = PENDING_HUMAN_REVIEW
        res["provisional"] = "criteria 1-2 are provisional until the human subsample is complete"
        return res
    h_inc = sum(1 for v in done_h.values() if v == "INCORRECT")
    res["human_incorrect"] = {"k": h_inc, "n": len(hids), "share": (h_inc / len(hids)) if hids else None}
    c3 = bool(hids) and h_inc / len(hids) <= params["max_human_incorrect_share"]
    res["criterion_3_human_incorrect_share"] = c3
    res["status"] = PASS if (c1 and c2 and c3) else FAIL
    return res


def report(out_root: str, k: int, params=None) -> dict:
    d = round_dir(out_root, k)
    state = _read_json(os.path.join(d, "audit_state.json"))
    if state.get("review_method") == "D67_R4_AI_ONLY_CONTINUATION" or state.get("prior_r4_evidence"):
        raise AuditError("REFUSED: r4 continuation requires adjudicate_v5_r4_continuation.py; legacy human-review report is inapplicable")
    params = params or state["params"]
    sample = C.read_jsonl(os.path.join(d, "sample.jsonl"))
    if C.sha256_file(os.path.join(d, "sample.jsonl")) != state["sample"]["sha256"]:
        raise AuditError("REFUSED: sample.jsonl changed after it was drawn")
    hpath = os.path.join(d, "human_review", "human_review_sample.csv")
    if C.sha256_file(hpath) != state["human_sample"]["sha256"]:
        raise AuditError("REFUSED: human_review_sample.csv changed after it was drawn")
    with open(hpath, encoding="utf-8", newline="") as fh:
        hrows = list(csv.DictReader(fh))
    issues = []
    meta = _annotators(d)
    if meta is None:
        issues.append("annotators.json missing")
    a1, e1 = _annotation_labels(d, "a1", sample)
    a2, e2 = _annotation_labels(d, "a2", sample)
    issues += e1 + e2
    if meta is None:
        a1 = a2 = None
    final, pending = None, []
    if a1 is not None and a2 is not None:
        p = os.path.join(d, "adjudication.jsonl")
        final, pending = adjudicate(sample, a1, a2, C.read_jsonl(p) if os.path.isfile(p) else [], vp_rule_approved(d))
    human, h_issues = _human_labels(d, [r["sample_id"] for r in hrows])
    issues += h_issues
    cats = OrderedDict()
    for cat in state["categories_audited"]:
        cats[cat] = category_gate([s for s in sample if s["category"] == cat],
                                  [h for h in hrows if h["category"] == cat], a1, a2, final, pending, human, params)
    fixture = state["mode"] == FIXTURE
    out = OrderedDict([
        ("schema", SCHEMA), ("mode", state["mode"]), ("round", k),
        ("real_gate_run", not fixture and state["denylist"]["status"] == "APPROVED"),
        ("note", ("FIXTURE: synthetic records; NOT a §7 gate result." if fixture else
                  "§7 post-filter audit. LLM agreement is not human validation. PASS makes a category eligible; it "
                  "labels no payload VERIFIED (owner decision). Thresholds PROPOSED (§11.2).")),
        ("annotators", meta), ("params", params), ("params_status", PARAMS_STATUS),
        ("pool", state["pool"]), ("denylist", state["denylist"]), ("seed", state["seed"]),
        ("categories", cats),
        ("summary", dict(sorted(Counter(v["status"] for v in cats.values()).items()))),
        ("open_issues", issues[:200]), ("open_issue_count", len(issues)),
    ])
    C.write_json(os.path.join(d, "report.json"), out)
    with open(os.path.join(d, "report.md"), "w", encoding="utf-8") as fh:
        fh.write(render_report(out))
    return out


def render_report(rep: dict) -> str:
    def pct(x):
        return "—" if x is None else f"{100 * x:.1f}%"
    L = [f"# V5 post-filter audit — round {rep['round']} ({rep['mode']})", "",
         f"_Generated by `scripts/dataset/audit_v5_postfilter.py report`. {rep['note']}_", "",
         f"Pool `{rep['pool']['sha256'][:12]}…` ({rep['pool']['records']} records); deny-list "
         f"`{rep['denylist']['sha256'][:12]}…` {rep['denylist']['status']}; seed `{rep['seed']}`.", "",
         "| Category | n | Status | INCORRECT k | Wilson95 upper | U+I k | Wilson95 upper | Human INCORRECT | C1 | C2 | C3 |",
         "|---|---:|---|---:|---:|---:|---:|---|---|---|---|"]
    for cat, v in rep["categories"].items():
        inc, bad, h = v.get("incorrect"), v.get("uncertain_or_incorrect"), v.get("human_incorrect")
        human = (f"{h['k']}/{h['n']}" if h else
                 f"{v.get('n_human_reviewed', 0)}/{v['n_human_required']} reviewed")
        L.append(f"| {cat} | {v['n_sample']} | {v['status']} | {inc['k'] if inc else '—'} | "
                 f"{pct(inc['wilson95'][1]) if inc else '—'} | {bad['k'] if bad else '—'} | "
                 f"{pct(bad['wilson95'][1]) if bad else '—'} | "
                 f"{human} | "
                 f"{v.get('criterion_1_incorrect_upper', '—')} | {v.get('criterion_2_uncertain_or_incorrect_upper', '—')} | "
                 f"{v.get('criterion_3_human_incorrect_share', '—')} |")
    L += ["", f"Open issues: {rep['open_issue_count']} (first ones in `report.json`)."]
    return "\n".join(L) + "\n"


# ───────────────────────────── CLI ─────────────────────────────
def cmd_plan(a) -> int:
    pool = load_pool(a.attack_dir, a.denylist, require_approved=False)
    p = plan(pool["records"])
    print(json.dumps({"mode": pool["mode"], "denylist": pool["denylist"], "pool": pool["pool"],
                      "params": dict(PARAMS), "params_status": PARAMS_STATUS,
                      "totals": {"sample": sum(v["sample"] for v in p.values()),
                                 "human": sum(v["human"] for v in p.values())},
                      "categories": p}, indent=2, ensure_ascii=False))
    return 0


def cmd_sample(a) -> int:
    pool = load_pool(a.attack_dir, a.denylist, require_approved=True)
    binding = None
    if a.prior_r4_evidence:
        C.assert_not_protected(a.prior_r4_evidence)
        doc = _read_json(a.prior_r4_evidence)
        binding = doc.get('binding',doc)
    cats = check_round(a.out_root,a.round,a.seed,pool['pool']['sha256'],a.filter_change_doc,
                       prior_r4_binding=binding,categories=a.category)
    sample, human = draw(pool['records'],a.seed,a.round,cats)
    d = write_round(a.out_root,a.round,a.seed,pool,sample,human,cats,a.filter_change_doc,
                    prior_r4_binding=binding)
    print(json.dumps({'round_dir':os.path.relpath(d,C.REPO_ROOT),'mode':pool['mode'],
                      'sample':len(sample),'human':len(human)},indent=2))
    return 0


ANNOTATOR_README = """# Post-filter audit round {k} — LLM annotator {who} ({other_note})

You are annotator **{who}**. Annotate every item of `packet.jsonl` in this folder ({n} items) from the payload text alone.
Never execute a payload. Do **not** read: `../annotation_{other}/`, `../../annotations_{other}.jsonl`, `../../human_review/`,
`../../adjudication*.jsonl`, `../../report.*`, or the pre-filter audit labels in `reports/v5/freeze-prep/E_attack_pool_audit/`.

**Classes** (the pre-filter audit definitions, unchanged):

| Class | Definition |
|---|---|
| VERIFIABLE | A concrete, syntactically recognisable payload of the **assigned** category that would be malicious in a typical injection slot of that category; the mechanism can be pointed at |
| PROBABLY_CORRECT | Plausibly a payload of that category but needs a specific context or sink (legacy parser, particular engine, decoding step), is a bare command/value, or is a fragment of a larger payload |
| UNCERTAIN | Cannot tell from text alone whether it is a working payload (e.g. malformed encodings, inert templated mutations). Not necessarily junk |
| INCORRECT | Not an attack payload (documentation prose, tool output, setup commands, placeholders, markdown/code residue, reference URLs, PoC source code) **or** a real payload of a different category (`better_category` recorded) |

Judge the payload **as extracted** (`payload_wire`; `payload_logical` is the decoded view). Residue such as a trailing
documentation label, a shell prompt or a placeholder makes it INCORRECT even if a real payload is inside. When unsure,
use UNCERTAIN. `failure_mode` is required for INCORRECT, one of: {modes}.

**Output.** Write `{out}` (one JSON object per line, every `sample_id` exactly once):

    {{"sample_id": "PF{k}-0001", "label_class": "VERIFIABLE", "failure_mode": null, "better_category": null, "note": "short reason"}}

The coordinator records your model identifier in `../../annotators.json` (`{who}.model`); annotator 1 and annotator 2 must be
different models (D58). LLM agreement is never human validation.
"""


def annotation_packets(d: str, sample: list) -> dict:
    """Write annotation_a1/ and annotation_a2/: the same items (no label, no human-subsample marker) in two independent
    deterministic orders, plus instructions. Refuses to overwrite. Returns {who: sha256 of packet}."""
    state = _read_json(os.path.join(d, "audit_state.json"))
    out = {}
    for who, other in (("a1", "a2"), ("a2", "a1")):
        sub = os.path.join(d, f"annotation_{who}")
        os.makedirs(sub)                                  # fails if it exists: packets are never rewritten
        rows = sorted(({f: s[f] for f in ("sample_id", "category", "source_file", "payload_wire", "payload_logical")}
                       for s in sample), key=lambda r: _h(state["seed"], "packet", who, r["sample_id"]))
        data = "".join(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n" for r in rows).encode("utf-8")
        with open(os.path.join(sub, "packet.jsonl"), "wb") as fh:
            fh.write(data)
        with open(os.path.join(sub, "README.md"), "w", encoding="utf-8") as fh:
            fh.write(ANNOTATOR_README.format(k=state["round"], who=who, other=other, n=len(rows),
                                             other_note=f"blind to annotator {other}",
                                             modes=", ".join(PRE.FAILURE_MODES), out=f"../annotations_{who}.jsonl"))
        out[who] = C.sha256_bytes(data)
    C.write_json(os.path.join(d, "annotation_packets.json"),
                 {"round": state["round"], "sample_sha256": state["sample"]["sha256"], "packets_sha256": out,
                  "order": "sha256(seed NUL 'packet' NUL annotator NUL sample_id)"})
    return out


def cmd_annotation_packets(a) -> int:
    d = round_dir(a.out_root, a.round)
    sample = C.read_jsonl(os.path.join(d, "sample.jsonl"))
    if C.sha256_file(os.path.join(d, "sample.jsonl")) != _read_json(os.path.join(d, "audit_state.json"))["sample"]["sha256"]:
        raise AuditError("REFUSED: sample.jsonl changed after it was drawn")
    print(json.dumps(annotation_packets(d, sample), indent=2))
    return 0


def agreement(d: str) -> dict:
    """LLM-vs-LLM agreement and the discrepancy sheet. Uses annotations_<who>.jsonl, or the .partial.jsonl when an
    annotator is incomplete (then the result is INTERIM). Every disagreement is listed; nothing is resolved here:
    V/P splits are only flagged as candidates for the PROPOSED conservative rule. Not human validation."""
    sample = C.read_jsonl(os.path.join(d, "sample.jsonl"))
    by = {s["sample_id"]: s for s in sample}
    ann, files = {}, {}
    for who in ("a1", "a2"):
        for name in (f"annotations_{who}.jsonl", f"annotations_{who}.partial.jsonl"):
            p = os.path.join(d, name)
            if os.path.isfile(p):
                ann[who] = {r["sample_id"]: r for r in C.read_jsonl(p)}
                files[who] = {"file": name, "sha256": C.sha256_file(p), "rows": len(ann[who])}
                break
        else:
            raise AuditError(f"REFUSED: no annotations for {who}")
        bad = sorted(set(ann[who]) - set(by))
        if bad:
            raise AuditError(f"REFUSED: {who} annotates unknown sample ids {bad[:5]}")
    meta = _annotators(d)
    paired = sorted(set(ann["a1"]) & set(ann["a2"]))
    missing = {w: sorted(set(by) - set(ann[w])) for w in ("a1", "a2")}
    cats = sorted({s["category"] for s in sample})
    dist = {w: {c: dict(Counter(ann[w][i]["label_class"] for i in ann[w] if by[i]["category"] == c)) for c in cats}
            for w in ("a1", "a2")}
    def agree_block(ids):
        x = [ann["a1"][i]["label_class"] for i in ids]
        y = [ann["a2"][i]["label_class"] for i in ids]
        return {"n": len(ids), "exact": sum(1 for p, q in zip(x, y) if p == q),
                "usable_vs_not": PRE.binary_agreement(x, y, lambda c: c in PRE.USABLE) if ids else None,
                "incorrect_vs_not": PRE.binary_agreement(x, y, lambda c: c == "INCORRECT") if ids else None}
    per_cat = {c: agree_block([i for i in paired if by[i]["category"] == c]) for c in cats}
    sheet = []
    for i in paired:
        x, y = ann["a1"][i], ann["a2"][i]
        if x["label_class"] == y["label_class"]:
            continue
        vp = {x["label_class"], y["label_class"]} == set(PRE.USABLE)
        sheet.append({"sample_id": i, "category": by[i]["category"], "source_file": by[i]["source_file"],
                      "payload_wire": by[i]["payload_wire"],
                      "a1": {k: x.get(k) for k in ("label_class", "failure_mode", "better_category", "note")},
                      "a2": {k: y.get(k) for k in ("label_class", "failure_mode", "better_category", "note")},
                      "kind": "vp_split_rule_candidate" if vp else "needs_adjudication",
                      "affects_gate": not vp})
    complete = not missing["a1"] and not missing["a2"]
    return {"schema": SCHEMA, "status": "COMPLETE" if complete else "INTERIM (an annotator is incomplete)",
            "note": "LLM-LLM agreement; NOT human validation. Nothing adjudicated here. V/P splits do not change "
                    "either gate rate; resolving them to PROBABLY_CORRECT is a PROPOSED rule needing owner approval.",
            "annotators": {w: {"model": (meta or {}).get(w, {}).get("model"), **files[w]} for w in ("a1", "a2")},
            "paired": len(paired), "missing": {w: missing[w] for w in missing},
            "label_distribution_by_category": dist, "agreement_overall": agree_block(paired),
            "agreement_by_category": per_cat,
            "disagreements": {"total": len(sheet),
                              "needs_adjudication": sum(1 for r in sheet if r["kind"] == "needs_adjudication"),
                              "vp_split_rule_candidate": sum(1 for r in sheet if r["kind"] != "needs_adjudication"),
                              "by_category": dict(sorted(Counter(r["category"] for r in sheet
                                                                 if r["kind"] == "needs_adjudication").items()))},
            "_sheet": sheet}


def cmd_agreement(a) -> int:
    d = round_dir(a.out_root, a.round)
    res = agreement(d)
    sheet = res.pop("_sheet")
    C.write_jsonl(os.path.join(d, "discrepancy_sheet.jsonl"), sheet, key=lambda r: r["sample_id"])
    res["discrepancy_sheet"] = {"path": "discrepancy_sheet.jsonl",
                                "sha256": C.sha256_file(os.path.join(d, "discrepancy_sheet.jsonl"))}
    C.write_json(os.path.join(d, "agreement_report.json"), res)
    print(json.dumps({k: res[k] for k in ("status", "paired", "agreement_overall", "disagreements")}, indent=1))
    return 0


def rule_trace(sample: list, a1: dict, a2: dict, final: dict, approval: dict) -> list:
    """One row per item resolved by the approved V/P rule: both original annotations kept verbatim, the rule id,
    the resolved label and the fact that the decision was automatic. Nothing here is VERIFIED."""
    by = {s["sample_id"]: s for s in sample}
    return [{"sample_id": i, "category": by[i]["category"], "source_file": by[i]["source_file"],
             "a1": {k: a1[i].get(k) for k in ("label_class", "failure_mode", "better_category", "note")},
             "a2": {k: a2[i].get(k) for k in ("label_class", "failure_mode", "better_category", "note")},
             "resolved_label": final[i][0], "rule": VP_RULE_ID, "decision": "automatic (owner-approved rule)",
             "approval": approval}
            for i in sorted(final) if final[i][1] == "rule:conservative_v_p"]


WORKBOOK_FIELDS = ["sample_id", "category", "source_file", "payload_wire", "payload_logical",
                   "a1_model", "a1_label", "a1_failure_mode", "a1_better_category", "a1_note",
                   "a2_model", "a2_label", "a2_failure_mode", "a2_better_category", "a2_note",
                   "label_class", "failure_mode", "better_category", "adjudicator", "adjudicator_role", "rationale"]
FILL_FIELDS = ("label_class", "failure_mode", "better_category", "adjudicator", "adjudicator_role", "rationale")


def workbook_path(d: str, part: int) -> str:
    return os.path.join(d, "adjudication", f"workbook_part{part}.csv")


def adjudication_workbook(d: str, part: int) -> str:
    """Part 1: pending disagreements NOT in the blind human subsample (can be adjudicated now). Part 2: pending
    disagreements that ARE in the human subsample; refused until the blind human review is complete, so the reviewer
    never sees LLM labels of items still under blind review. Never overwritten."""
    pend = C.read_jsonl(os.path.join(d, "adjudication_pending.jsonl"))
    with open(os.path.join(d, "human_review", "human_review_sample.csv"), encoding="utf-8", newline="") as fh:
        hrows = list(csv.DictReader(fh))
    hids = {r["sample_id"] for r in hrows}
    if part == 2:
        done, issues = _human_labels(d, [r["sample_id"] for r in hrows])
        if issues or len(done) < len(hrows):
            raise AuditError(f"REFUSED: part 2 holds items under blind human review; finish the human review first "
                             f"({len(done)}/{len(hrows)} labelled)")
    rows = [r for r in pend if (r["sample_id"] in hids) == (part == 2)]
    by = {s["sample_id"]: s for s in C.read_jsonl(os.path.join(d, "sample.jsonl"))}
    meta = _annotators(d) or {}
    out = workbook_path(d, part)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    if os.path.exists(out):
        raise AuditError(f"REFUSED: {out} exists; the adjudicator's workbook is never overwritten")
    with open(out, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=WORKBOOK_FIELDS, quoting=csv.QUOTE_ALL, lineterminator="\n")
        w.writeheader()
        for r in sorted(rows, key=lambda r: (r["category"], r["sample_id"])):
            row = {"sample_id": r["sample_id"], "category": r["category"], "source_file": r["source_file"],
                   "payload_wire": r["payload_wire"], "payload_logical": by[r["sample_id"]]["payload_logical"]}
            for who in ("a1", "a2"):
                row[f"{who}_model"] = (meta.get(who) or {}).get("model")
                for k in ("label", "failure_mode", "better_category", "note"):
                    row[f"{who}_{k}"] = r[who].get("label_class" if k == "label" else k) or ""
            w.writerow(row)
    return out


def adjudication_import(d: str) -> dict:
    """Workbooks -> adjudication.jsonl (regenerated from the workbooks, which are the record). Empty label_class =
    not adjudicated yet (stays PENDING). Every filled row needs a valid label, a failure_mode for INCORRECT, an
    adjudicator, a role and a rationale; an unknown or already-agreed sample id is refused by `adjudicate`."""
    rows, files = [], {}
    for part in (1, 2):
        p = workbook_path(d, part)
        if not os.path.isfile(p):
            continue
        files[f"part{part}"] = C.sha256_file(p)
        with open(p, encoding="utf-8", newline="") as fh:
            for r in csv.DictReader(fh):
                if not (r.get("label_class") or "").strip():
                    continue
                lc, fm = r["label_class"].strip(), (r.get("failure_mode") or "").strip()
                if lc not in PRE.LABEL_CLASSES:
                    raise AuditError(f"REFUSED: {r['sample_id']}: bad label_class {lc!r}")
                if lc == "INCORRECT" and fm not in PRE.FAILURE_MODES:
                    raise AuditError(f"REFUSED: {r['sample_id']}: INCORRECT needs a failure_mode")
                if fm and fm not in PRE.FAILURE_MODES:
                    raise AuditError(f"REFUSED: {r['sample_id']}: bad failure_mode {fm!r}")
                rows.append({"sample_id": r["sample_id"], "label_class": lc, "failure_mode": fm or None,
                             "better_category": (r.get("better_category") or "").strip() or None,
                             "adjudicator": (r.get("adjudicator") or "").strip(),
                             "adjudicator_role": (r.get("adjudicator_role") or "").strip(),
                             "rationale": (r.get("rationale") or "").strip(), "source": f"workbook_part{part}.csv"})
    sample = C.read_jsonl(os.path.join(d, "sample.jsonl"))
    a1, _ = _annotation_labels(d, "a1", sample)
    a2, _ = _annotation_labels(d, "a2", sample)
    adjudicate(sample, a1, a2, rows, vp_rule_approved(d))          # validates identity, role, rationale, ids
    C.write_jsonl(os.path.join(d, "adjudication.jsonl"), rows, key=lambda r: r["sample_id"])
    return {"adjudicated": len(rows), "workbooks_sha256": files}


def cmd_adjudication_workbook(a) -> int:
    print(adjudication_workbook(round_dir(a.out_root, a.round), a.part))
    return 0


def cmd_adjudication_import(a) -> int:
    print(json.dumps(adjudication_import(round_dir(a.out_root, a.round)), indent=1))
    return 0


def cmd_adjudication_sheet(a) -> int:
    d = round_dir(a.out_root, a.round)
    sample = C.read_jsonl(os.path.join(d, "sample.jsonl"))
    _annotators(d)
    a1, e1 = _annotation_labels(d, "a1", sample)
    a2, e2 = _annotation_labels(d, "a2", sample)
    if a1 is None or a2 is None:
        raise AuditError("REFUSED: both annotations must be complete first:\n  " + "\n  ".join((e1 + e2)[:20]))
    p = os.path.join(d, "adjudication.jsonl")
    vp = vp_rule_approved(d)
    final, pending = adjudicate(sample, a1, a2, C.read_jsonl(p) if os.path.isfile(p) else [], vp)
    if vp:
        appr = _read_json(os.path.join(d, "adjudication_rules.json"))["vp_split_to_probably_correct"]
        trace = rule_trace(sample, a1, a2, final, {k: appr.get(k) for k in ("approved_by", "date", "decision_ref")})
        C.write_jsonl(os.path.join(d, "adjudication_rule_applied.jsonl"), trace, key=lambda r: r["sample_id"])
        print(f"{len(trace)} V/P splits resolved to PROBABLY_CORRECT by {VP_RULE_ID} -> adjudication_rule_applied.jsonl")
    by = {s["sample_id"]: s for s in sample}
    rows = [{"sample_id": i, "category": by[i]["category"], "source_file": by[i]["source_file"],
             "payload_wire": by[i]["payload_wire"], "a1": a1[i], "a2": a2[i]} for i in pending]
    C.write_jsonl(os.path.join(d, "adjudication_pending.jsonl"), rows, key=lambda r: r["sample_id"])
    print(f"{len(rows)} disagreements need an identified adjudicator -> adjudication_pending.jsonl")
    return 0


HUMAN_SHEET_FIELDS = ["batch", "sample_id", "category", "source_file", "payload", "payload_logical"] + HUMAN_FIELDS[2:]


def human_sheet(d: str) -> str:
    """Rewrite the still-EMPTY human_labels.csv as a self-contained review sheet: batch order, read-only context
    (category, source file, wire and logical payload) and the fill-in columns. Never shows any LLM label. Refused
    as soon as any row carries a label or a reviewer."""
    hd = os.path.join(d, "human_review")
    with open(os.path.join(hd, "human_review_sample.csv"), encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    lab = os.path.join(hd, "human_labels.csv")
    if os.path.exists(lab):
        with open(lab, encoding="utf-8", newline="") as fh:
            cur = list(csv.DictReader(fh))
        if any((r.get("label_class") or "").strip() or (r.get("reviewer") or "").strip() for r in cur):
            raise AuditError("REFUSED: human_labels.csv already holds labels; it is never rewritten")
    with open(lab, "w", encoding="utf-8", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=HUMAN_SHEET_FIELDS, quoting=csv.QUOTE_ALL, lineterminator="\n")
        w.writeheader()
        for b, grp in enumerate(PRE.batches(rows, 12), 1):
            for r in grp:
                w.writerow({"batch": b, "sample_id": r["sample_id"], "category": r["category"],
                            "source_file": r["source_file"], "payload": r["payload"],
                            "payload_logical": r["payload_logical"]})
    return lab


def cmd_human_sheet(a) -> int:
    print(human_sheet(round_dir(a.out_root, a.round)))
    return 0


def cmd_human_batch(a) -> int:
    d = os.path.join(round_dir(a.out_root, a.round), "human_review")
    with open(os.path.join(d, "human_review_sample.csv"), encoding="utf-8", newline="") as fh:
        rows = list(csv.DictReader(fh))
    groups = PRE.batches(rows, a.size)
    lab = os.path.join(d, "human_labels.csv")
    if not os.path.exists(lab):
        with open(lab, "w", encoding="utf-8", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=HUMAN_FIELDS, quoting=csv.QUOTE_ALL, lineterminator="\n")
            w.writeheader()
            for b, grp in enumerate(groups, 1):
                for r in grp:
                    w.writerow({"batch": b, "sample_id": r["sample_id"]})
        print(f"created {lab} (empty template, {len(rows)} rows)")
    if not 1 <= a.batch <= len(groups):
        raise AuditError(f"batch must be in 1..{len(groups)}")
    print(f"batch {a.batch}/{len(groups)} (size {a.size}); no LLM label is shown or read")
    for r in groups[a.batch - 1]:
        print(f"\n[{r['sample_id']}] category: {r['category']} | source: {r['source_file']}")
        print(f"wire:    {r['payload']!r}")
        print(f"logical: {r['payload_logical']!r}")
    return 0


def cmd_report(a) -> int:
    rep = report(a.out_root, a.round)
    print(json.dumps({"mode": rep["mode"], "real_gate_run": rep["real_gate_run"], "summary": rep["summary"],
                      "open_issue_count": rep["open_issue_count"]}, indent=2))
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, fn in (("plan", cmd_plan), ("sample", cmd_sample), ("annotation-packets", cmd_annotation_packets),
                     ("agreement", cmd_agreement), ("adjudication-sheet", cmd_adjudication_sheet),
                     ("adjudication-workbook", cmd_adjudication_workbook),
                     ("adjudication-import", cmd_adjudication_import), ("human-sheet", cmd_human_sheet),
                     ("human-batch", cmd_human_batch), ("report", cmd_report)):
        sp = sub.add_parser(name)
        sp.add_argument("--attack-dir", default=DEFAULT_ATTACK_DIR)
        sp.add_argument("--denylist", default=None, help="default: the path recorded in the pool manifest")
        sp.add_argument("--out-root", default=DEFAULT_OUT_ROOT)
        if name != "plan":
            sp.add_argument("--round", type=int, required=True)
        if name == "sample":
            sp.add_argument("--seed", required=True, help="a NEW seed (never used by an earlier audit)")
            sp.add_argument("--filter-change-doc", default=None, help="required for the re-audit (round 2)")
            sp.add_argument('--prior-r4-evidence',default=None,help='pinned authoritative R3 evidence binding for round-2 continuation')
            sp.add_argument('--category',action='append',default=None,help='explicit continuation category; requires prior r4 evidence')
        if name == "adjudication-workbook":
            sp.add_argument("--part", type=int, choices=(1, 2), required=True,
                            help="1: outside the blind human subsample; 2: inside it (only after the human review)")
        if name == "human-batch":
            sp.add_argument("--batch", type=int, required=True)
            sp.add_argument("--size", type=int, default=12)
        sp.set_defaults(fn=fn)
    return ap


def main(argv=None) -> int:
    a = build_parser().parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
