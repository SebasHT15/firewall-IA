#!/usr/bin/env python3
"""Per-component audit binding for a multi-source V5 dataset (component-evidence contract).

The legacy FINAL reader verifies ONE audited pool for ALL attack rows. A V5 dataset that draws
path_traversal/file_inclusion from the ORIGINAL pool (path_file_access PASS, not transferred) and the
injection categories from a NEW census pool needs each row bound to exactly one component, with that
component's outcome deciding eligibility. This module verifies each component with the real
`v5_audit_evidence.verify`, derives each row's audited category FROM its pinned pool record (not the row's
claim), cross-checks identity + content, and admits only PASS_AI_AUDITED in the owning component. It never
computes a combined-pool PASS.

Backward compatible: `component_bindings(audit_item)` returns the legacy single component when no
`components` list is present, so existing single-pool freeze records keep working.
"""
import json
from pathlib import Path

import v5_audit_evidence as AE

PASS = "PASS_AI_AUDITED"


def component_bindings(audit_item):
    """Normalise a freeze record's post_filter_audit item to a list of component dicts.

    New form: audit_item['components'] = [{component_id, audit_evidence, category_outcomes}, ...].
    Legacy form: a single {audit_evidence, category_outcomes} -> one component 'default'.
    """
    comps = audit_item.get("components")
    if comps is None:
        return [{"component_id": "default",
                 "audit_evidence": audit_item.get("audit_evidence"),
                 "category_outcomes": audit_item.get("category_outcomes")}]
    if not isinstance(comps, list) or not comps:
        raise ValueError("post_filter_audit.components must be a non-empty list")
    ids = [c.get("component_id") for c in comps]
    if any(not isinstance(i, str) or not i.strip() for i in ids) or len(set(ids)) != len(ids):
        raise ValueError("each component needs a unique component_id")
    return comps


def _pool_index(binding):
    """record_id -> pinned pool record, from the EXACT bytes whose sha256 the binding pins.

    AE.verify already compared that sha to the file; here we re-read, re-hash and assert equality so the index
    is built over the verified bytes (never a divergent re-read), and we REJECT duplicate record_ids — a
    duplicate makes pool membership ambiguous and must fail closed, not be silently overwritten."""
    pool_path = Path(binding["pool"]["path"])
    if not pool_path.is_absolute():
        pool_path = Path(AE.C.REPO_ROOT) / pool_path
    raw = pool_path.read_bytes()
    if AE.sha256(raw) != binding["pool"]["sha256"]:
        raise ValueError("pool bytes changed since verification")
    idx = {}
    for line in raw.split(b"\n"):
        if not line.strip():
            continue
        r = json.loads(line)
        rid = r.get("record_id")
        if not isinstance(rid, str) or not rid:
            raise ValueError("pool record has no record_id")
        if rid in idx:
            raise ValueError(f"duplicate record_id in pool: {rid}")
        idx[rid] = r
    return idx


def _derive_category(record, outcomes):
    """The audited category of a pool record = the record field (category_v4 or d47_category) whose value is a
    key in THIS component's outcomes. Returns None if neither names an audited category here."""
    for field in ("category_v4", "d47_category", "dedup_scope", "category", "attack_category"):
        v = record.get(field)
        if isinstance(v, str) and v in outcomes:
            return v
    return None


def resolve_components(rows, components, *, committed_checker=None):
    """Verify each component and bind every BLOCK row to exactly one component.

    A component may declare `categories` = the categories it is AUTHORITATIVE for (its contribution to the
    dataset). When present, only those categories enter the merged outcome map and a row is admissible only
    if its DERIVED category is one of them — so the original pool (which the R3 report scores for every
    category) contributes ONLY its declared categories (e.g. path_file_access), and a SQLi record sitting in
    that same pool is NOT admitted by it. When `categories` is absent the component owns every category its
    report scores (legacy single-component behaviour).

    Returns {"diags": [(code, detail), ...], "merged_outcomes": {category: status}, "components_meta": [...]}.
    merged_outcomes is category->status with each category owned by exactly ONE component (a category declared
    by two components is a hard error — never a combined PASS)."""
    diags, verified, owner, merged, comp_meta = [], {}, {}, {}, []
    for comp in components:
        cid = comp.get("component_id")
        try:
            res = AE.verify(comp.get("audit_evidence"),
                            expected_outcomes=comp.get("category_outcomes"),
                            committed_checker=committed_checker)
            idx = _pool_index(comp["audit_evidence"])
        except (OSError, ValueError, TypeError) as e:
            diags.append(("AUDIT_COMPONENT_EVIDENCE", f"{cid}: {e}"))
            continue
        outcomes = res["category_outcomes"]
        declared = comp.get("categories")
        declared = set(outcomes) if declared is None else set(declared)
        unknown = sorted(declared - set(outcomes))
        if unknown:
            diags.append(("AUDIT_COMPONENT_CATEGORY_NOT_AUDITED", f"{cid}: declared categories not in its audit: {unknown}"))
        verified[cid] = (outcomes, idx, declared)
        comp_meta.append({"component_id": cid, "pool_sha256": comp["audit_evidence"]["pool"]["sha256"],
                          "categories": sorted(declared),
                          "category_outcomes": {c: outcomes.get(c) for c in sorted(declared)}})
        for cat in declared:
            if cat in merged and merged[cat][0] != cid:
                diags.append(("AUDIT_CATEGORY_IN_MULTIPLE_COMPONENTS", f"{cat}: owned by {merged[cat][0]} and {cid}"))
            merged[cat] = (cid, outcomes.get(cat))
        for rid, record in idx.items():
            # A component owns only records in its declared authoritative
            # categories. The original pool contains SQLi and other rows, but
            # its evidence contributes only path_file_access here; those
            # incidental IDs must not make a SQLi-v3 row ambiguous.
            if _derive_category(record, outcomes) in declared:
                owner.setdefault(rid, set()).add(cid)

    if diags:
        # a component's audit did not verify (or its categories are inconsistent): do not bind rows against a
        # partial/invalid component set — report the component-level failure alone.
        return {"diags": diags, "merged_outcomes": {c: st for c, (cid, st) in merged.items()},
                "components_meta": comp_meta}

    for r in rows:
        meta = r.get("meta", r)
        if meta.get("label") != "BLOCK":
            continue
        rid = meta.get("payload_record_id")
        claimed = meta.get("attack_category")
        comps = owner.get(rid, set())
        if not comps:
            diags.append(("AUDIT_POOL_MEMBERSHIP", f"{rid}: in no verified component pool")); continue
        if len(comps) > 1:
            diags.append(("COMPONENT_MEMBERSHIP_AMBIGUOUS", f"{rid}: {sorted(comps)}")); continue
        cid = next(iter(comps))
        outcomes, idx, declared = verified[cid]
        record = idx[rid]
        if meta.get("payload_wire") is not None and meta["payload_wire"] != record.get("payload_wire"):
            diags.append(("AUDIT_ROW_CONTENT_MISMATCH", f"{rid}: payload_wire differs from pinned pool record")); continue
        derived = _derive_category(record, outcomes)
        if derived is None or derived not in declared:
            diags.append(("AUDIT_CATEGORY_NOT_IN_COMPONENT",
                          f"{rid}: record category {derived!r} is not authoritative in component {cid} "
                          f"(declared {sorted(declared)}); no combined-pool PASS")); continue
        if claimed is not None and claimed != derived:
            diags.append(("AUDIT_CATEGORY_CROSS_CLAIM",
                          f"{rid}: row claims {claimed!r} but audited record category is {derived!r} in {cid}")); continue
        if outcomes.get(derived) != PASS:
            diags.append(("AUDIT_CATEGORY_NOT_PASSED",
                          f"{rid}: {derived!r} outcome {outcomes.get(derived)!r} in {cid}; only {PASS!r} eligible"))
    return {"diags": diags, "merged_outcomes": {c: st for c, (cid, st) in merged.items()},
            "components_meta": comp_meta}


def verify_components(rows, audit_item, *, committed_checker=None):
    """Back-compatible wrapper: returns only the (code, detail) rejections for a freeze-record audit item
    (legacy single `audit_evidence` or a `components` list). Used by the reader paths."""
    return resolve_components(rows, component_bindings(audit_item), committed_checker=committed_checker)["diags"]
