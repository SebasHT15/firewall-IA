"""PROPOSED selective-blocking metrics for VALIDATION, with explicit denominators.

Pure functions over supplied records; no file loading, fitting, threshold selection,
protected-test evaluation or policy activation. A caller must supply the threshold
and identify label provenance and the reached population. These point estimates do
not establish operational safety; uncertainty/group-based evaluation remains required.
"""
import math
from dataclasses import dataclass


@dataclass(frozen=True)
class ValidationScore:
    row_id: str
    group_id: str
    role: str
    reference_label: str
    label_provenance: str
    population: str
    p_block: float


def _probability(value):
    return type(value) in (float, int) and 0 <= value <= 1 and math.isfinite(value)


def _rate(numerator, denominator):
    return {"numerator": numerator, "denominator": denominator,
            "value": numerator / denominator if denominator else None}


def summarize_validation(rows, *, threshold):
    """Summarize a caller-chosen threshold. Never find or approve an operating point.

    Raw/all traffic and Fast Path CONTINUE populations must never be silently mixed.
    Different label provenances must be reported separately. V4/V5 model decisions
    are forbidden as reference labels; an AI audit label is not called VERIFIED.
    """
    if not _probability(threshold):
        raise ValueError("threshold must be finite and in [0,1]")
    rows = tuple(rows)
    if not rows:
        raise ValueError("empty validation population")
    seen = set()
    provenance = set()
    populations = set()
    for row in rows:
        if type(row) is not ValidationScore or row.role != "VALIDATION":
            raise ValueError("only explicitly identified VALIDATION records are allowed")
        if any(type(x) is not str or not x.strip() for x in (row.row_id, row.group_id)):
            raise ValueError("row and group identifiers are required")
        if row.row_id in seen:
            raise ValueError("duplicate row identifier")
        seen.add(row.row_id)
        if row.reference_label not in ("ALLOW", "BLOCK"):
            raise ValueError("unknown reference label")
        if row.label_provenance not in ("fixture_synthetic", "constructive", "policy_defined", "ai_audited"):
            raise ValueError("unsupported label provenance; model agreement is not a reference")
        if row.population not in ("all_traffic_fast_path_ineligible", "fast_path_continue"):
            raise ValueError("reached population must be identified")
        if not _probability(row.p_block):
            raise ValueError("invalid posterior")
        provenance.add(row.label_provenance)
        populations.add(row.population)
    if len(provenance) != 1 or len(populations) != 1:
        raise ValueError("report label provenance and reached populations separately")
    benign = sum(r.reference_label == "ALLOW" for r in rows)
    attack = len(rows) - benign
    fp = sum(r.reference_label == "ALLOW" and r.p_block >= threshold for r in rows)
    tp = sum(r.reference_label == "BLOCK" and r.p_block >= threshold for r in rows)
    blocked = fp + tp
    return {"threshold": threshold, "threshold_status": "caller_supplied_not_approved",
            "label_provenance": next(iter(provenance)), "population": next(iter(populations)),
            "records": len(rows), "groups": len({r.group_id for r in rows}),
            "early_block_false_positive_rate": _rate(fp, benign),
            "attack_early_block_rate": _rate(tp, attack),
            "block_precision": _rate(tp, blocked),
            "defer_rate": _rate(len(rows) - blocked, len(rows)),
            "uncertainty": "not_estimated; point_estimates_only",
            "operational_policy_approved": False}
