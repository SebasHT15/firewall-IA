"""Whole-group bootstrap diagnostics at a fixed threshold; proposal only.

Conditional on fixed predictions and declared groups; no fit, selection,
representativeness claim, dataset authorization or operational risk bound.
"""
from collections import defaultdict
import math
import random

from .evaluation import summarize_validation

METRICS = ("early_block_false_positive_rate", "attack_early_block_rate",
           "block_precision", "defer_rate")


def _counts(rows, threshold):
    benign = sum(r.reference_label == "ALLOW" for r in rows)
    fp = sum(r.reference_label == "ALLOW" and r.p_block >= threshold for r in rows)
    tp = sum(r.reference_label == "BLOCK" and r.p_block >= threshold for r in rows)
    return len(rows), benign, len(rows) - benign, fp, tp


def _fractions(counts):
    total, benign, attack, fp, tp = counts
    return ((fp, benign), (tp, attack), (tp, fp + tp), (total - fp - tp, total))


def _quantile(values, p):
    """Linear interpolation at (n-1)*p in sorted nonempty values."""
    location = (len(values) - 1) * p
    lo, hi = math.floor(location), math.ceil(location)
    return values[lo] + (values[hi] - values[lo]) * (location - lo)


def summarize_grouped_validation(rows, *, threshold, group_definition,
                                 confidence_level, n_resamples, seed):
    rows = tuple(rows)
    point = summarize_validation(rows, threshold=threshold)
    if type(group_definition) is not str or not group_definition.strip():
        raise ValueError("explicit group definition required")
    if type(confidence_level) not in (float, int) or not 0 < confidence_level < 1:
        raise ValueError("confidence level must be strictly between zero and one")
    if type(n_resamples) is not int or not 2 <= n_resamples <= 100000:
        raise ValueError("resamples must be an integer in [2,100000] (offline work bound)")
    if type(seed) is not int or seed < 0:
        raise ValueError("nonnegative integer seed required")
    grouped = defaultdict(list)
    for row in rows:
        grouped[row.group_id].append(row)
    counts = [_counts(grouped[key], threshold) for key in sorted(grouped)]
    if len(counts) * n_resamples > 10000000:
        raise ValueError("offline resampling work bound exceeded")
    contributing = [sum(_fractions(c)[i][1] > 0 for c in counts) for i in range(4)]
    draws, undefined = [[] for _ in METRICS], [0] * len(METRICS)
    rng = random.Random(seed)
    for _ in range(n_resamples):
        totals = [0] * 5
        for _ in counts:
            c = counts[rng.randrange(len(counts))]
            for j, value in enumerate(c):
                totals[j] += value
        for i, (num, den) in enumerate(_fractions(totals)):
            if den:
                draws[i].append(num / den)
            else:
                undefined[i] += 1
    intervals, alpha = {}, (1 - confidence_level) / 2
    for i, name in enumerate(METRICS):
        values, interval = sorted(draws[i]), None
        if point[name]["denominator"] == 0:
            status = "NO_DENOMINATOR"
        elif contributing[i] < 2:
            status = "INSUFFICIENT_CONTRIBUTING_GROUPS"
        elif undefined[i]:
            status = "UNDEFINED_RESAMPLES"  # Never discard denominator failures silently.
        elif values[0] == values[-1]:
            status = "DEGENERATE_RESAMPLES"  # Zero observed errors is not zero risk.
        else:
            low, high = _quantile(values, alpha), _quantile(values, 1 - alpha)
            status = "COLLAPSED_PERCENTILES" if low == high else "ESTIMATED_CONDITIONAL"
            if low != high:
                interval = {"low": low, "high": high}
        intervals[name] = {"status": status, "interval": interval,
                           "contributing_groups": contributing[i],
                           "defined_resamples": len(values),
                           "undefined_resamples": undefined[i]}
    return {
        "point": point,
        "group_summary": {"groups": len(counts), "smallest": min(c[0] for c in counts),
                          "largest": max(c[0] for c in counts),
                          "benign_groups": sum(c[1] > 0 for c in counts),
                          "benign_groups_with_false_block": sum(c[3] > 0 for c in counts)},
        "uncertainty": {"method": "whole_group_percentile_bootstrap/proposal-v1",
                        "group_definition": group_definition,
                        "confidence_level": confidence_level, "n_resamples": n_resamples,
                        "seed": seed, "intervals": intervals,
                        "assumptions": "declared groups independent and exchangeable; not verified here",
                        "scope": "fixed predictions and threshold; excludes fit/selection uncertainty",
                        "readiness": "diagnostic_only_not_a_risk_bound"},
        "operational_policy_approved": False,
    }
