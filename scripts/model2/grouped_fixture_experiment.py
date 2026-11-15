"""Fixed V5 fixture: complete target-path ablation and grouped diagnostics.

No external data entry point, saved weights, selected model or policy. Original
label metadata is retained; synthetic provenance follows in-process generation.
"""
import argparse
from collections import Counter
from dataclasses import replace
import hashlib
import json
import math
import sys
import tempfile

from . import v5_fixture_integration as integration
from .evaluation import ValidationScore
from .feature_views import PATH_VIEW
from .grouped_evaluation import summarize_grouped_validation
from .identity_groups import connected_groups, GROUP_DEFINITION, IDENTITY_KEYS

ROOT = integration.ROOT


def source_hashes():
    hashes = integration.source_hashes()
    for name in ("grouped_fixture_experiment", "grouped_evaluation", "identity_groups", "feature_views"):
        path = f"scripts/model2/{name}.py"
        hashes[path] = hashlib.sha256((ROOT / path).read_bytes()).hexdigest()
    return hashes


def _overlap(rows, neutralize):
    by_split = {"TRAIN": set(), "VALIDATION": set()}
    for row in rows:
        vector = integration.experiment.feature_dict(row.text, neutralize_path=neutralize)
        by_split[row.split].add(json.dumps(vector, sort_keys=True))
    return {"train_unique_vectors": len(by_split["TRAIN"]),
            "validation_unique_vectors": len(by_split["VALIDATION"]),
            "shared_vectors": len(by_split["TRAIN"] & by_split["VALIDATION"]),
            "interpretation": "diagnostic feature collisions; no rows removed, no content leaked"}


def run(*, demonstration_threshold, confidence_level, n_resamples, seed):
    import sklearn
    if (type(demonstration_threshold) not in (int, float)
            or not 0 <= demonstration_threshold <= 1 or not math.isfinite(demonstration_threshold)):
        raise ValueError("finite demonstration threshold required")
    before = source_hashes()
    if tuple(integration.exchange.D.IDENTITY_KEYS) != IDENTITY_KEYS:
        raise ValueError("exchange identity contract drift")
    with tempfile.TemporaryDirectory(prefix="model2-grouped-fixture-") as directory:
        integration.build_fixture(directory)
        examples = integration.exchange.load_examples(directory)
        groups = connected_groups(examples)
        group_by_id = {f"{split}:{index}": group for (split, index), group in groups.items()}
        rows = tuple(replace(row, group_id=group_by_id[row.row_id])
                     for row in integration._fixture_rows(examples))
        variants = []
        for neutralize in (False, True):
            encoder, _, validation, probabilities = integration.experiment._fit_fixture(
                rows, neutralize_path=neutralize)
            scores = [ValidationScore(r.row_id, r.group_id, r.split, r.label, r.provenance,
                                     "all_traffic_fast_path_ineligible", float(p))
                      for r, p in zip(validation, probabilities, strict=True)]
            variants.append({
                "variant": PATH_VIEW if neutralize else "baseline_34",
                "input_fields": 32 if neutralize else 34,
                "encoded_features": list(encoder.get_feature_names_out()),
                "feature_overlap": _overlap(rows, neutralize),
                "validation": summarize_grouped_validation(
                    scores, threshold=demonstration_threshold, group_definition=GROUP_DEFINITION,
                    confidence_level=confidence_level, n_resamples=n_resamples, seed=seed),
            })
        metadata = {split: {
            "rows": len(items),
            "pair_groups": len({ex["identities"]["pair_id"] for ex in items}),
            "connected_components": len({groups[(split, ex["row_index"])] for ex in items}),
            "label_status": dict(Counter(ex["label_status"] for ex in items)),
            "label_basis": dict(Counter(str(ex["label_basis"]) for ex in items)),
        } for split, items in examples.items()}
        manifests = {ex["manifest_sha256"] for items in examples.values() for ex in items}
        if len(manifests) != 1:
            raise ValueError("fixture manifest mismatch")
    if before != source_hashes():
        raise RuntimeError("source changed during execution; rerun")
    return {"schema": "model2-grouped-fixture-experiment/proposal-v1", "scope": "FIXTURE_ONLY",
            "python": sys.version.split()[0], "sklearn": sklearn.__version__,
            "source_sha256": before, "fixture_manifest_sha256": next(iter(manifests)),
            "metadata": metadata, "group_definition": GROUP_DEFINITION,
            "identity_keys": IDENTITY_KEYS, "variants": variants,
            "selected_variant": None, "weights_saved": False, "operational_policy_approved": False,
            "limitations": [
                "Synthetic engineering labels and sampling do not estimate security performance.",
                "Connected components do not prove independent/exchangeable population groups.",
                "Intervals condition on fixed model predictions and threshold; no selection correction.",
                "Target-path ablation retains path-like content in query/body and a constant slash.",
                "C1 extensions remain metadata only; 34-field baseline is incomplete C1.",
                "No real training, protected evaluation, C2, V5 inference or active cascade.",
            ]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--demonstration-threshold", type=float, required=True)
    parser.add_argument("--confidence-level", type=float, required=True)
    parser.add_argument("--resamples", type=int, required=True)
    parser.add_argument("--seed", type=int, required=True)
    args = parser.parse_args()
    print(json.dumps(run(demonstration_threshold=args.demonstration_threshold,
                         confidence_level=args.confidence_level,
                         n_resamples=args.resamples, seed=args.seed), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
