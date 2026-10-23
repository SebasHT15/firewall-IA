"""Synthetic V5 example exchange -> C1 -> ephemeral Model 2 integration.

Generates its own temporary fixture. No caller dataset/authorization/model path
accepted. Original label metadata remains distinct from synthetic scope.
"""
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
import tempfile

from . import fixture_experiment as experiment
from .evaluation import ValidationScore, summarize_validation

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / "scripts" / "training"), str(ROOT / "scripts" / "dataset")]
import v5_example_exchange as exchange
import v5_fixture as fixture
import v5_generator as generator


def build_fixture(directory):
    world, generated, gates = fixture.generate()
    if not gates["ok"]:
        raise ValueError("synthetic V5 producer gates failed")
    return generator.write_outputs(world, generated, gates, str(directory), extra={"fixture": True})


def _fixture_rows(examples):
    """Private adapter for our generated fixture; not a real-data eligibility gate.

    The V5 reader checks all identity dimensions. Pair IDs here support descriptive
    fixture metrics only, not group-aware confidence intervals.
    """
    rows = []
    for split in ("TRAIN", "VALIDATION"):
        for ex in examples[split]:
            row_id = f"{split}:{ex['row_index']}"
            group = ex["identities"].get("pair_id") or row_id
            rows.append(experiment.FixtureRow(row_id, group, split, ex["label"],
                                              ex["text"], ex["text_sha256"]))
    return tuple(rows)


def source_hashes():
    hashes = experiment._source_hashes()
    names = ("scripts/model2/v5_fixture_integration.py", "scripts/training/v5_example_exchange.py",
             "scripts/training/v5_train_data.py", "scripts/training/v5_training_recipe_v1.json")
    # Pin fixture producer/helpers without accessing any data pools.
    paths = {ROOT / n for n in names} | set((ROOT / "scripts" / "dataset").glob("v5_*.py"))
    for path in sorted(paths):
        hashes[str(path.relative_to(ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
    return hashes


def run(*, demonstration_threshold):
    """Fit the fixed generated fixture only; discard all weights on return."""
    import math
    import sklearn
    if (type(demonstration_threshold) not in (int, float)
            or not 0 <= demonstration_threshold <= 1 or not math.isfinite(demonstration_threshold)):
        raise ValueError("explicit finite demonstration threshold required")
    before = source_hashes()
    with tempfile.TemporaryDirectory(prefix="model2-v5-fixture-") as directory:
        build_fixture(directory)
        examples = exchange.load_examples(directory)
        rows = _fixture_rows(examples)
        encoder, _, validation, probabilities = experiment._fit_fixture(rows)
        scores = [ValidationScore(r.row_id, r.group_id, r.split, r.label,
                                 "fixture_synthetic", "all_traffic_fast_path_ineligible", float(p))
                  for r, p in zip(validation, probabilities, strict=True)]
        metrics = summarize_validation(scores, threshold=demonstration_threshold)
        metadata = {}
        for split, items in examples.items():
            metadata[split] = {
                "rows": len(items),
                "reference_labels": dict(Counter(ex["label"] for ex in items)),
                "label_status": dict(Counter(ex["label_status"] for ex in items)),
                "label_basis": dict(Counter(str(ex["label_basis"]) for ex in items)),
            }
        manifest_hashes = {ex["manifest_sha256"] for items in examples.values() for ex in items}
        if len(manifest_hashes) != 1:
            raise ValueError("examples do not share one verified manifest")
    if before != source_hashes():
        raise RuntimeError("integration source changed during execution; rerun")
    return {
        "schema": "model2-v5-fixture-integration/v1", "scope": "FIXTURE_ONLY",
        "python": sys.version.split()[0], "sklearn": sklearn.__version__,
        "source_sha256": before, "fixture_manifest_sha256": next(iter(manifest_hashes)),
        "dataset_metadata": metadata, "input_features": len(experiment.FEATURES),
        "encoded_features": list(encoder.get_feature_names_out()),
        "validation": metrics, "weights_saved": False, "operational_policy_approved": False,
        "limitations": [
            "Synthetic fixture labels test integration, not security accuracy.",
            "Original label statuses/bases preserved in metadata; not promoted to VERIFIED.",
            "Fixture provenance established by in-process generation, not row declarations.",
            "No C2 or V5 weights; baseline C1 incomplete; no active cascade tested.",
            "No real dataset, chosen operating point, protected evaluation or saved model.",
            "Pair-group counts are descriptive, not a full statistical grouping protocol.",
        ],
    }


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--demonstration-threshold", type=float, required=True)
    args = parser.parse_args()
    print(json.dumps(run(demonstration_threshold=args.demonstration_threshold), sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
