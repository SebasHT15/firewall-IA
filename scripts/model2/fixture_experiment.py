"""Fixed synthetic Model 2 wiring exercise; no dataset/model entry point.

Fits ephemeral logistic regression on canonical C1 baseline features. Labels are
arbitrary engineering labels, not verified attack judgments. No weights saved.
"""
import argparse
from dataclasses import asdict, dataclass
import hashlib
import json
import math
from pathlib import Path
import sys
import warnings

from .contracts import REPRESENTATION, invalid_features, rf
from .evaluation import ValidationScore, summarize_validation
from .feature_views import neutralize_target_path
import canonical_request as cr

FEATURES = (
    "method", "path_length", "query_length", "body_length", "has_body",
    "content_type", "body_format", "query_param_count", "body_param_count",
    "total_param_count", "repeated_param_name_count", "alnum_ratio",
    "symbol_count", "symbol_ratio", "non_ascii_count", "percent_encoded_count",
    "percent_encoded_ratio", "has_percent_encoding", "longest_char_run",
    "entropy_bits_per_char", "path_depth", "json_depth", "single_quote_count",
    "double_quote_count", "parenthesis_count", "semicolon_count", "slash_count",
    "backslash_count", "angle_bracket_count", "pipe_count", "ampersand_count",
    "equals_count", "percent_count", "brace_count",
)
# Narrow ablation: surface-wide character/entropy features still include path.
DIRECT_PATH_FIELDS = frozenset(("path_length", "path_depth"))
ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class FixtureRow:
    row_id: str
    group_id: str
    split: str
    label: str
    text: str
    text_sha256: str
    provenance: str = "fixture_synthetic"
    representation: str = REPRESENTATION


def _digest(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def fixtures():
    """Fixed artificial labels, independent of V5 and its manifest gates.

    Pairs share a group within one split. Validation has an unseen method.
    Canonical ACCEPT required; fixture limits leave size unchecked.
    """
    result = []
    for split, count in (("TRAIN", 12), ("VALIDATION", 4)):
        for index in range(count):
            for label, value in (("ALLOW", "ordinary"), ("BLOCK", "synthmark;;;((()))")):
                group = f"{split.lower()}-{index}"
                target = f"/fixture/{group}?value={value}&n={index}".encode()
                method = b"OPTIONS" if split == "VALIDATION" and index == 0 else b"GET"
                canonical = cr.canonicalize(cr.RequestParts(
                    method=method, target=target, http_version="HTTP/1.1",
                    headers=((b"Host", b"fixture.invalid"),), body=b""),
                    cr.Limits(max_decoded_body=4096))
                if canonical.outcome != cr.ACCEPT:
                    raise ValueError("built-in fixture was not canonical ACCEPT")
                text = canonical.text
                result.append(FixtureRow(f"{group}-{label}", group, split, label,
                                         text, _digest(text)))
    return tuple(result)


def validate_fixture_rows(rows):
    """Fixture integrity only; caller metadata cannot authorize real training.

    Real V5 checks must cover every identity dimension via its verified loader.
    """
    rows = tuple(rows)
    if not rows:
        raise ValueError("empty fixture")
    ids = set()
    groups = {"TRAIN": set(), "VALIDATION": set()}
    texts = {"TRAIN": set(), "VALIDATION": set()}
    labels = {"TRAIN": set(), "VALIDATION": set()}
    for row in rows:
        if type(row) is not FixtureRow or row.split not in groups:
            raise ValueError("only fixture TRAIN/VALIDATION rows supported")
        if row.provenance != "fixture_synthetic" or row.representation != REPRESENTATION:
            raise ValueError("fixture provenance and canonical representation required")
        if any(type(s) is not str or not s.strip() for s in (row.row_id, row.group_id, row.text)):
            raise ValueError("fixture identifiers and text required")
        if row.row_id in ids or row.text_sha256 != _digest(row.text):
            raise ValueError("duplicate identifier or text integrity mismatch")
        if row.label not in ("ALLOW", "BLOCK"):
            raise ValueError("fixture reference must be ALLOW/BLOCK")
        ids.add(row.row_id)
        groups[row.split].add(row.group_id)
        texts[row.split].add(row.text_sha256)
        labels[row.split].add(row.label)
    if labels["TRAIN"] != {"ALLOW", "BLOCK"} or not labels["VALIDATION"]:
        raise ValueError("two TRAIN classes and nonempty VALIDATION required")
    if groups["TRAIN"] & groups["VALIDATION"] or texts["TRAIN"] & texts["VALIDATION"]:
        raise ValueError("TRAIN/VALIDATION group or text overlap")
    return rows


def feature_dict(text, *, omit_direct_path=False, neutralize_path=False):
    if type(neutralize_path) is not bool or type(omit_direct_path) is not bool:
        raise TypeError("feature-view flags must be boolean")
    if neutralize_path:
        text = neutralize_target_path(text)
    features = rf.extract_features(text)
    if invalid_features(features):
        raise ValueError("invalid C1 features")
    values = asdict(features)
    if set(values) != set(FEATURES) | {"schema_version"}:
        raise ValueError("feature schema changed; explicit review required")
    return {key: values[key] for key in FEATURES
            if not ((omit_direct_path or neutralize_path) and key in DIRECT_PATH_FIELDS)}


def _fit_fixture(rows, *, omit_direct_path=False, neutralize_path=False):
    """Private helper. run_fixture_experiment is the supported entry point."""
    from sklearn.feature_extraction import DictVectorizer
    from sklearn.preprocessing import StandardScaler
    from sklearn.linear_model import LogisticRegression
    from sklearn.exceptions import ConvergenceWarning

    rows = validate_fixture_rows(rows)
    train = [r for r in rows if r.split == "TRAIN"]
    validation = [r for r in rows if r.split == "VALIDATION"]
    encoder = DictVectorizer(sparse=True, sort=True)
    scaler = StandardScaler(with_mean=False)
    x_train = scaler.fit_transform(encoder.fit_transform([
        feature_dict(r.text, omit_direct_path=omit_direct_path,
                     neutralize_path=neutralize_path) for r in train]))
    x_validation = scaler.transform(encoder.transform([
        feature_dict(r.text, omit_direct_path=omit_direct_path,
                     neutralize_path=neutralize_path) for r in validation]))
    model = LogisticRegression(C=1.0, solver="lbfgs", max_iter=500,
                               tol=1e-6, random_state=0)
    with warnings.catch_warnings():
        warnings.simplefilter("error", ConvergenceWarning)
        model.fit(x_train, [r.label for r in train])
    block_index = list(model.classes_).index("BLOCK")
    probabilities = model.predict_proba(x_validation)[:, block_index]
    if any(not math.isfinite(p) or not 0 <= p <= 1 for p in probabilities):
        raise ValueError("invalid learner probabilities")
    return encoder, scaler, validation, probabilities


def _source_hashes():
    names = ("data_plane/request_features.py", "data_plane/canonical_request.py",
             "scripts/model2/fixture_experiment.py", "scripts/model2/contracts.py",
             "scripts/model2/evaluation.py", "scripts/model2/feature_views.py")
    return {name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest() for name in names}


def run_fixture_experiment(*, demonstration_threshold):
    """No caller data accepted; threshold is demonstration-only, never selected."""
    import sklearn

    if (type(demonstration_threshold) not in (float, int)
            or not 0 <= demonstration_threshold <= 1
            or not math.isfinite(demonstration_threshold)):
        raise ValueError("explicit finite demonstration threshold required")
    before = _source_hashes()
    rows = fixtures()
    variants = []
    for omit_path in (False, True):
        encoder, _, validation, probabilities = _fit_fixture(rows, omit_direct_path=omit_path)
        scores = [ValidationScore(r.row_id, r.group_id, r.split, r.label, r.provenance,
                                 "all_traffic_fast_path_ineligible", float(p))
                  for r, p in zip(validation, probabilities, strict=True)]
        variants.append({
            "variant": "omit_direct_path_fields" if omit_path else "baseline_34",
            "input_fields": len(FEATURES) - (2 if omit_path else 0),
            "encoded_features": list(encoder.get_feature_names_out()),
            "validation": summarize_validation(scores, threshold=demonstration_threshold),
        })
    if before != _source_hashes():
        raise RuntimeError("source changed during execution; rerun")
    return {
        "schema": "model2-fixture-experiment/v1", "scope": "FIXTURE_ONLY",
        "representation": REPRESENTATION, "feature_schema": rf.FEATURE_SCHEMA_VERSION,
        "python": sys.version.split()[0], "sklearn": sklearn.__version__,
        "source_sha256": before,
        "train_rows": sum(r.split == "TRAIN" for r in rows),
        "validation_rows": sum(r.split == "VALIDATION" for r in rows),
        "recipe": {"learner": "LogisticRegression", "C": 1.0, "solver": "lbfgs",
                   "max_iter": 500, "tol": 1e-6, "random_state": 0,
                   "encoder_fit": "TRAIN_only", "scaler_fit": "TRAIN_only",
                   "scaler": "StandardScaler(with_mean=False)"},
        "variants": variants, "selected_variant": None,
        "weights_saved": False, "operational_policy_approved": False,
        "limitations": [
            "Artificial labels check wiring only; metrics do not measure security quality.",
            "Baseline 34 features are not complete C1; C2 is absent.",
            "Omitting path_length/path_depth does not remove all path-derived information.",
            "Fixture pair disjointness is not the full V5 identity/leakage protocol.",
            "No V5 exchange loader exercised; no real data or trained candidate produced.",
            "Canonical ACCEPT uses fixture limits, no ratified B; size remains unchecked.",
            "No threshold selection, uncertainty estimate, gateway integration or enforcement.",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--demonstration-threshold", type=float, required=True)
    args = parser.parse_args()
    # Extra guard only, not a complete filesystem security boundary.
    def deny_dataset_reads(event, values):
        if event == "open" and isinstance(values[0], (str, bytes)):
            import os
            if "datasets" in Path(os.fsdecode(values[0])).resolve().parts:
                raise PermissionError("dataset access forbidden in fixture experiment")
    sys.addaudithook(deny_dataset_reads)
    print(json.dumps(run_fixture_experiment(demonstration_threshold=args.demonstration_threshold),
                     indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
