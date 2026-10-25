#!/usr/bin/env python3.12
"""C-S4: fit on TRAIN structure only and score VALIDATION once."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy
import scipy
import sklearn
from sklearn.feature_extraction import DictVectorizer
from sklearn.linear_model import LogisticRegression

FEATURES = ("carrier", "method", "media_type", "encoder_profile", "length_bin",
            "field_names", "struct_cluster_id", "template_id", "placement_mode",
            "attacked_slot_role", "attacked_slot_type")


def read(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def features(row: dict) -> dict[str, str]:
    return {name: json.dumps(row.get(name), sort_keys=True, ensure_ascii=False) for name in FEATURES}


def check(dataset: Path) -> dict:
    train = read(dataset / "rows.TRAIN.meta.jsonl")
    valid = read(dataset / "rows.VALIDATION.meta.jsonl")
    vec = DictVectorizer(sparse=True)
    # The pinned sklearn 1.9.1 rejects scipy sparse matrices with int64
    # indices. This small design matrix is dense (<30 MiB), avoiding an
    # environment-dependent sparse-index cast.
    x_train = vec.fit_transform([features(row) for row in train]).toarray()
    x_valid = vec.transform([features(row) for row in valid]).toarray()
    model = LogisticRegression(max_iter=1000, random_state=0, solver="liblinear")
    model.fit(x_train, [row["label"] for row in train])
    accuracy = float(model.score(x_valid, [row["label"] for row in valid]))
    return {"schema": "v5-cs4-structure-probe/v1", "train_rows": len(train),
            "validation_rows": len(valid), "feature_names": list(FEATURES),
            "encoded_feature_count": x_train.shape[1], "accuracy": accuracy,
            "libraries": {"numpy": numpy.__version__, "scipy": scipy.__version__,
                          "scikit_learn": sklearn.__version__},
            "fit": {"random_state": 0, "solver": "liblinear", "max_iter": 1000},
            "warn_accuracy_gt": .55, "block_accuracy_gt": .65,
            "status": "BLOCK" if accuracy > .65 else "WARN" if accuracy > .55 else "PASS"}


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("dataset", type=Path)
    p.add_argument("--out", type=Path, required=True)
    a = p.parse_args()
    result = check(a.dataset)
    a.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"accuracy": result["accuracy"], "status": result["status"]}, sort_keys=True))


if __name__ == "__main__":
    main()
