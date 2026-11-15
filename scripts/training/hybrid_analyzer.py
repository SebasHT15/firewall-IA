"""
firewall-IA — Lightweight Request Analyzer, Phase 2B building blocks (Issue #53).

Research code, never imported by the data plane (D52, D33). Needs numpy and
scikit-learn from the separate research environment:

    uv venv --python 3.12 --seed .venv-analyzer
    .venv-analyzer/bin/python -m pip install -r requirements-analyzer-research.txt

What is here, and nothing more:

  load_dataset      hybrid_analyzer_v1 (SHA-256 verified) as RequestFeatures + targets
  FeatureEncoder    RequestFeatures v2 -> numeric vector; fitted on TRAIN only
  make_model        the three model families with their fixed hyperparameters
  metrics           attack / category metrics, reliability bins, bootstrap intervals
  AnalyzerModel     attack model (+ calibrator) and category model -> AnalyzerOutput (D50)

The two tasks are separate (D46): `attack` over every fitted row, category only over
BLOCK rows. The model input is RequestFeatures v2 and nothing else; the dataset's
`meta_` fields are only used to slice the evaluation.
"""

import dataclasses
import hashlib
import json
import math
import os
import sys

import numpy as np
from sklearn import metrics as skm
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO_ROOT, "data_plane"))

import hybrid_contracts as contracts  # noqa: E402
import request_features as rf  # noqa: E402

DATASET = os.path.join(REPO_ROOT, "datasets", "hybrid_analyzer_v1", "hybrid_analyzer_v1.jsonl")
DATASET_MANIFEST = os.path.join(REPO_ROOT, "datasets", "manifest_hybrid_analyzer_v1.json")

CATEGORIES = contracts.ANALYZER_CATEGORIES
FEATURE_FIELDS = tuple(f.name for f in dataclasses.fields(rf.RequestFeatures)
                       if f.name != "schema_version")
_TYPES = {f.name: f.type for f in dataclasses.fields(rf.RequestFeatures)}
_TYPE_NAME = {n: getattr(t, "__name__", t) for n, t in _TYPES.items()}
COUNT_FIELDS = tuple(n for n in FEATURE_FIELDS if _TYPE_NAME[n] == "int")
RATIO_FIELDS = tuple(n for n in FEATURE_FIELDS if _TYPE_NAME[n] == "float")
BOOLEAN_FIELDS = tuple(n for n in FEATURE_FIELDS if _TYPE_NAME[n] == "bool")
CATEGORICAL_FIELDS = tuple(n for n in FEATURE_FIELDS if _TYPE_NAME[n] == "str")
# body_format is a closed enum of request_features; method and content_type are open.
BODY_FORMATS = ("none", "form", "json", "json_invalid", "other")
OTHER = "__other__"
PATH_ABLATION = ("path_length", "path_depth")          # D46 mandatory ablation
SEED = 0
REPORT_THRESHOLD = 0.5   # reporting convention for confusion counts; not an operating point


# ── dataset ─────────────────────────────────────────────────────────────────
def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_dataset(path=DATASET, manifest_path=DATASET_MANIFEST, verify=True, roles=None):
    """Rows of a hybrid_analyzer dataset (v1 by default), with `features` turned into
    RequestFeatures. Refuses a file whose SHA-256 differs from its manifest. `roles`
    keeps only rows of those roles, so a stage that must not see INTERNAL TEST never
    holds its rows in memory."""
    if verify:
        expected = json.load(open(manifest_path))["artifact"]["sha256"]
        actual = sha256_file(path)
        if actual != expected:
            raise ValueError(f"{path}: SHA-256 {actual} != manifest {expected}")
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            r = json.loads(line)
            if roles is not None and r["role"] not in roles:
                continue
            r["features"] = rf.RequestFeatures(**r["features"])
            rows.append(r)
    return rows


def views(rows):
    """The fitted roles and evaluation views of D51, as lists of rows. Selection is by
    `role`, `slice` and the test flag only; no row is removed from the file."""
    def eligible(role):
        return [r for r in rows if r["role"] == role and r["slice"] is None]
    full = eligible("internal_test")
    return {
        "train": eligible("train"),
        "validation": eligible("validation"),
        "internal_test_full": full,
        "internal_test_feature_disjoint": [r for r in full if not r["meta_feature_vector_in_train"]],
        "unsupported_jwt": [r for r in rows if r["role"] == "internal_test"
                            and r["slice"] == "unsupported_jwt"],
        "unsupported_jwt_validation": [r for r in rows if r["role"] == "validation"
                                       and r["slice"] == "unsupported_jwt"],
    }


def block_rows(rows):
    """Rows of the category task: BLOCK and fitted (JWT has no category)."""
    return [r for r in rows if r["target_attack"] == 1 and r["target_category"] is not None]


def y_attack(rows):
    return np.array([r["target_attack"] for r in rows], dtype=np.int64)


def y_category(rows):
    index = {c: i for i, c in enumerate(CATEGORIES)}
    return np.array([index[r["target_category"]] for r in rows], dtype=np.int64)


# ── preprocessing ───────────────────────────────────────────────────────────
class FeatureEncoder:
    """RequestFeatures v2 -> float vector, columns in RequestFeatures field order.

    mode "linear" (logistic regression): counts -> log1p (if `log1p`), then every
        numeric column standardized with TRAIN mean / std; booleans 0/1; categoricals
        one-hot.
    mode "tree" (random forest, gradient boosting): numerics raw; booleans 0/1;
        categoricals one-hot. Nothing else.

    `method` and `content_type` get one column per value seen in TRAIN plus an `other`
    column for values never seen in TRAIN; `body_format` is its closed enum. Fitting reads
    only the rows it is given — call it with TRAIN, never with VALIDATION or test rows.
    `drop` removes RequestFeatures fields (the ablation); no field is ever added.
    """

    def __init__(self, mode, log1p=True, drop=()):
        if mode not in ("linear", "tree"):
            raise ValueError(f"mode must be 'linear' or 'tree', got {mode!r}")
        unknown = set(drop) - set(FEATURE_FIELDS)
        if unknown:
            raise ValueError(f"unknown fields to drop: {sorted(unknown)}")
        self.mode, self.log1p, self.drop = mode, bool(log1p) and mode == "linear", tuple(drop)
        self.fields = tuple(n for n in FEATURE_FIELDS if n not in self.drop)
        self.levels, self.mean, self.std = {}, {}, {}
        self.fitted = False

    def _numeric(self, name, value):
        v = float(value)
        if self.log1p and name in COUNT_FIELDS:
            v = math.log1p(v)
        return v

    def fit(self, records):
        records = list(records)
        if not records:
            raise ValueError("cannot fit on zero rows")
        for name in self.fields:
            if name in CATEGORICAL_FIELDS:
                self.levels[name] = (list(BODY_FORMATS) if name == "body_format" else
                                     sorted({getattr(r, name) for r in records}) + [OTHER])
            elif name not in BOOLEAN_FIELDS and self.mode == "linear":
                col = np.array([self._numeric(name, getattr(r, name)) for r in records])
                std = float(col.std())
                self.mean[name], self.std[name] = float(col.mean()), std if std > 0 else 1.0
        self.fitted = True
        return self

    @property
    def columns(self):
        out = []
        for name in self.fields:
            if name in CATEGORICAL_FIELDS:
                out += [f"{name}={v}" for v in self.levels[name]]
            else:
                out.append(name)
        return out

    def column_groups(self):
        """RequestFeatures field -> indices of its columns (for field-level importance)."""
        groups, i = {}, 0
        for name in self.fields:
            k = len(self.levels[name]) if name in CATEGORICAL_FIELDS else 1
            groups[name] = list(range(i, i + k))
            i += k
        return groups

    def encode_row(self, rec):
        if not self.fitted:
            raise RuntimeError("FeatureEncoder used before fit()")
        out = []
        for name in self.fields:
            value = getattr(rec, name)
            if name in CATEGORICAL_FIELDS:
                levels = self.levels[name]
                if value not in levels:
                    if name == "body_format":
                        raise ValueError(f"body_format {value!r} outside its closed enum")
                    value = OTHER
                out += [1.0 if v == value else 0.0 for v in levels]
            elif name in BOOLEAN_FIELDS:
                out.append(1.0 if value else 0.0)
            else:
                v = self._numeric(name, value)
                if self.mode == "linear":
                    v = (v - self.mean[name]) / self.std[name]
                out.append(v)
        return out

    def transform(self, records):
        return np.array([self.encode_row(r) for r in records], dtype=np.float64)

    def to_dict(self):
        return {"mode": self.mode, "log1p": self.log1p, "drop": list(self.drop),
                "fields": list(self.fields), "columns": self.columns,
                "levels": self.levels, "mean": self.mean, "std": self.std}

    @classmethod
    def from_dict(cls, d):
        enc = cls(d["mode"], d["log1p"], d["drop"])
        enc.levels, enc.mean, enc.std = d["levels"], d["mean"], d["std"]
        enc.fitted = True
        return enc


# ── models ──────────────────────────────────────────────────────────────────
FAMILY_MODE = {"logreg": "linear", "random_forest": "tree", "hist_gb": "tree"}


def make_model(family, params, seed=SEED):
    """An unfitted estimator. `params` holds only the hyperparameters that a grid
    varies (plus `log1p`, which belongs to the encoder); everything else is fixed here."""
    p = {k: v for k, v in params.items() if k != "log1p"}
    if family == "logreg":
        return LogisticRegression(max_iter=5000, random_state=seed, **p)
    if family == "random_forest":
        return RandomForestClassifier(n_jobs=-1, random_state=seed, **p)
    if family == "hist_gb":
        # early_stopping=False: the default would carve a random, row-level (not
        # group-aware) split out of TRAIN; the number of iterations is a grid value.
        return HistGradientBoostingClassifier(learning_rate=0.1, early_stopping=False,
                                              random_state=seed, **p)
    raise ValueError(f"unknown family {family!r}")


def make_encoder(family, params, drop=()):
    return FeatureEncoder(FAMILY_MODE[family], log1p=params.get("log1p", True), drop=drop)


def finalize_for_inference(model):
    """Single-threaded prediction (the benchmark measures one request at a time)."""
    inner = getattr(model, "estimator", None)
    for m in (model, getattr(inner, "estimator", inner)):
        if m is not None and hasattr(m, "n_jobs"):
            m.n_jobs = 1
    return model


# ── metrics ─────────────────────────────────────────────────────────────────
def _f(x):
    return None if x is None else float(round(x, 6))


def reliability_bins(y, p, n_bins=15):
    """Equal-width reliability table of P(attack) and its ECE / MCE."""
    y, p = np.asarray(y, dtype=float), np.asarray(p, dtype=float)
    idx = np.minimum((p * n_bins).astype(int), n_bins - 1)
    bins, ece, mce = [], 0.0, 0.0
    for b in range(n_bins):
        m = idx == b
        n = int(m.sum())
        if n == 0:
            bins.append({"bin": [b / n_bins, (b + 1) / n_bins], "n": 0})
            continue
        conf, freq = float(p[m].mean()), float(y[m].mean())
        gap = abs(conf - freq)
        ece += n / len(y) * gap
        mce = max(mce, gap)
        bins.append({"bin": [b / n_bins, (b + 1) / n_bins], "n": n,
                     "mean_predicted": _f(conf), "observed_frequency": _f(freq)})
    return {"n_bins": n_bins, "ece": _f(ece), "mce": _f(mce), "bins": bins}


EPS = 1e-15   # probability floor of the log losses (a 0 or 1 probability stays finite)


def binary_log_loss(y, p):
    p = np.clip(np.asarray(p, dtype=float), EPS, 1 - EPS)
    y = np.asarray(y, dtype=float)
    return float(-(y * np.log(p) + (1 - y) * np.log(1 - p)).mean())


def attack_metrics(y, p, threshold=REPORT_THRESHOLD, with_bins=True):
    y, p = np.asarray(y), np.asarray(p, dtype=float)
    pred = (p >= threshold).astype(int)
    tp = int(((pred == 1) & (y == 1)).sum()); tn = int(((pred == 0) & (y == 0)).sum())
    fp = int(((pred == 1) & (y == 0)).sum()); fn = int(((pred == 0) & (y == 1)).sum())
    pos, neg = tp + fn, tn + fp
    both = pos > 0 and neg > 0
    prec = tp / (tp + fp) if tp + fp else None
    rec = tp / pos if pos else None
    f1 = (None if prec is None or rec is None else
          2 * prec * rec / (prec + rec) if prec + rec else 0.0)
    out = {
        "n": int(len(y)), "positives": pos, "negatives": neg,
        "prevalence": _f(pos / len(y)) if len(y) else None, "threshold": threshold,
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "accuracy": _f((tp + tn) / len(y)) if len(y) else None,
        "precision": _f(prec), "recall": _f(rec),
        "f1": _f(f1),
        "fpr": _f(fp / neg) if neg else None, "fnr": _f(fn / pos) if pos else None,
        "roc_auc": _f(skm.roc_auc_score(y, p)) if both else None,
        "pr_auc": _f(skm.average_precision_score(y, p)) if both else None,
        "brier": _f(skm.brier_score_loss(y, p, pos_label=1)) if len(y) else None,
        "log_loss": _f(binary_log_loss(y, p)) if len(y) else None,
    }
    if with_bins:
        out["reliability"] = reliability_bins(y, p)
        out["ece"] = out["reliability"]["ece"]
    return out


def attack_metrics_group_weighted(y, p, groups, threshold=REPORT_THRESHOLD):
    """Diagnostic: every group (one logical request; e.g. a CSIC request repeated under
    many envelopes, which RequestFeatures cannot tell apart) weighs 1 in total."""
    y, p, groups = np.asarray(y), np.asarray(p, dtype=float), np.asarray(groups)
    _, inverse, counts = np.unique(groups, return_inverse=True, return_counts=True)
    w = 1.0 / counts[inverse]
    pred = p >= threshold
    tp, tn = w[pred & (y == 1)].sum(), w[~pred & (y == 0)].sum()
    fp, fn = w[pred & (y == 0)].sum(), w[~pred & (y == 1)].sum()
    both = (y == 1).any() and (y == 0).any()
    return {"n_groups": int(len(counts)), "largest_group_rows": int(counts.max()),
            "tp": _f(tp), "tn": _f(tn), "fp": _f(fp), "fn": _f(fn),
            "accuracy": _f((tp + tn) / w.sum()),
            "precision": _f(tp / (tp + fp)) if tp + fp else None,
            "recall": _f(tp / (tp + fn)) if tp + fn else None,
            "fpr": _f(fp / (fp + tn)) if fp + tn else None,
            "roc_auc": _f(skm.roc_auc_score(y, p, sample_weight=w)) if both else None,
            "pr_auc": _f(skm.average_precision_score(y, p, sample_weight=w)) if both else None,
            "brier": _f(float((w * (p - y) ** 2).sum() / w.sum()))}


def error_concentration(rows, p, group_key, threshold=REPORT_THRESHOLD, top=5):
    """Diagnostic: how many errors the largest error groups account for (offline
    metadata used only to describe them)."""
    from collections import Counter
    size = Counter(r[group_key] for r in rows)
    out = {}
    for kind, want_attack, want_pred in (("false_positives", 0, True), ("false_negatives", 1, False)):
        errs = [r for r, pi in zip(rows, p) if r["target_attack"] == want_attack
                and (pi >= threshold) == want_pred]
        by = Counter(r[group_key] for r in errs)
        tops = []
        for g, n in by.most_common(top):
            members = [r for r in rows if r[group_key] == g]
            tops.append({"group_rows": size[g], "errors": n,
                         "source": dict(Counter(r["meta_source"] for r in members)),
                         "v4_category": dict(Counter(r["meta_v4_category"] for r in members)),
                         "method": dict(Counter(r["features"].method for r in members))})
        out[kind] = {"errors": len(errs), "distinct_groups": len(by),
                     "top_groups": tops,
                     "share_in_top_2_groups": _f(sum(n for _, n in by.most_common(2)) / len(errs))
                     if errs else None}
    return out


def recall_by_reason(rows, p, threshold=REPORT_THRESHOLD, floor=30):
    """Attack recall per original V4 category (all 18 fitted BLOCK reasons, even those
    merged into other_attack), with the D18 support status."""
    out = {}
    for cat in sorted({r["meta_v4_category"] for r in rows if r["target_attack"] == 1}):
        idx = [i for i, r in enumerate(rows) if r["meta_v4_category"] == cat]
        hit = sum(p[i] >= threshold for i in idx)
        out[cat] = {"support": len(idx), "detected": int(hit), "recall": _f(hit / len(idx)),
                    "analyzer_category": rows[idx[0]]["target_category"],
                    "status": "OK" if len(idx) >= floor else "INSUFFICIENT DATA (support < 30)"}
    return out


def category_metrics(y, proba):
    """Single-label metrics over the 8 D47 categories (BLOCK rows only)."""
    y, proba = np.asarray(y), np.asarray(proba, dtype=float)
    pred = proba.argmax(axis=1)
    labels = list(range(len(CATEGORIES)))
    p, r, f, s = skm.precision_recall_fscore_support(y, pred, labels=labels, zero_division=0)
    top = proba.max(axis=1)
    correct = (pred == y).astype(float)
    onehot = np.eye(len(CATEGORIES))[y]
    return {
        "n": int(len(y)),
        "macro_f1": _f(skm.f1_score(y, pred, labels=labels, average="macro", zero_division=0)),
        "micro_f1": _f(skm.f1_score(y, pred, labels=labels, average="micro", zero_division=0)),
        "weighted_f1": _f(skm.f1_score(y, pred, labels=labels, average="weighted", zero_division=0)),
        "balanced_accuracy": _f(skm.balanced_accuracy_score(y, pred)),
        "per_class": {c: {"precision": _f(p[i]), "recall": _f(r[i]), "f1": _f(f[i]),
                          "support": int(s[i])} for i, c in enumerate(CATEGORIES)},
        "confusion_matrix": {"labels": list(CATEGORIES), "rows_true_cols_pred":
                             skm.confusion_matrix(y, pred, labels=labels).tolist()},
        "log_loss": _f(float(-np.log(np.clip(proba[np.arange(len(y)), y], EPS, 1)).mean())),
        "brier_multiclass": _f(float(((proba - onehot) ** 2).sum(axis=1).mean())),
        "mean_top1_probability": _f(float(top.mean())),
        "top1_reliability": reliability_bins(correct, top),
    }


def group_bootstrap(groups, stat, n_boot=1000, seed=SEED):
    """Percentile interval of `stat(index_array)` under resampling of whole groups."""
    rng = np.random.default_rng(seed)
    keys, inverse = np.unique(np.asarray(groups), return_inverse=True)
    members = [np.flatnonzero(inverse == k) for k in range(len(keys))]
    values = []
    for _ in range(n_boot):
        pick = rng.integers(0, len(keys), len(keys))
        values.append(stat(np.concatenate([members[k] for k in pick])))
    values = np.array([v for v in values if v is not None and np.isfinite(v)])
    return {"n_boot": n_boot, "n_groups": int(len(keys)),
            "ci95": [_f(np.percentile(values, 2.5)), _f(np.percentile(values, 97.5))],
            "mean": _f(values.mean())}


# ── the Analyzer ────────────────────────────────────────────────────────────
class AnalyzerModel:
    """One Analyzer candidate: features -> AnalyzerOutput (D50).

    attack:   encoder + model (+ calibrator; then `attack_model` is the calibrated wrapper)
    category: encoder + model over the 8 D47 categories, given attack
    """

    def __init__(self, version, attack_encoder, attack_model, category_encoder, category_model):
        self.version = version
        self.attack_encoder, self.attack_model = attack_encoder, attack_model
        self.category_encoder, self.category_model = category_encoder, category_model
        order = list(getattr(category_model, "classes_", range(len(CATEGORIES))))
        if order != list(range(len(CATEGORIES))):
            raise ValueError(f"category model classes {order} != the 8 D47 categories")
        self._shared = attack_encoder.to_dict() == category_encoder.to_dict()

    def attack_proba(self, records):
        return self.attack_model.predict_proba(self.attack_encoder.transform(records))[:, 1]

    def category_proba(self, records):
        return self.category_model.predict_proba(self.category_encoder.transform(records))

    def analyze(self, features):
        """One request -> AnalyzerOutput. The contract validates every signal."""
        xa = np.array([self.attack_encoder.encode_row(features)])
        xc = xa if self._shared else np.array([self.category_encoder.encode_row(features)])
        attack = float(self.attack_model.predict_proba(xa)[0, 1])
        cat = self.category_model.predict_proba(xc)[0]
        signals = {contracts.ATTACK: min(1.0, max(0.0, attack))}
        signals.update({contracts.CATEGORY_PREFIX + c: float(cat[i])
                        for i, c in enumerate(CATEGORIES)})
        return contracts.AnalyzerOutput(signals, self.version)
