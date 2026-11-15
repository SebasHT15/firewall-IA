"""
firewall-IA — Hybrid Architecture Phase 2B: Analyzer baselines and evaluation (Issue #53).

Stages, in this order (research environment only; see hybrid_analyzer.py):

  select   fits every pre-declared configuration on TRAIN, scores it on VALIDATION,
           selects one configuration per family, chooses the `attack` calibration by
           group cross-validation inside VALIDATION, runs the mandatory category ablation
           (D46), field-level permutation importance and paired bootstrap intervals, and
           saves one Analyzer per family. INTERNAL TEST is not read. Re-runnable (it is
           deterministic) until `freeze`.
  bench    latency / footprint of every saved Analyzer, each in a fresh single-threaded
           process, on VALIDATION requests.
  freeze   records the winning family for `attack` and for category, with the SHA-256 of
           every model and of the validation / latency evidence. After it, `select` refuses.
  test     the single INTERNAL TEST evaluation of the frozen models: internal_test_full,
           internal_test_feature_disjoint and unsupported_jwt. Refuses to run twice.

Two runs share this code (`--run`, default run-001 so the run-001 commands stay valid):

  run-001  hybrid_analyzer_v1 (D51) -> reports/hybrid/phase2b-analyzer-baselines/; its test was
           the first look at INTERNAL TEST. Kept as historical evidence; never re-run.
  run-002  hybrid_analyzer_v2 (D54) -> reports/hybrid/phase2b-analyzer-v2-run-002/; winner
           chosen by a pre-declared mechanical rule; its test is labelled
           "SECOND-LOOK INTERNAL EVALUATION AFTER METHODOLOGY CORRECTION — NOT AN UNTOUCHED TEST".

`select` and `bench` load only TRAIN and VALIDATION rows. External Test v1 is never read (D53).

RUN (repository root; add `--run run-002` before the stage for run-002):
    .venv-analyzer/bin/python scripts/training/run_hybrid_analyzer_baselines.py select
    .venv-analyzer/bin/python scripts/training/run_hybrid_analyzer_baselines.py bench
    .venv-analyzer/bin/python scripts/training/run_hybrid_analyzer_baselines.py freeze \
        --attack <family> --category <family> --rationale "..."
    .venv-analyzer/bin/python scripts/training/run_hybrid_analyzer_baselines.py test
"""

import argparse
import hashlib
import json
import math
import os
import pickle
import platform
import resource
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(REPO_ROOT, "data_plane"))

SECOND_LOOK_LABEL = ("SECOND-LOOK INTERNAL EVALUATION AFTER METHODOLOGY CORRECTION — "
                     "NOT AN UNTOUCHED TEST")
RUNS = {
    "run-001": {"dataset": "hybrid_analyzer_v1",
                "report_dir": os.path.join("reports", "hybrid", "phase2b-analyzer-baselines"),
                "model_dir": "model-output-hybrid-analyzer-v1",
                "calibration_logloss_guard": False,
                "test_group_key": "meta_canonical_request_sha256",
                "test_label": "INTERNAL TEST run-001 (first look)",
                "winner_rule": "judgement"},
    "run-002": {"dataset": "hybrid_analyzer_v2",
                "report_dir": os.path.join("reports", "hybrid", "phase2b-analyzer-v2-run-002"),
                "model_dir": "model-output-hybrid-analyzer-v2",
                "calibration_logloss_guard": True,
                "test_group_key": "meta_group_id",
                "test_label": SECOND_LOOK_LABEL,
                "winner_rule": "mechanical"},
}
RUN_NAME = "run-001"
RUN = RUNS[RUN_NAME]
REPORT_DIR = os.path.join(REPO_ROOT, RUN["report_dir"])
MODEL_DIR = os.path.join(REPO_ROOT, RUN["model_dir"])
DEV_ROLES = ("train", "validation")


def configure(run_name):
    """Point every stage at one run's dataset, report folder and model folder."""
    global RUN_NAME, RUN, REPORT_DIR, MODEL_DIR
    RUN_NAME, RUN = run_name, RUNS[run_name]
    REPORT_DIR = os.path.join(REPO_ROOT, RUN["report_dir"])
    MODEL_DIR = os.path.join(REPO_ROOT, RUN["model_dir"])


def dataset_paths():
    name = RUN["dataset"]
    return (os.path.join(REPO_ROOT, "datasets", name, f"{name}.jsonl"),
            os.path.join(REPO_ROOT, "datasets", f"manifest_{name}.json"))


def analyzer_version(suffix):
    return f"hybrid-analyzer-{RUN['dataset'].rsplit('_', 1)[1]}/{suffix}"


V4_TRAIN = os.path.join(REPO_ROOT, "datasets", "v4_clean", "train.jsonl")

FAMILIES = ("logreg", "random_forest", "hist_gb")

# ── pre-declared configurations (the complete list of what is tried) ────────
# Each family: its library default (or nearest) plus a few justified variations.
# `log1p` belongs to the linear encoder; the C=1 / log1p=False row is the check of
# whether log1p of the counts helps at all (Phase 2A plan item 2).
ATTACK_GRID = {
    "logreg": [{"C": 0.01, "log1p": True}, {"C": 0.1, "log1p": True},
               {"C": 1.0, "log1p": True}, {"C": 10.0, "log1p": True},
               {"C": 1.0, "log1p": False}],
    "random_forest": [{"n_estimators": n, "min_samples_leaf": leaf}
                      for leaf in (1, 5) for n in (100, 300)],
    "hist_gb": [{"max_iter": it, "max_leaf_nodes": leaves}
                for it in (100, 300) for leaves in (15, 31)],
}
CATEGORY_GRID = {
    "logreg": [{"C": c, "class_weight": cw, "log1p": True}
               for cw in (None, "balanced") for c in (0.1, 1.0, 10.0)]
              + [{"C": 1.0, "class_weight": None, "log1p": False}],
    "random_forest": [{"n_estimators": n, "class_weight": cw}
                      for cw in (None, "balanced_subsample") for n in (100, 300)],
    "hist_gb": [{"max_iter": it, "class_weight": cw}
                for cw in (None, "balanced") for it in (100, 300)],
}
# Optional small MLP (issue item 11): NOT trained. Decided on VALIDATION after the first
# select run: the attack gap left by the trees is small and concentrated in a few groups,
# and the category ceiling comes from the labels (synthetic-endpoint confounding, D46),
# which a different function class does not address. See the report README.
MLP_DECISION = ("not trained: tree families reach VALIDATION group-weighted attack ROC-AUC "
                "~0.995; remaining attack errors concentrate in a few groups; category limits "
                "are label/endpoint-bound (D46 ablation), not capacity-bound")

ABLATIONS = {
    # D46 mandatory: VALIDATION and INTERNAL TEST
    "path": ("path_length", "path_depth"),
    # diagnostic only (VALIDATION): slash_count also counts the path's slashes
    "path_and_slash_diagnostic": ("path_length", "path_depth", "slash_count"),
}
CALIBRATION_METHODS = ("native", "sigmoid", "isotonic")
CALIBRATION_FOLDS = 5
CALIBRATION_SALT = "hybrid-analyzer-v1-calibration-cv"
STABILITY_SEEDS = (1, 2)
N_BOOT = 1000
PERMUTATION_REPEATS = 5
BENCH_WARMUP = 500
BENCH_PASSES = 2

SELECTION_RULES = {
    "attack": "per family, highest VALIDATION ROC-AUC; ties (6 decimals) -> lowest Brier; "
              "then first in grid order",
    "category": "per family, highest VALIDATION macro-F1; ties (6 decimals) -> lowest "
                "log loss; then first in grid order",
    "calibration": "per family, out-of-fold predictions over 5 group folds of VALIDATION for "
                   "native / sigmoid / isotonic, in that order of complexity; start from native "
                   "and move to the next more complex method only if its paired group-bootstrap "
                   "95% interval of the OOF Brier difference (candidate - current) lies entirely "
                   "below 0; the chosen calibrator is then refit on all of VALIDATION",
    "calibration_amendment": "the first select run used 'lowest mean OOF Brier'. It picked "
                             "isotonic for random_forest by 0.0003 Brier over sigmoid, inside the "
                             "fold-to-fold spread, which does not satisfy the issue's rule that a "
                             "technique without enough statistical support is not used. The rule "
                             "above implements that requirement; amended on VALIDATION evidence "
                             "only, before INTERNAL TEST was read",
    "diagnostics": "group-weighted attack metrics (each VALIDATION group / INTERNAL TEST "
                   "canonical request weighs 1) and error concentration per group are reported "
                   "next to the row-level metrics; they are not selection criteria (added after "
                   "the first select run showed 281 of one model's 325 VALIDATION false positives "
                   "in two CSIC benign groups; declared before INTERNAL TEST was read)",
    "winner": "not mechanical: attack quality, feature-disjoint generalization, calibration, "
              "category, latency, size, memory, deployment, stability, interpretability "
              "(issue item 22); recorded by `freeze` before INTERNAL TEST is read",
}


# run-002: declared before any hybrid_analyzer_v2 model was fitted.
SELECTION_RULES_RUN_002 = {
    "attack (per family)": SELECTION_RULES["attack"],
    "category (per family)": SELECTION_RULES["category"],
    "calibration": SELECTION_RULES["calibration"] + "; AND the candidate's OOF log loss must "
                   "not exceed the current method's (log-loss guard)",
    "calibration_guard_origin": "added for run-002 at the owner's instruction to be careful "
                                "with isotonic after run-001, where isotonic produced exact 0/1 "
                                "probabilities (seen on VALIDATION before run-001's test) and "
                                "tripled log loss on INTERNAL TEST (seen in run-001's test). "
                                "It is therefore informed by the first INTERNAL TEST look; "
                                "recorded as such (D54)",
    "winner_attack": "mechanical: among the three families' selected + calibrated models, the "
                     "lowest VALIDATION calibrated-OOF Brier is 'best'; every family whose paired "
                     "group-bootstrap 95% interval of (Brier family - Brier best) includes 0 is "
                     "statistically tied with it; among the tied, the lowest bench attack-"
                     "inference P50 wins (then smaller artifact)",
    "winner_category": "mechanical: highest VALIDATION macro-F1 is 'best'; families whose paired "
                       "group-bootstrap 95% interval of (macro-F1 family - macro-F1 best) includes "
                       "0 are tied; among the tied, the lowest bench category-inference P50 wins "
                       "(then smaller artifact)",
    "diagnostics": "row-weighted metrics are the reported metrics; group-weighted (each D54 group "
                   "weighs 1) and error concentration are reported next to them as a standing "
                   "diagnostic, never as a selection criterion",
    "threshold": "0.5 is a reporting-only threshold for confusion counts; it is not the "
                 "firewall's operating point (decided later with the Small Decision Model)",
    "grids": "unchanged from run-001 (same families, same configurations); no MLP",
    "second_look": "INTERNAL TEST is read once, after `freeze`, and labelled: " + SECOND_LOOK_LABEL,
}


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def write_json(name, obj):
    os.makedirs(REPORT_DIR, exist_ok=True)
    path = os.path.join(REPORT_DIR, name)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False, default=_json_default)
        f.write("\n")
    return path


def _json_default(o):
    import numpy as np
    if isinstance(o, (np.integer,)):
        return int(o)
    if isinstance(o, (np.floating,)):
        return float(o)
    if isinstance(o, tuple):
        return list(o)
    raise TypeError(type(o))


def config_id(family, params):
    return family + ":" + ",".join(f"{k}={v}" for k, v in params.items())


def environment():
    import joblib
    import numpy
    import scipy
    import sklearn
    import threadpoolctl
    cpu = ""
    try:
        cpu = next(line.split(":", 1)[1].strip() for line in open("/proc/cpuinfo")
                   if line.startswith("model name"))
    except (OSError, StopIteration):
        pass
    return {"python": platform.python_version(), "numpy": numpy.__version__,
            "scikit_learn": sklearn.__version__, "scipy": scipy.__version__,
            "joblib": joblib.__version__, "threadpoolctl": threadpoolctl.__version__,
            "platform": platform.platform(), "cpu": cpu, "logical_cpus": os.cpu_count(),
            "interpreter": sys.executable}


# ── select ──────────────────────────────────────────────────────────────────
def fit_eval(ha, task, family, params, data, drop=(), seed=None):
    """Fit encoder (TRAIN only) and model on TRAIN; return (encoder, model, VALIDATION
    probabilities, seconds to fit)."""
    import numpy as np
    seed = ha.SEED if seed is None else seed
    train, val = data[task]["train"], data[task]["validation"]
    enc = ha.make_encoder(family, params, drop).fit([r["features"] for r in train])
    x_tr = enc.transform([r["features"] for r in train])
    x_va = enc.transform([r["features"] for r in val])
    y_tr = data[task]["y_train"]
    model = ha.make_model(family, params, seed)
    t0 = time.perf_counter()
    model.fit(x_tr, y_tr)
    fit_s = time.perf_counter() - t0
    # Predict single-threaded: a parallel forest sums tree votes in thread order, which
    # changes the last bits of the probabilities and, through them, the calibrator.
    ha.finalize_for_inference(model)
    proba = model.predict_proba(x_va)
    proba = proba[:, 1] if task == "attack" else proba
    return enc, model, np.asarray(proba), fit_s, x_va


def select_best(task, results):
    if task == "attack":
        key = lambda r: (-round(r["metrics"]["roc_auc"], 6), r["metrics"]["brier"])  # noqa: E731
    else:
        key = lambda r: (-round(r["metrics"]["macro_f1"], 6), r["metrics"]["log_loss"])  # noqa: E731
    return min(enumerate(results), key=lambda ir: (key(ir[1]), ir[0]))[1]


def calibration_cv(ha, model, x_val, y_val, groups):
    """Out-of-fold comparison of native / sigmoid / isotonic inside VALIDATION."""
    import numpy as np
    from sklearn.calibration import CalibratedClassifierCV
    from sklearn.frozen import FrozenEstimator
    folds = np.array([int.from_bytes(hashlib.sha256(f"{CALIBRATION_SALT}\x00{g}".encode())
                                     .digest()[:8], "big") % CALIBRATION_FOLDS for g in groups])
    out, oof_by_method = {}, {}
    for method in CALIBRATION_METHODS:
        oof = np.empty(len(y_val))
        fold_brier = []
        for k in range(CALIBRATION_FOLDS):
            te, tr = folds == k, folds != k
            if method == "native":
                oof[te] = model.predict_proba(x_val[te])[:, 1]
            else:
                cal = CalibratedClassifierCV(FrozenEstimator(model), method=method)
                cal.fit(x_val[tr], y_val[tr])
                oof[te] = cal.predict_proba(x_val[te])[:, 1]
            fold_brier.append(float(np.mean((oof[te] - y_val[te]) ** 2)))
        m = ha.attack_metrics(y_val, oof)
        out[method] = {"oof_brier": m["brier"], "oof_log_loss": m["log_loss"],
                       "oof_ece": m["ece"], "oof_roc_auc": m["roc_auc"],
                       "oof_exactly_0": int((oof == 0).sum()), "oof_exactly_1": int((oof == 1).sum()),
                       "oof_errors_at_exactly_0_or_1": int(((oof == 1) & (y_val == 0)).sum()
                                                           + ((oof == 0) & (y_val == 1)).sum()),
                       "fold_brier": [round(b, 6) for b in fold_brier],
                       "fold_rows": [int((folds == k).sum()) for k in range(CALIBRATION_FOLDS)],
                       "oof_reliability": m["reliability"]}
        oof_by_method[method] = oof
    chosen, steps = CALIBRATION_METHODS[0], []
    for candidate in CALIBRATION_METHODS[1:]:
        cur, new = oof_by_method[chosen], oof_by_method[candidate]
        ci = ha.group_bootstrap(groups, lambda i, cur=cur, new=new: float(
            np.mean((new[i] - y_val[i]) ** 2) - np.mean((cur[i] - y_val[i]) ** 2)), N_BOOT)
        guard_ok = (not RUN["calibration_logloss_guard"]
                    or out[candidate]["oof_log_loss"] <= out[chosen]["oof_log_loss"])
        adopt = ci["ci95"][1] < 0 and guard_ok
        steps.append({"candidate": candidate, "versus": chosen,
                      "oof_brier_diff (candidate - current)": ci,
                      "oof_log_loss (candidate, current)": [out[candidate]["oof_log_loss"],
                                                            out[chosen]["oof_log_loss"]],
                      "log_loss_guard": RUN["calibration_logloss_guard"],
                      "adopted": adopt})
        if adopt:
            chosen = candidate
    out["selection_steps"] = steps
    if chosen == "native":
        final = model
    else:
        final = CalibratedClassifierCV(FrozenEstimator(model), method=chosen).fit(x_val, y_val)
        assert len(final.calibrated_classifiers_) == 1
    return out, chosen, final, oof_by_method[chosen]


def field_importance(ha, task, model, enc, x, y, seed=0):
    """Field-level permutation importance on VALIDATION: the columns of one
    RequestFeatures field are permuted together (one-hot blocks stay whole)."""
    import numpy as np
    rng = np.random.default_rng(seed)

    def score(xm):
        p = model.predict_proba(xm)
        if task == "attack":
            m = ha.attack_metrics(y, p[:, 1], with_bins=False)
            return m["roc_auc"], m["log_loss"]
        m = ha.category_metrics(y, p)
        return m["macro_f1"], m["log_loss"]

    base_main, base_ll = score(x)
    out = {}
    for field, cols in enc.column_groups().items():
        drops, lls = [], []
        for _ in range(PERMUTATION_REPEATS):
            perm = rng.permutation(len(x))
            xp = x.copy()
            xp[:, cols] = x[perm][:, cols]
            s, ll = score(xp)
            drops.append(base_main - s)
            lls.append(ll - base_ll)
        out[field] = {("roc_auc_drop" if task == "attack" else "macro_f1_drop"):
                      round(float(np.mean(drops)), 6),
                      "log_loss_increase": round(float(np.mean(lls)), 6),
                      "log_loss_increase_sd": round(float(np.std(lls)), 6)}
    ranked = sorted(out.items(), key=lambda kv: -kv[1]["log_loss_increase"])
    return {"metric_base": {"main": base_main, "log_loss": base_ll},
            "repeats": PERMUTATION_REPEATS, "ranked_by": "log_loss_increase",
            "fields": dict(ranked)}


def logreg_coefficients(model, enc, task, top=12):
    import numpy as np
    names = enc.columns
    if task == "attack":
        coef = model.coef_[0]
        order = np.argsort(-np.abs(coef))[:top]
        return {"space": "standardized encoder columns (log1p counts)" if enc.log1p
                else "standardized encoder columns",
                "intercept": float(model.intercept_[0]),
                "top_abs": [{"column": names[i], "coef": round(float(coef[i]), 4)} for i in order]}
    out = {}
    import hybrid_analyzer as ha
    for k, c in enumerate(ha.CATEGORIES):
        coef = model.coef_[k]
        order = np.argsort(-coef)[:6]
        out[c] = [{"column": names[i], "coef": round(float(coef[i]), 4)} for i in order]
    return {"space": "standardized encoder columns", "top_positive_per_class": out}


def paired_bootstrap(ha, task, groups, y, probs, reference="logreg"):
    """Group-bootstrap interval of (family - reference) for the headline metrics."""
    import numpy as np
    from sklearn import metrics as skm
    out = {}
    for fam, p in probs.items():
        if fam == reference:
            continue
        if task == "attack":
            stats = {
                "roc_auc_diff": lambda i, p=p: (skm.roc_auc_score(y[i], p[i])
                                                - skm.roc_auc_score(y[i], probs[reference][i]))
                if len(set(y[i])) == 2 else None,
                "brier_diff": lambda i, p=p: float(np.mean((p[i] - y[i]) ** 2)
                                                   - np.mean((probs[reference][i] - y[i]) ** 2)),
            }
        else:
            labels = list(range(len(ha.CATEGORIES)))
            stats = {"macro_f1_diff": lambda i, p=p: (
                skm.f1_score(y[i], p[i].argmax(1), labels=labels, average="macro", zero_division=0)
                - skm.f1_score(y[i], probs[reference][i].argmax(1), labels=labels,
                               average="macro", zero_division=0))}
        out[f"{fam} - {reference}"] = {name: ha.group_bootstrap(groups, s, N_BOOT)
                                       for name, s in stats.items()}
    return out


def prepare(ha, rows):
    import numpy as np
    v = ha.views(rows)
    data = {"attack": {}, "category": {}}
    for role in ("train", "validation"):
        data["attack"][role] = v[role]
        data["category"][role] = ha.block_rows(v[role])
    for task, yf in (("attack", ha.y_attack), ("category", ha.y_category)):
        data[task]["y_train"] = yf(data[task]["train"])
        data[task]["y_validation"] = yf(data[task]["validation"])
        data[task]["groups_validation"] = np.array([r["meta_group_id"]
                                                    for r in data[task]["validation"]])
    return v, data


def cmd_select(args):
    import numpy as np
    import hybrid_analyzer as ha
    if os.path.exists(os.path.join(REPORT_DIR, "frozen_selection.json")):
        raise SystemExit("FATAL: the selection is frozen; `select` would change frozen models")
    families, attack_grid, category_grid = FAMILIES, ATTACK_GRID, CATEGORY_GRID

    path, manifest_path = dataset_paths()
    rows = ha.load_dataset(path, manifest_path, roles=DEV_ROLES)
    assert {r["role"] for r in rows} <= set(DEV_ROLES), "select must not hold INTERNAL TEST rows"
    v, data = prepare(ha, rows)
    manifest = json.load(open(manifest_path))
    config = {
        "issue": 53, "run": RUN_NAME, "created_utc": now(),
        "stage_order": ["select", "bench", "freeze", "test"],
        "dataset": {"name": RUN["dataset"],
                    "manifest": os.path.relpath(manifest_path, REPO_ROOT),
                    "manifest_sha256": sha256_file(manifest_path),
                    "grouping": manifest.get("grouping"), "validation_split": manifest.get("validation"),
                    "artifact_sha256": manifest["artifact"]["sha256"],
                    "feature_schema": manifest["feature_schema"],
                    "target_schema": manifest["target_schema"]},
        "fitted_rows": {"attack": {r: len(data["attack"][r]) for r in ("train", "validation")},
                        "category": {r: len(data["category"][r]) for r in ("train", "validation")}},
        "model_input": "RequestFeatures v2 only (34 fields); no meta_ field",
        "preprocessing": {
            "linear (logreg)": "int counts -> log1p (grid-checked) -> standardize with TRAIN "
                                    "mean/std; float ratios -> standardize; booleans 0/1 (not "
                                    "scaled); method / content_type one-hot over TRAIN values + "
                                    "`__other__`; body_format one-hot over its closed enum",
            "tree (random_forest, hist_gb)": "numerics raw; booleans 0/1; same one-hot; nothing else",
            "fit": "TRAIN rows only (attack: all fitted TRAIN rows; category: TRAIN BLOCK rows)",
        },
        "families": list(families),
        "mlp": MLP_DECISION,
        "attack_grid": attack_grid, "category_grid": category_grid,
        "fixed_hyperparameters": {
            "logreg": "lbfgs, max_iter=5000, L2", "random_forest": "max_features='sqrt' (default), "
            "bootstrap, n_jobs=-1 to fit / 1 to predict",
            "hist_gb": "learning_rate=0.1, early_stopping=False, other defaults"},
        "seed": ha.SEED, "stability_seeds": list(STABILITY_SEEDS),
        "selection_rules": SELECTION_RULES if RUN_NAME == "run-001" else SELECTION_RULES_RUN_002,
        "feature_order": list(ha.FEATURE_FIELDS),
        "calibration": {"methods": list(CALIBRATION_METHODS), "folds": CALIBRATION_FOLDS,
                        "fold_assignment": f"sha256('{CALIBRATION_SALT}' NUL meta_group_id)[:8] % 5"},
        "ablations": {k: list(d) for k, d in ABLATIONS.items()},
        "reporting_threshold": ha.REPORT_THRESHOLD,
        "bootstrap": {"n_boot": N_BOOT, "unit": "VALIDATION group (meta_group_id); INTERNAL "
                      f"TEST {RUN['test_group_key']}"},
        "internal_test_rows_loaded_by_select": 0,
        "permutation_importance": {"repeats": PERMUTATION_REPEATS, "data": "VALIDATION",
                                   "unit": "RequestFeatures field (all its encoder columns)"},
        "external_test_v1": "not read (D53)",
        "environment": environment(),
    }
    write_json("experiment_config.json", config)

    out = {"stage": "select", "run": RUN_NAME, "created_utc": now(), "internal_test_read": False,
           "baselines": {}, "attack": {}, "category": {}, "ablation": {}, "interpretability": {}}

    # floor baselines
    ya_tr, ya_va = data["attack"]["y_train"], data["attack"]["y_validation"]
    prior = float(ya_tr.mean())
    out["baselines"]["attack_prior"] = {
        "description": "P(attack) = TRAIN prevalence for every row; majority class at 0.5",
        "train_prevalence": round(prior, 6),
        "validation": ha.attack_metrics(ya_va, np.full(len(ya_va), prior), with_bins=False)}
    yc_tr, yc_va = data["category"]["y_train"], data["category"]["y_validation"]
    freq = np.bincount(yc_tr, minlength=len(ha.CATEGORIES)) / len(yc_tr)
    out["baselines"]["category_majority"] = {
        "description": "always the most frequent TRAIN category; probabilities = TRAIN frequencies",
        "majority": ha.CATEGORIES[int(freq.argmax())],
        "train_frequencies": {c: round(float(freq[i]), 6) for i, c in enumerate(ha.CATEGORIES)},
        "validation": ha.category_metrics(yc_va, np.tile(freq, (len(yc_va), 1)))}
    tr_vec = {r["meta_feature_vector_sha256"] for r in data["attack"]["train"]}
    out["baselines"]["feature_vector_lookup_diagnostic"] = {
        "description": "memorization / leakage diagnostic, not a candidate: VALIDATION rows "
                       "whose exact feature vector occurs in TRAIN",
        "validation_rows_covered": sum(r["meta_feature_vector_sha256"] in tr_vec
                                       for r in data["attack"]["validation"])}

    selected, saved = {}, {}
    oof_probs, cat_probs = {}, {}
    for task, grid in (("attack", attack_grid), ("category", category_grid)):
        y_va = data[task]["y_validation"]
        for fam in families:
            results = []
            for params in grid[fam]:
                enc, model, proba, fit_s, x_va = fit_eval(ha, task, fam, params, data)
                m = (ha.attack_metrics(y_va, proba, with_bins=False) if task == "attack"
                     else {k: v for k, v in ha.category_metrics(y_va, proba).items()
                           if k not in ("top1_reliability",)})
                results.append({"config": config_id(fam, params), "params": params,
                                "fit_seconds": round(fit_s, 3), "metrics": m,
                                "_obj": (enc, model, proba, x_va)})
                print(f"[{task}] {config_id(fam, params)}: "
                      + (f"roc_auc={m['roc_auc']} brier={m['brier']}" if task == "attack"
                         else f"macro_f1={m['macro_f1']} log_loss={m['log_loss']}"), flush=True)
            best = select_best(task, results)
            enc, model, proba, x_va = best.pop("_obj")
            for r in results:
                r.pop("_obj", None)
            entry = {"configs": results, "selected": best["config"],
                     "selected_params": best["params"]}
            # stability of the selected configuration across seeds
            if fam != "logreg":
                seeds = {}
                for s in STABILITY_SEEDS:
                    _, _, p_s, _, _ = fit_eval(ha, task, fam, best["params"], data, seed=s)
                    ms = (ha.attack_metrics(y_va, p_s, with_bins=False) if task == "attack"
                          else ha.category_metrics(y_va, p_s))
                    seeds[s] = ({"roc_auc": ms["roc_auc"], "brier": ms["brier"]} if task == "attack"
                                else {"macro_f1": ms["macro_f1"], "log_loss": ms["log_loss"]})
                entry["seed_stability"] = {ha.SEED: ({"roc_auc": best["metrics"]["roc_auc"],
                                                      "brier": best["metrics"]["brier"]}
                                                     if task == "attack" else
                                                     {"macro_f1": best["metrics"]["macro_f1"],
                                                      "log_loss": best["metrics"]["log_loss"]}),
                                           **seeds}
            else:
                entry["seed_stability"] = "deterministic (lbfgs, convex)"
            if task == "attack":
                cal, chosen, final, oof = calibration_cv(
                    ha, model, x_va, y_va, data["attack"]["groups_validation"])
                entry["calibration_cv"] = cal
                entry["calibration_chosen"] = chosen
                entry["validation_native"] = ha.attack_metrics(y_va, proba)
                entry["validation_recall_by_reason_native"] = ha.recall_by_reason(
                    data["attack"]["validation"], proba)
                entry["validation_calibrated_oof"] = ha.attack_metrics(y_va, oof)
                g_va = data["attack"]["groups_validation"]
                entry["validation_group_weighted (diagnostic)"] = {
                    "native": ha.attack_metrics_group_weighted(y_va, proba, g_va),
                    "calibrated_oof": ha.attack_metrics_group_weighted(y_va, oof, g_va)}
                entry["validation_error_concentration_native (diagnostic)"] = ha.error_concentration(
                    data["attack"]["validation"], proba, "meta_group_id")
                oof_probs[fam] = oof
                selected[("attack", fam)] = (enc, final, model, x_va)
            else:
                entry["validation"] = ha.category_metrics(y_va, proba)
                cat_probs[fam] = proba
                selected[("category", fam)] = (enc, model, None, x_va)
            out[task][fam] = entry

    # mandatory category ablation (D46) + diagnostic: same grid, same selection rule
    y_va = data["category"]["y_validation"]
    abl_models = {}
    for name, drop in ABLATIONS.items():
        out["ablation"][name] = {"dropped_fields": list(drop), "families": {}}
        for fam in families:
            results = []
            for params in category_grid[fam]:
                enc, model, proba, fit_s, _ = fit_eval(ha, "category", fam, params, data, drop=drop)
                m = ha.category_metrics(y_va, proba)
                results.append({"config": config_id(fam, params), "params": params,
                                "metrics": m, "_obj": (enc, model)})
                print(f"[ablation {name}] {config_id(fam, params)}: macro_f1={m['macro_f1']}",
                      flush=True)
            best = select_best("category", results)
            enc, model = best.pop("_obj")
            for r in results:
                r.pop("_obj", None)
            full = out["category"][fam]["validation"]
            abl = best["metrics"]
            out["ablation"][name]["families"][fam] = {
                "configs": [{"config": r["config"], "macro_f1": r["metrics"]["macro_f1"]}
                            for r in results],
                "selected": best["config"],
                "validation_full_features": {"config": out["category"][fam]["selected"],
                                             "macro_f1": full["macro_f1"],
                                             "micro_f1": full["micro_f1"]},
                "validation_ablation": abl,
                "delta_macro_f1": round(abl["macro_f1"] - full["macro_f1"], 6),
                "delta_micro_f1": round(abl["micro_f1"] - full["micro_f1"], 6),
                "delta_f1_per_class": {c: round(abl["per_class"][c]["f1"] - full["per_class"][c]["f1"], 6)
                                       for c in ha.CATEGORIES},
                "delta_confusion_matrix": (np.array(abl["confusion_matrix"]["rows_true_cols_pred"])
                                           - np.array(full["confusion_matrix"]["rows_true_cols_pred"])).tolist(),
            }
            if name == "path":
                abl_models[fam] = (enc, model)

    # interpretability of every selected model (VALIDATION)
    for fam in families:
        enc, _, native, x_va = selected[("attack", fam)]
        ya = data["attack"]["y_validation"]
        interp = {"attack_permutation": field_importance(ha, "attack", native, enc, x_va, ya)}
        enc_c, model_c, _, x_vc = selected[("category", fam)]
        interp["category_permutation"] = field_importance(ha, "category", model_c, enc_c, x_vc,
                                                          data["category"]["y_validation"])
        if fam == "logreg":
            interp["attack_coefficients"] = logreg_coefficients(native, enc, "attack")
            interp["category_coefficients"] = logreg_coefficients(model_c, enc_c, "category")
        out["interpretability"][fam] = interp
        print(f"[importance] {fam} done", flush=True)

    out["paired_bootstrap_validation"] = {
        "attack (calibrated out-of-fold probabilities)": paired_bootstrap(
            ha, "attack", data["attack"]["groups_validation"], data["attack"]["y_validation"],
            oof_probs),
        "category (macro-F1)": paired_bootstrap(
            ha, "category", data["category"]["groups_validation"],
            data["category"]["y_validation"], cat_probs)}
    # every ordered pair, for the run-002 mechanical winner rule
    out["paired_bootstrap_validation_all_pairs"] = {
        "attack (calibrated out-of-fold probabilities)": {
            ref: paired_bootstrap(ha, "attack", data["attack"]["groups_validation"],
                                  data["attack"]["y_validation"], oof_probs, reference=ref)
            for ref in families},
        "category (macro-F1)": {
            ref: paired_bootstrap(ha, "category", data["category"]["groups_validation"],
                                  data["category"]["y_validation"], cat_probs, reference=ref)
            for ref in families}}
    out["unsupported_jwt_validation_rows"] = len(v["unsupported_jwt_validation"])

    # save one Analyzer per family + the ablated category models
    os.makedirs(MODEL_DIR, exist_ok=True)
    preprocessing = {}
    for fam in families:
        enc_a, final_a, _, _ = selected[("attack", fam)]
        enc_c, model_c, _, _ = selected[("category", fam)]
        analyzer = ha.AnalyzerModel(analyzer_version(fam),
                                    enc_a, ha.finalize_for_inference(final_a),
                                    enc_c, ha.finalize_for_inference(model_c))
        path = os.path.join(MODEL_DIR, f"{fam}.pkl")
        with open(path, "wb") as f:
            pickle.dump(analyzer, f, protocol=5)
        enc_ab, model_ab = abl_models[fam]
        path_ab = os.path.join(MODEL_DIR, f"{fam}_category_path_ablation.pkl")
        with open(path_ab, "wb") as f:
            pickle.dump({"encoder": enc_ab, "model": ha.finalize_for_inference(model_ab)}, f,
                        protocol=5)
        saved[fam] = {"analyzer": {"path": os.path.relpath(path, REPO_ROOT),
                                   "bytes": os.path.getsize(path), "sha256": sha256_file(path)},
                      "category_path_ablation": {"path": os.path.relpath(path_ab, REPO_ROOT),
                                                 "bytes": os.path.getsize(path_ab),
                                                 "sha256": sha256_file(path_ab)}}
        preprocessing[fam] = {"attack": enc_a.to_dict(), "category": enc_c.to_dict(),
                              "category_path_ablation": enc_ab.to_dict()}
    out["saved_models"] = saved
    write_json("preprocessing.json", preprocessing)
    write_json("validation_results.json", out)
    print("select: done")


# ── bench ───────────────────────────────────────────────────────────────────
def rss_kib():
    for line in open("/proc/self/status"):
        if line.startswith("VmRSS:"):
            return int(line.split()[1])
    return None


def percentiles(ns):
    s = sorted(ns)
    n = len(s)

    def nr(q):
        return s[max(0, math.ceil(q * n) - 1)] / 1e6
    return {"n": n, "min": s[0] / 1e6, "mean": sum(s) / n / 1e6, "p50": nr(0.50),
            "p95": nr(0.95), "p99": nr(0.99), "max": s[-1] / 1e6}


def cmd_bench_one(args):
    """Runs in a fresh process: memory and load first, then timings (milliseconds)."""
    rss0 = rss_kib()
    t0 = time.perf_counter()
    import numpy as np
    import hybrid_analyzer as ha
    import_s = time.perf_counter() - t0
    rss1 = rss_kib()
    t0 = time.perf_counter()
    with open(args.model, "rb") as f:
        analyzer = pickle.load(f)
    load_s = time.perf_counter() - t0
    rss2 = rss_kib()

    rows = [r for r in ha.load_dataset(*dataset_paths(), roles=("validation",))
            if r["slice"] is None]
    texts = {}
    with open(V4_TRAIN, encoding="utf-8") as f:
        for line in f:
            inp = json.loads(line)["input"]
            texts[hashlib.sha256(inp.encode("utf-8")).hexdigest()] = inp
    reqs = [texts[r["row_id"]] for r in rows]
    feats = [r["features"] for r in rows]

    t0 = time.perf_counter_ns()
    first = analyzer.analyze(feats[0])
    first_ms = (time.perf_counter_ns() - t0) / 1e6
    for i in range(BENCH_WARMUP):
        analyzer.analyze(feats[i % len(feats)])

    enc_a, enc_c = analyzer.attack_encoder, analyzer.category_encoder
    m_a, m_c, shared = analyzer.attack_model, analyzer.category_model, analyzer._shared
    seg = {k: [] for k in ("extraction", "preprocessing", "attack_inference",
                           "category_inference", "contract", "analyzer_segmented_total",
                           "analyzer_call", "extraction_plus_analyzer")}
    violations = 0
    pc = time.perf_counter_ns
    for _ in range(BENCH_PASSES):
        for text, feat in zip(reqs, feats):
            t0 = pc()
            f = ha.rf.extract_features(text)
            t1 = pc()
            xa = np.array([enc_a.encode_row(f)])
            xc = xa if shared else np.array([enc_c.encode_row(f)])
            t2 = pc()
            pa = float(m_a.predict_proba(xa)[0, 1])
            t3 = pc()
            pcat = m_c.predict_proba(xc)[0]
            t4 = pc()
            signals = {"attack": min(1.0, max(0.0, pa))}
            signals.update({"category:" + c: float(pcat[i]) for i, c in enumerate(ha.CATEGORIES)})
            ha.contracts.AnalyzerOutput(signals, analyzer.version)
            t5 = pc()
            try:
                analyzer.analyze(feat)
            except ValueError:
                violations += 1
            t6 = pc()
            seg["extraction"].append(t1 - t0)
            seg["preprocessing"].append(t2 - t1)
            seg["attack_inference"].append(t3 - t2)
            seg["category_inference"].append(t4 - t3)
            seg["contract"].append(t5 - t4)
            seg["analyzer_segmented_total"].append(t5 - t1)
            seg["analyzer_call"].append(t6 - t5)
            seg["extraction_plus_analyzer"].append(t5 - t0)
    t0 = time.perf_counter()
    for feat in feats:
        analyzer.analyze(feat)
    loop_s = time.perf_counter() - t0
    result = {
        "model": os.path.relpath(args.model, REPO_ROOT), "artifact_bytes": os.path.getsize(args.model),
        "artifact_sha256": sha256_file(args.model), "analyzer_version": analyzer.version,
        "threads_env": {k: os.environ.get(k) for k in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS",
                                                       "MKL_NUM_THREADS")},
        "import_seconds (numpy + sklearn + module)": round(import_s, 4),
        "load_seconds (pickle.load)": round(load_s, 4),
        "rss_kib": {"process_start": rss0, "after_imports": rss1, "after_model_load": rss2,
                    "model_load_delta": rss2 - rss1,
                    "peak_maxrss": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss},
        "first_call_ms": round(first_ms, 4), "warmup_calls": BENCH_WARMUP,
        "requests": len(feats), "passes": BENCH_PASSES,
        "latency_ms": {k: {kk: (round(vv, 4) if isinstance(vv, float) else vv)
                           for kk, vv in percentiles(v).items()} for k, v in seg.items()},
        "throughput_rps_single_thread (tight analyze() loop)": round(len(feats) / loop_s, 1),
        "contract_violations": violations,
    }
    with open(args.out, "w") as f:
        json.dump(result, f, indent=2)


def cmd_bench(args):
    frozen_path = os.path.join(REPORT_DIR, "frozen_selection.json")
    if os.path.exists(frozen_path):
        evidence = json.load(open(frozen_path)).get("evidence_sha256", {})
        if args.out in evidence or os.path.exists(os.path.join(REPORT_DIR, args.out)):
            raise SystemExit(f"FATAL: {RUN_NAME} is frozen; {args.out} is frozen evidence or "
                             "already exists and is never overwritten")
    families = args.models or [f for f in FAMILIES
                               if os.path.exists(os.path.join(MODEL_DIR, f"{f}.pkl"))]
    env = {**os.environ, "OMP_NUM_THREADS": "1", "OPENBLAS_NUM_THREADS": "1", "MKL_NUM_THREADS": "1",
           "PYTHONHASHSEED": "0"}
    out = {"stage": "bench", "run": RUN_NAME, "created_utc": now(), "data": "VALIDATION requests (fitted rows); "
           "D1 text from V4-clean train joined by row_id for the extraction column",
           "mode": "one request per call, single thread, fresh process per model",
           "percentiles": "nearest-rank", "units": "milliseconds",
           "environment": environment(), "models": {}}
    for fam in families:
        tmp = os.path.join(MODEL_DIR, f".bench_{fam}.json")
        subprocess.run([sys.executable, os.path.abspath(__file__), "--run", RUN_NAME, "bench-one",
                        "--model", os.path.join(MODEL_DIR, f"{fam}.pkl"), "--out", tmp],
                       check=True, env=env)
        out["models"][fam] = json.load(open(tmp))
        os.remove(tmp)
        print(f"[bench] {fam}: analyzer_call p50={out['models'][fam]['latency_ms']['analyzer_call']['p50']} ms",
              flush=True)
    write_json(args.out, out)


# ── freeze ──────────────────────────────────────────────────────────────────
def _ci_includes_zero(ci):
    return ci["ci95"][0] <= 0 <= ci["ci95"][1]


def mechanical_winners(val, lat):
    """The run-002 winner rule (SELECTION_RULES_RUN_002), applied to VALIDATION and bench
    evidence only. Returns (attack family, category family, record)."""
    fams = list(val["saved_models"])

    def cost(f, stage):
        m = lat["models"][f]
        return (m["latency_ms"][stage]["p50"], m["artifact_bytes"])

    brier = {f: val["attack"][f]["validation_calibrated_oof"]["brier"] for f in fams}
    best_a = min(fams, key=lambda f: (brier[f], fams.index(f)))
    pa = val["paired_bootstrap_validation_all_pairs"]["attack (calibrated out-of-fold probabilities)"][best_a]
    tied_a = [best_a] + [f for f in fams if f != best_a
                         and _ci_includes_zero(pa[f"{f} - {best_a}"]["brier_diff"])]
    attack = min(tied_a, key=lambda f: cost(f, "attack_inference"))

    f1 = {f: val["category"][f]["validation"]["macro_f1"] for f in fams}
    best_c = max(fams, key=lambda f: (f1[f], -fams.index(f)))
    pc = val["paired_bootstrap_validation_all_pairs"]["category (macro-F1)"][best_c]
    tied_c = [best_c] + [f for f in fams if f != best_c
                         and _ci_includes_zero(pc[f"{f} - {best_c}"]["macro_f1_diff"])]
    category = min(tied_c, key=lambda f: cost(f, "category_inference"))
    record = {
        "attack": {"calibrated_oof_brier": brier, "best": best_a,
                   "ci_vs_best": {k: v["brier_diff"]["ci95"] for k, v in pa.items()},
                   "statistically_tied_with_best": tied_a,
                   "attack_inference_p50_ms": {f: cost(f, "attack_inference")[0] for f in fams},
                   "winner": attack},
        "category": {"macro_f1": f1, "best": best_c,
                     "ci_vs_best": {k: v["macro_f1_diff"]["ci95"] for k, v in pc.items()},
                     "statistically_tied_with_best": tied_c,
                     "category_inference_p50_ms": {f: cost(f, "category_inference")[0] for f in fams},
                     "winner": category}}
    return attack, category, record


def code_hashes():
    files = ["scripts/training/hybrid_analyzer.py", "scripts/training/run_hybrid_analyzer_baselines.py",
             "scripts/dataset/build_hybrid_analyzer_v1.py", "scripts/dataset/build_hybrid_analyzer_v2.py",
             "scripts/dataset/recover_v4_provenance.py", "scripts/dataset/analyze_analyzer_targets.py",
             "scripts/dataset/parse_dataset_v4.py", "data_plane/request_features.py",
             "data_plane/hybrid_contracts.py"]
    return {f: sha256_file(os.path.join(REPO_ROOT, f)) for f in files
            if os.path.exists(os.path.join(REPO_ROOT, f))}


def cmd_freeze(args):
    path = os.path.join(REPORT_DIR, "frozen_selection.json")
    if os.path.exists(path):
        raise SystemExit("FATAL: already frozen")
    if os.path.exists(os.path.join(REPORT_DIR, "internal_test_results.json")):
        raise SystemExit("FATAL: INTERNAL TEST results exist for this run; a freeze after them "
                         "would be informed by the test")
    val = json.load(open(os.path.join(REPORT_DIR, "validation_results.json")))
    winner_record = None
    if RUN["winner_rule"] == "mechanical":
        if args.attack or args.category:
            raise SystemExit("FATAL: this run's winners come from the pre-declared rule; do not "
                             "pass --attack / --category")
        lat = json.load(open(os.path.join(REPORT_DIR, "latency_results.json")))
        if lat.get("run") != RUN_NAME:
            raise SystemExit("FATAL: latency_results.json was not produced by this run")
        for f, info in val["saved_models"].items():
            if lat["models"][f]["artifact_sha256"] != info["analyzer"]["sha256"]:
                raise SystemExit(f"FATAL: latency of {f} was measured on a different model; re-run bench")
        args.attack, args.category, winner_record = mechanical_winners(val, lat)
        args.rationale = ("pre-declared mechanical rule (selection_rules.winner_attack / "
                          "winner_category); evidence in winner_rule_record"
                          + (f". Note: {args.rationale}" if args.rationale else ""))
    elif not (args.attack and args.category and args.rationale):
        raise SystemExit("FATAL: --attack, --category and --rationale are required for this run")
    for fam in (args.attack, args.category):
        if fam not in val["saved_models"]:
            raise SystemExit(f"FATAL: no saved model for {fam!r}")
    models = {}
    for fam, entry in val["saved_models"].items():
        models[fam] = {}
        for kind, info in entry.items():
            actual = sha256_file(os.path.join(REPO_ROOT, info["path"]))
            if actual != info["sha256"]:
                raise SystemExit(f"FATAL: {info['path']} changed since select")
            models[fam][kind] = info
    # The recommended Analyzer: the attack winner's encoder + calibrated attack model and the
    # category winner's encoder + category model, unchanged, in one artifact.
    import hybrid_analyzer as ha
    a = pickle.load(open(os.path.join(REPO_ROOT, models[args.attack]["analyzer"]["path"]), "rb"))
    c = pickle.load(open(os.path.join(REPO_ROOT, models[args.category]["analyzer"]["path"]), "rb"))
    recommended = ha.AnalyzerModel(analyzer_version(f"attack={args.attack},category={args.category}"),
                                   a.attack_encoder, a.attack_model, c.category_encoder, c.category_model)
    rec_path = os.path.join(MODEL_DIR, "recommended.pkl")
    with open(rec_path, "wb") as f:
        pickle.dump(recommended, f, protocol=5)
    frozen = {
        "frozen_utc": now(), "run": RUN_NAME,
        "internal_test_read_before_freeze": (False if RUN_NAME == "run-001" else
                                             "not in this run; INTERNAL TEST was read once by "
                                             "run-001 (hybrid_analyzer_v1), before this run existed"),
        "winner_attack": args.attack, "winner_category": args.category,
        "winner_rule": RUN["winner_rule"],
        "rationale": args.rationale,
        "frozen_per_family": {fam: {"attack_config": val["attack"][fam]["selected"],
                                    "attack_calibration": val["attack"][fam]["calibration_chosen"],
                                    "category_config": val["category"][fam]["selected"],
                                    "category_path_ablation_config":
                                        val["ablation"]["path"]["families"][fam]["selected"]}
                              for fam in val["saved_models"]},
        "models": models,
        "recommended": {"analyzer_version": recommended.version,
                        "path": os.path.relpath(rec_path, REPO_ROOT),
                        "bytes": os.path.getsize(rec_path), "sha256": sha256_file(rec_path)},
        "evidence_sha256": {n: sha256_file(os.path.join(REPORT_DIR, n)) for n in
                            ("experiment_config.json", "validation_results.json",
                             "latency_results.json", "preprocessing.json")},
    }
    if RUN_NAME != "run-001":
        manifest_path = dataset_paths()[1]
        manifest = json.load(open(manifest_path))
        cfg = json.load(open(os.path.join(REPORT_DIR, "experiment_config.json")))
        prep = json.load(open(os.path.join(REPORT_DIR, "preprocessing.json")))
        frozen.update({
            "winner_rule_record": winner_record,
            "dataset": {"name": RUN["dataset"], "manifest": os.path.relpath(manifest_path, REPO_ROOT),
                        "manifest_sha256": sha256_file(manifest_path),
                        "artifact_sha256": manifest["artifact"]["sha256"],
                        "grouping": manifest["grouping"], "validation_split": manifest["validation"],
                        "counts": manifest["counts"]},
            "feature_order": cfg["feature_order"],
            "preprocessing": {"description": cfg["preprocessing"],
                              "attack_encoder": prep[args.attack]["attack"],
                              "category_encoder": prep[args.category]["category"]},
            "candidate_families": cfg["families"], "attack_grid": cfg["attack_grid"],
            "category_grid": cfg["category_grid"], "selection_rules": cfg["selection_rules"],
            "exact_hyperparameters": {
                "attack": {"family": args.attack,
                           "config": val["attack"][args.attack]["selected_params"],
                           "fixed": cfg["fixed_hyperparameters"][args.attack]},
                "category": {"family": args.category,
                             "config": val["category"][args.category]["selected_params"],
                             "fixed": cfg["fixed_hyperparameters"][args.category]}},
            "calibration": {"chosen": val["attack"][args.attack]["calibration_chosen"],
                            "selection_steps": val["attack"][args.attack]["calibration_cv"]["selection_steps"],
                            "artifact": "inside the attack model of recommended.pkl "
                                        "(CalibratedClassifierCV over a FrozenEstimator) when not native"},
            "validation_metrics": {
                "attack_calibrated_oof": {k: v for k, v in val["attack"][args.attack]
                                          ["validation_calibrated_oof"].items() if k != "reliability"},
                "attack_group_weighted (diagnostic)": val["attack"][args.attack]
                ["validation_group_weighted (diagnostic)"],
                "category": {k: val["category"][args.category]["validation"][k]
                             for k in ("macro_f1", "micro_f1", "per_class")}},
            "category_ablation_validation": {
                f: {"delta_macro_f1": a["delta_macro_f1"], "full": a["validation_full_features"]["macro_f1"],
                    "ablation": a["validation_ablation"]["macro_f1"]}
                for f, a in val["ablation"]["path"]["families"].items()},
            "threshold_policy": "0.5 is reporting-only; not an operating point",
            "code_sha256": code_hashes(),
            "second_look_label": RUN["test_label"],
        })
    write_json("frozen_selection.json", frozen)
    print(json.dumps({k: frozen[k] for k in ("winner_attack", "winner_category")}))


# ── test ────────────────────────────────────────────────────────────────────
def cmd_test(args):
    import numpy as np
    import hybrid_analyzer as ha
    out_path = os.path.join(REPORT_DIR, "internal_test_results.json")
    if os.path.exists(out_path):
        raise SystemExit("FATAL: INTERNAL TEST was already evaluated; it is read exactly once. "
                         "A methodological bug must be documented as invalidating the run first.")
    frozen = json.load(open(os.path.join(REPORT_DIR, "frozen_selection.json")))
    if frozen.get("run", "run-001") != RUN_NAME:
        raise SystemExit("FATAL: frozen_selection.json belongs to another run")
    if "dataset" in frozen:
        path, manifest_path = dataset_paths()
        if (sha256_file(manifest_path) != frozen["dataset"]["manifest_sha256"]
                or sha256_file(path) != frozen["dataset"]["artifact_sha256"]):
            raise SystemExit("FATAL: dataset differs from the one frozen")
    for n, digest in frozen["evidence_sha256"].items():
        if sha256_file(os.path.join(REPORT_DIR, n)) != digest:
            raise SystemExit(f"FATAL: {n} changed after freeze")
    analyzers, ablated = {}, {}
    for fam, entry in frozen["models"].items():
        for kind, info in entry.items():
            p = os.path.join(REPO_ROOT, info["path"])
            if sha256_file(p) != info["sha256"]:
                raise SystemExit(f"FATAL: {info['path']} changed after freeze")
        analyzers[fam] = pickle.load(open(os.path.join(REPO_ROOT, entry["analyzer"]["path"]), "rb"))
        ablated[fam] = pickle.load(open(os.path.join(REPO_ROOT, entry["category_path_ablation"]["path"]), "rb"))

    rec_info = frozen["recommended"]
    rec_path = os.path.join(REPO_ROOT, rec_info["path"])
    if sha256_file(rec_path) != rec_info["sha256"]:
        raise SystemExit("FATAL: recommended.pkl changed after freeze")
    recommended = pickle.load(open(rec_path, "rb"))

    rows = ha.load_dataset(*dataset_paths())
    v = ha.views(rows)
    train_used = v["train"] + v["validation"]
    ya_prior = float(ha.y_attack(v["train"]).mean())
    yc_train = ha.y_category(ha.block_rows(v["train"]))
    freq = np.bincount(yc_train, minlength=len(ha.CATEGORIES)) / len(yc_train)

    out = {"stage": "test", "run": RUN_NAME, "label": RUN["test_label"],
           "second_look": RUN_NAME != "run-001", "created_utc": now(), "frozen_selection_sha256":
           sha256_file(os.path.join(REPORT_DIR, "frozen_selection.json")),
           "winner_attack": frozen["winner_attack"], "winner_category": frozen["winner_category"],
           "views": {}, "external_test_v1": "not read (D53)"}
    out["code_sha256_at_test"] = code_hashes()
    out["code_changed_since_freeze"] = sorted(
        f for f, h in out["code_sha256_at_test"].items()
        if frozen.get("code_sha256", {}).get(f, h) != h)
    out["environment"] = environment()
    if RUN_NAME != "run-001":
        r1 = os.path.join(REPO_ROOT, RUNS["run-001"]["report_dir"], "internal_test_results.json")
        out["run_001_internal_test_results_sha256 (unchanged, historical)"] = sha256_file(r1)

    # feature-vector lookup (memorization diagnostic, not a candidate)
    by_vec = {}
    for r in train_used:
        by_vec.setdefault(r["meta_feature_vector_sha256"], Counter())[r["target_attack"]] += 1

    for view in ("internal_test_full", "internal_test_feature_disjoint"):
        vr = v[view]
        ya = ha.y_attack(vr)
        brows = ha.block_rows(vr)
        yc = ha.y_category(brows)
        gkey = RUN["test_group_key"]
        groups_a = np.array([r[gkey] for r in vr])
        groups_c = np.array([r[gkey] for r in brows])
        entry = {"rows": len(vr), "class_mix": {"BLOCK": int(ya.sum()), "ALLOW": int(len(ya) - ya.sum())},
                 "category_support": dict(Counter(r["target_category"] for r in brows)),
                 "flags": {"meta_feature_vector_in_train": sum(r["meta_feature_vector_in_train"] for r in vr),
                           "meta_canonical_request_in_train": sum(r["meta_canonical_request_in_train"] for r in vr),
                           **({"meta_generator_family_in_train": sum(r["meta_generator_family_in_train"] for r in vr)}
                              if "meta_generator_family_in_train" in vr[0] else {})},
                 "group_unit": gkey,
                 "attack": {"prior_baseline": ha.attack_metrics(ya, np.full(len(ya), ya_prior), with_bins=False)},
                 "category": {"majority_baseline": ha.category_metrics(yc, np.tile(freq, (len(yc), 1)))},
                 "category_path_ablation": {}, "contract_violations": {}}
        pa_all, pc_all = {}, {}
        for fam, an in analyzers.items():
            feats = [r["features"] for r in vr]
            pa = an.attack_proba(feats)
            native = an.attack_model.estimator.predict_proba(an.attack_encoder.transform(feats))[:, 1] \
                if hasattr(an.attack_model, "calibrated_classifiers_") else pa
            pcat = an.category_proba([r["features"] for r in brows])
            pa_all[fam], pc_all[fam] = pa, pcat
            entry["attack"][fam] = {**ha.attack_metrics(ya, pa),
                                    "native_probability": {k: ha.attack_metrics(ya, native, with_bins=False)[k]
                                                           for k in ("brier", "log_loss", "roc_auc")}
                                    | {"ece": ha.reliability_bins(ya, native)["ece"]},
                                    "recall_by_v4_reason": ha.recall_by_reason(vr, pa),
                                    "group_weighted (diagnostic)": ha.attack_metrics_group_weighted(
                                        ya, pa, groups_a),
                                    "error_concentration (diagnostic)": ha.error_concentration(
                                        vr, pa, gkey)}
            entry["category"][fam] = ha.category_metrics(yc, pcat)
            ab = ablated[fam]
            p_ab = ab["model"].predict_proba(ab["encoder"].transform([r["features"] for r in brows]))
            m_ab = ha.category_metrics(yc, p_ab)
            full_m = entry["category"][fam]
            entry["category_path_ablation"][fam] = {
                "metrics": m_ab,
                "delta_macro_f1": round(m_ab["macro_f1"] - full_m["macro_f1"], 6),
                "delta_micro_f1": round(m_ab["micro_f1"] - full_m["micro_f1"], 6),
                "delta_f1_per_class": {c: round(m_ab["per_class"][c]["f1"] - full_m["per_class"][c]["f1"], 6)
                                       for c in ha.CATEGORIES},
                "delta_confusion_matrix": (np.array(m_ab["confusion_matrix"]["rows_true_cols_pred"])
                                           - np.array(full_m["confusion_matrix"]["rows_true_cols_pred"])).tolist()}
            bad = 0
            for r in vr:
                try:
                    an.analyze(r["features"])
                except ValueError:
                    bad += 1
            entry["contract_violations"][fam] = bad
        entry["paired_bootstrap"] = {
            "attack": paired_bootstrap(ha, "attack", groups_a, ya, pa_all),
            "category": paired_bootstrap(ha, "category", groups_c, yc, pc_all)}
        # memorization diagnostic: rows whose exact vector was seen in TRAIN u VALIDATION
        covered = [i for i, r in enumerate(vr) if r["meta_feature_vector_sha256"] in by_vec]
        if covered:
            look = np.array([by_vec[vr[i]["meta_feature_vector_sha256"]].most_common(1)[0][0] for i in covered])
            entry["feature_vector_lookup_diagnostic"] = {
                "covered_rows": len(covered),
                "lookup_accuracy_on_covered": round(float((look == ya[covered]).mean()), 6),
                "model_accuracy_on_covered": {fam: round(float(((pa_all[fam][covered] >= 0.5) == ya[covered]).mean()), 6)
                                              for fam in analyzers},
                "model_accuracy_on_not_covered": {
                    fam: round(float(((np.delete(pa_all[fam], covered) >= 0.5) == np.delete(ya, covered)).mean()), 6)
                    for fam in analyzers}}
        else:
            entry["feature_vector_lookup_diagnostic"] = {"covered_rows": 0}
        # the recommended Analyzer must equal its two parts and never violate the contract
        feats = [r["features"] for r in vr]
        rec_pa = recommended.attack_proba(feats)
        bad = 0
        for r in vr:
            try:
                recommended.analyze(r["features"])
            except ValueError:
                bad += 1
        entry["recommended"] = {
            "analyzer_version": recommended.version, "contract_violations": bad,
            "attack_equals_winner": bool(np.array_equal(rec_pa, pa_all[frozen["winner_attack"]])),
            "category_equals_winner": bool(np.array_equal(
                recommended.category_proba([r["features"] for r in brows]),
                pc_all[frozen["winner_category"]]))}
        out["views"][view] = entry
        print(f"[test] {view} done", flush=True)

    jwt = v["unsupported_jwt"]
    out["views"]["unsupported_jwt"] = {
        "rows": len(jwt), "note": "never fitted (D48); share scored attack-like at the 0.5 "
                                  "reporting threshold",
        "per_family": {fam: {"scored_attack_like": int((an.attack_proba([r["features"] for r in jwt]) >= 0.5).sum()),
                             "mean_attack_probability": round(float(an.attack_proba([r["features"] for r in jwt]).mean()), 6),
                             "attack_probabilities": [round(float(x), 4) for x in an.attack_proba([r["features"] for r in jwt])]}
                       for fam, an in analyzers.items()}}
    text = json.dumps(out, indent=2, ensure_ascii=False, default=_json_default) + "\n"
    with open(out_path, "x", encoding="utf-8") as f:   # serialized first: no truncated file
        f.write(text)
    print("test: done")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--run", choices=sorted(RUNS), default="run-001")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("select")
    bn = sub.add_parser("bench")
    bn.add_argument("--models", nargs="*", help="pickles in the model dir (default: the families)")
    bn.add_argument("--out", default="latency_results.json")
    b1 = sub.add_parser("bench-one")
    b1.add_argument("--model", required=True)
    b1.add_argument("--out", required=True)
    fz = sub.add_parser("freeze")
    fz.add_argument("--attack")
    fz.add_argument("--category")
    fz.add_argument("--rationale", default="")
    sub.add_parser("test")
    args = ap.parse_args()
    configure(args.run)
    {"select": cmd_select, "bench": cmd_bench, "bench-one": cmd_bench_one,
     "freeze": cmd_freeze, "test": cmd_test}[args.cmd](args)


if __name__ == "__main__":
    main()
