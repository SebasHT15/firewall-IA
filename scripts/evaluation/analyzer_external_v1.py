"""
firewall-IA — one aggregate post-freeze evaluation of the frozen Lightweight Request
Analyzer (Model 1) on External Test v1 (D53, under D40 / D45).

Protocol, fixed before exposure: reports/hybrid/analyzer-external-v1-run-001/PROTOCOL.md

OFFLINE and AGGREGATE ONLY. It scores the frozen D1 `request_text` of the 400 External v1
cases with the frozen artifact and writes aggregate metrics. It never writes, prints or logs
request text, case ids, per-case labels, probabilities, predictions, FP / FN lists or
tracebacks; a failure records only the stage and the exception class name.

It does not retrain, re-fit, re-calibrate or threshold anything. 0.5 is the D55
reporting-only threshold, not an operating point. It is not an evaluation of the gateway
or of a Hybrid cascade, and it computes no joint V4 x Analyzer count.

Research environment only (D52, D33):

    .venv-analyzer/bin/python scripts/evaluation/analyzer_external_v1.py preflight
    .venv-analyzer/bin/python scripts/evaluation/analyzer_external_v1.py run --confirm-single-run

`run` refuses to start if `run_attempt.json` exists: the evaluation is started once. If it
fails after starting, the failure is recorded and nothing is retried (protocol §6).

Synthetic validation lives in tests/test_analyzer_external_v1.py and never touches
External v1: every function takes explicit paths, and the real case file is refused unless
the caller is the `run` command (`allow_real_external=True`).
"""

import argparse
import hashlib
import json
import math
import os
import pickle
import platform
import subprocess
import sys
import warnings
from collections import Counter
from datetime import datetime, timezone

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(REPO_ROOT, "data_plane"))
sys.path.insert(0, os.path.join(REPO_ROOT, "scripts", "training"))

import numpy as np  # noqa: E402
from sklearn import metrics as skm  # noqa: E402

sys.path.insert(0, os.path.join(REPO_ROOT, "scripts", "dataset"))

import analyze_analyzer_targets as design  # noqa: E402  (frozen: parse_text)
import hybrid_analyzer as ha  # noqa: E402
import hybrid_contracts as contracts  # noqa: E402
import parse_dataset_v4 as gen  # noqa: E402  (frozen: canonical_key; pandas only inside main)
import request_features as rf  # noqa: E402

RUN_ID = "analyzer-external-v1-run-001"
REPORT_DIR = os.path.join(REPO_ROOT, "reports", "hybrid", RUN_ID)

EXT_DIR = os.path.join(REPO_ROOT, "datasets", "external_v1")
REAL_CASES = os.path.join(EXT_DIR, "cases.jsonl")
REAL_MANIFEST = os.path.join(EXT_DIR, "manifest.json")
REAL_EXT_SUMS = os.path.join(EXT_DIR, "SHA256SUMS")

RUN002_DIR = os.path.join(REPO_ROOT, "reports", "hybrid", "phase2b-analyzer-v2-run-002")
RUN001_DIR = os.path.join(REPO_ROOT, "reports", "hybrid", "phase2b-analyzer-baselines")
DATASET_V2 = os.path.join(REPO_ROOT, "datasets", "hybrid_analyzer_v2", "hybrid_analyzer_v2.jsonl")
DATASET_V2_MANIFEST = os.path.join(REPO_ROOT, "datasets", "manifest_hybrid_analyzer_v2.json")
V4_SUMMARY = os.path.join(REPO_ROOT, "reports", "external", "external-v1-run-001", "summary.json")
INTERNAL_RESULTS = os.path.join(RUN002_DIR, "internal_test_results.json")

# Anchors, copied from the frozen records (PROTOCOL.md §2); the run checks the files against them.
ANCHORS = {
    "freeze_commit": "36df2ee",
    "cases_sha256": "721dfdaa6425463ae0ce26520f6d47986fdc7388468b55d7b1a5bffed822d342",
    "integrity_hash": "ccac5f55eee27f94a79295f0022edf6eac792abe828ed1a1fe5f43ac85c5e52b",
    "model_path": "model-output-hybrid-analyzer-v2/recommended.pkl",
    "model_bytes": 8866799,
    "model_sha256": "79eb7265a7a3abd9f5a499234732042a9100729b4434971a02d73e03f6a2ff9b",
    "model_version": "hybrid-analyzer-v2/attack=hist_gb,category=hist_gb",
    "frozen_selection_sha256": "86271a46b9e2dbf85fe2c421c68c9b45ea0e73b6de7dd23eac6065a7b454b8a5",
    "dataset_v2_sha256": "e8da8674435ed65057161bb4c74b41dc4aa1d8bf876b0327c53ecba7c0d99b75",
    "dataset_v2_manifest_sha256": "40f958eaf538b36a4198bed4a459347a6f680a2d98229aeffa52fc7a7d2e6b83",
    "feature_schema": "request-features/v2",
    "internal_results_sha256": "74619d87177299da4719a6475d0cd1607bfd485195ce4830b940a9693e8d2394",
    "preprocessing_sha256": "6928eeddbe9c89bb3fc24ac636937821b285678ef7c342165faf55008df4b991",
    "v4_summary_sha256": "9923aae9c07c55b28c025f472f1f090f5bd1ffd833397ac5cc6cd307780bc1c0",
}
EXPECTED_ENV = {"python": "3.12.15", "numpy": "2.5.3", "scikit_learn": "1.9.1",
                "scipy": "1.18.1", "joblib": "1.6.0", "threadpoolctl": "3.7.0"}
BRANCH = "research/hybrid-analyzer-external-v1-aggregate"
# The only paths allowed to differ from HEAD when the run starts (nothing is committed).
ALLOWED_DIRTY = ("scripts/evaluation/analyzer_external_v1.py",
                 "tests/test_analyzer_external_v1.py",
                 "reports/hybrid/analyzer-external-v1-run-001/")
# Tracked evidence that must be byte-identical to HEAD.
FROZEN_TRACKED = ("datasets/external_v1", "reports/external",
                  "reports/hybrid/phase2b-analyzer-baselines",
                  "reports/hybrid/phase2b-analyzer-v2-run-002")
TEST_MODULE = "tests.test_analyzer_external_v1"

BENIGN_CELLS = ("browser-navigation", "browser-forms-session", "api-json", "api-query",
                "unseen-structure")
ATTACK_CELLS = ("sqli", "cmdi", "xss", "path-traversal", "ssrf")
CELLS = BENIGN_CELLS + ATTACK_CELLS
PER_CELL = 40
# payload_placement -> visible to RequestFeatures (path / query / body) or not (D44: only
# Content-Type is read among headers). Fixed before exposure (PROTOCOL.md §3.2b).
PLACEMENT_VISIBILITY = {"query": "visible", "path": "visible", "form": "visible",
                        "json": "visible", "header": "invisible", "cookie": "invisible"}
# External v1 attack category -> D47 / D49 Analyzer category. Fixed before exposure.
CATEGORY_MAP = {"sqli": "sql_injection", "cmdi": "command_injection", "xss": "xss",
                "path-traversal": "path_file_access", "ssrf": "ssrf"}
LABEL = {"ALLOW": 0, "BLOCK": 1}

THRESHOLD = ha.REPORT_THRESHOLD           # 0.5, reporting-only (D55)
BOOT_N = 2000
BOOT_SEED = int.from_bytes(hashlib.sha256(RUN_ID.encode()).digest()[:8], "big")  # big-endian
GROUP_BOOT_N = 1000
WILSON_Z = 1.959963984540054
# k-rule: no published quantity may be a function of fewer than K_MIN cases' predictions,
# directly or by differencing two published figures (code audit, before exposure).
K_MIN = 10
MIN_BIN = K_MIN                           # reliability bins below this are suppressed
MAX_LIST = 16                             # no list in the output may be longer than this
MAX_DICT = 24                             # no dict in the output may have more keys than this
MIN_SUPPORT = 30                          # D18 / D19

SAFE = "message and traceback deliberately not recorded (aggregate-only rule)"


class PreflightError(Exception):
    """Raised with a message built only from fixed text and counts — never case data."""


# ── small helpers ───────────────────────────────────────────────────────────
def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def sha256_file(path):
    return ha.sha256_file(path)


def sha_text(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def rel(path):
    return os.path.relpath(path, REPO_ROOT)


def write_exclusive(path, text):
    """Create `path`; refuse if it exists (never overwrite evidence)."""
    with open(path, "x", encoding="utf-8") as f:
        f.write(text)


def load_json(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def dumps(obj):
    return json.dumps(obj, indent=2, ensure_ascii=False) + "\n"


def _f(x):
    return None if x is None else float(round(float(x), 6))


def refuse_real_external(path, allow_real_external):
    """Synthetic callers can never read the real External v1 file by accident."""
    real = os.path.realpath(REAL_CASES)
    if os.path.realpath(path) == real and not allow_real_external:
        raise PreflightError("the real External v1 cases may only be read by the `run` "
                             "command (allow_real_external=True)")


# ── integrity: External v1 ──────────────────────────────────────────────────
def load_cases(path, allow_real_external=False):
    refuse_real_external(path, allow_real_external)
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def integrity_hash(rows, cells=CELLS):
    ordered = sorted(rows, key=lambda r: (cells.index(r["primary_cell"]), r["selection_key"]))
    canonical = "\n".join(f"{r['case_id']}|{r['request_sha256']}" for r in ordered)
    return sha_text(canonical)


def verify_sha256sums(sums_path, must_list=()):
    """Verify a SHA256SUMS file; returns (n_ok, n_bad). File names are evidence paths,
    not case data. An empty file, or one that omits a name in `must_list`, counts as bad."""
    base = os.path.dirname(sums_path)
    ok = bad = 0
    listed = set()
    with open(sums_path, encoding="utf-8") as f:
        for line in f:
            if not line.strip():
                continue
            digest, name = line.split(None, 1)
            name = name.strip().lstrip("*")
            listed.add(os.path.normpath(name))
            p = os.path.join(base, name)
            if os.path.exists(p) and sha256_file(p) == digest:
                ok += 1
            else:
                bad += 1
    bad += sum(1 for n in must_list if os.path.normpath(n) not in listed)
    if ok == 0:
        bad += 1
    return ok, bad


def verify_external(cases_path, manifest_path, sums_path, anchors=None,
                    allow_real_external=False, expected_total=400, per_cell=PER_CELL):
    """Integrity and label-consistency checks. Returns (rows, checks); every problem is a
    count or a fixed string, never a case id or text."""
    anchors = ANCHORS if anchors is None else anchors
    refuse_real_external(cases_path, allow_real_external)
    problems = []
    for p in (cases_path, manifest_path, sums_path):
        if not os.path.exists(p):
            raise PreflightError(f"missing file: {os.path.basename(p)}")
    m = load_json(manifest_path)
    rows = load_cases(cases_path, allow_real_external)
    artifact = sha256_file(cases_path)
    if m.get("status") != "FROZEN" or not m.get("frozen"):
        problems.append("manifest status is not FROZEN")
    if artifact != m.get("artifact_sha256"):
        problems.append("cases SHA-256 != manifest artifact_sha256")
    if artifact != anchors["cases_sha256"]:
        problems.append("cases SHA-256 != anchor")
    bad_sha = sum(1 for r in rows if sha_text(r["request_text"]) != r["request_sha256"])
    if bad_sha:
        problems.append(f"{bad_sha} request_sha256 value(s) do not recompute")
    try:
        ihash = integrity_hash(rows)
    except (ValueError, KeyError):
        ihash = None
        problems.append("integrity hash cannot be computed (unknown cell or missing field)")
    if ihash != m.get("integrity_hash"):
        problems.append("integrity hash != manifest")
    if ihash != anchors["integrity_hash"]:
        problems.append("integrity hash != anchor")
    sums_ok, sums_bad = verify_sha256sums(sums_path, must_list=("cases.jsonl",))
    if sums_bad:
        problems.append(f"{sums_bad} SHA256SUMS entr(y/ies) do not verify")
    if len(rows) != expected_total:
        problems.append(f"{len(rows)} cases != {expected_total}")
    if len({r["case_id"] for r in rows}) != len(rows):
        problems.append("duplicate case ids")
    dec = Counter(r["expected_decision"] for r in rows)
    if set(dec) - set(LABEL):
        problems.append("unknown expected_decision value(s)")
    if dec.get("ALLOW", 0) != expected_total // 2 or dec.get("BLOCK", 0) != expected_total // 2:
        problems.append(f"balance ALLOW {dec.get('ALLOW', 0)} / BLOCK {dec.get('BLOCK', 0)}")
    per = Counter(r["primary_cell"] for r in rows)
    for c in CELLS:
        if per.get(c, 0) != per_cell:
            problems.append(f"cell {c}: {per.get(c, 0)} != {per_cell}")
    if set(per) - set(CELLS):
        problems.append("unknown cell(s)")
    inconsistent = sum(1 for r in rows if not _label_consistent(r))
    if inconsistent:
        problems.append(f"{inconsistent} case(s) with labels inconsistent with their cell")
    missing = sum(1 for r in rows if not isinstance(r.get("payload_placement"), str)
                  or not isinstance(r.get("request_text"), str))
    if missing:
        problems.append(f"{missing} case(s) without a string payload_placement / request_text")
    unmapped = sum(1 for r in rows if r.get("expected_decision") == "BLOCK"
                   and r.get("payload_placement") not in PLACEMENT_VISIBILITY)
    if unmapped:
        problems.append(f"{unmapped} BLOCK case(s) with a payload_placement outside the fixed mapping")
    checks = {"manifest_status": m.get("status"), "cases_sha256": artifact,
              "integrity_hash": ihash, "sha256sums_verified": sums_ok,
              "n_cases": len(rows), "allow": dec.get("ALLOW", 0), "block": dec.get("BLOCK", 0),
              "per_cell": {c: per.get(c, 0) for c in CELLS}, "problems": problems}
    return rows, checks


def _label_consistent(r):
    cell, dec = r.get("primary_cell"), r.get("expected_decision")
    if cell in BENIGN_CELLS:
        return dec == "ALLOW" and r.get("attack_category") is None and r.get("benign_slice") == cell
    if cell in ATTACK_CELLS:
        return dec == "BLOCK" and r.get("attack_category") == cell and r.get("benign_slice") is None
    return False


# ── integrity: model, frozen reports, code, dataset, environment, git ──────
def verify_model_and_reports(anchors=None, repo_root=None, run002_dir=None, run001_dir=None,
                             dataset=None, dataset_manifest=None):
    anchors = ANCHORS if anchors is None else anchors
    repo_root = REPO_ROOT if repo_root is None else repo_root
    run002_dir = RUN002_DIR if run002_dir is None else run002_dir
    run001_dir = RUN001_DIR if run001_dir is None else run001_dir
    dataset = DATASET_V2 if dataset is None else dataset
    dataset_manifest = DATASET_V2_MANIFEST if dataset_manifest is None else dataset_manifest
    problems = []
    model = os.path.join(repo_root, anchors["model_path"])
    if not os.path.exists(model):
        raise PreflightError("missing frozen artifact")
    model_sha = sha256_file(model)
    if model_sha != anchors["model_sha256"]:
        problems.append("artifact SHA-256 != frozen")
    if os.path.getsize(model) != anchors["model_bytes"]:
        problems.append("artifact size != frozen")
    fs_path = os.path.join(run002_dir, "frozen_selection.json")
    if not os.path.exists(fs_path):
        raise PreflightError("missing frozen_selection.json")
    fs_sha = sha256_file(fs_path)
    if fs_sha != anchors["frozen_selection_sha256"]:
        problems.append("frozen_selection.json SHA-256 != anchor")
    frozen = load_json(fs_path)
    rec = frozen.get("recommended", {})
    if (rec.get("sha256") != anchors["model_sha256"] or rec.get("path") != anchors["model_path"]
            or rec.get("analyzer_version") != anchors["model_version"]):
        problems.append("frozen_selection.recommended != anchors")
    run002 = verify_sha256sums(os.path.join(run002_dir, "SHA256SUMS"))
    if run002[1]:
        problems.append(f"run-002 SHA256SUMS: {run002[1]} mismatch(es)")
    run001_sums = os.path.join(run001_dir, "SHA256SUMS")
    run001 = verify_sha256sums(run001_sums) if os.path.exists(run001_sums) else None
    if run001 and run001[1]:
        problems.append(f"run-001 SHA256SUMS: {run001[1]} mismatch(es)")
    for path, key in ((os.path.join(run002_dir, "internal_test_results.json"), "internal_results_sha256"),
                      (os.path.join(run002_dir, "preprocessing.json"), "preprocessing_sha256"),
                      (V4_SUMMARY, "v4_summary_sha256")):
        if not os.path.exists(path) or sha256_file(path) != anchors[key]:
            problems.append(f"{os.path.basename(path)} SHA-256 != anchor")
    code = {}
    for f, digest in frozen.get("code_sha256", {}).items():
        p = os.path.join(repo_root, f)
        same = os.path.exists(p) and sha256_file(p) == digest
        code[f] = same
        if not same:
            problems.append(f"frozen code changed: {f}")
    ds = frozen.get("dataset", {})
    for path, key, frozen_key in ((dataset, "dataset_v2_sha256", "artifact_sha256"),
                                  (dataset_manifest, "dataset_v2_manifest_sha256", "manifest_sha256")):
        if not os.path.exists(path):
            problems.append(f"missing {os.path.basename(path)}")
            continue
        digest = sha256_file(path)
        if digest != anchors[key] or digest != ds.get(frozen_key):
            problems.append(f"{os.path.basename(path)} SHA-256 != frozen")
    return frozen, {"model_sha256": model_sha, "model_bytes": os.path.getsize(model),
                    "frozen_selection_sha256": fs_sha,
                    "run002_sha256sums": {"ok": run002[0], "bad": run002[1]},
                    "run001_sha256sums": None if run001 is None else {"ok": run001[0], "bad": run001[1]},
                    "frozen_code_unchanged": code, "problems": problems}


def environment():
    import joblib
    import scipy
    import sklearn
    import threadpoolctl
    return {"python": platform.python_version(), "numpy": np.__version__,
            "scikit_learn": sklearn.__version__, "scipy": scipy.__version__,
            "joblib": joblib.__version__, "threadpoolctl": threadpoolctl.__version__,
            "platform": platform.platform(), "interpreter": sys.executable}


def verify_environment(expected=None):
    expected = EXPECTED_ENV if expected is None else expected
    env = environment()
    problems = [f"{k}: {env.get(k)} != {v}" for k, v in expected.items() if env.get(k) != v]
    return env, problems


def _git(*args):
    return subprocess.run(["git", "-C", REPO_ROOT, *args], capture_output=True, text=True)


def verify_git():
    problems = []
    branch = _git("rev-parse", "--abbrev-ref", "HEAD").stdout.strip()
    head = _git("rev-parse", "HEAD").stdout.strip()
    if branch != BRANCH:
        problems.append(f"branch {branch!r} != {BRANCH!r}")
    if _git("merge-base", "--is-ancestor", ANCHORS["freeze_commit"], "HEAD").returncode != 0:
        problems.append("External v1 freeze commit is not an ancestor of HEAD (D39)")
    porcelain = _git("status", "--porcelain", "--untracked-files=all").stdout.splitlines()
    dirty = sorted(line[3:] for line in porcelain if line.strip())
    unexpected = [p for p in dirty if not p.startswith(ALLOWED_DIRTY)]
    if unexpected:
        problems.append(f"{len(unexpected)} uncommitted path(s) outside the allowlist")
    frozen_diff = _git("diff", "--quiet", "HEAD", "--", *FROZEN_TRACKED).returncode
    if frozen_diff != 0:
        problems.append("tracked frozen evidence differs from HEAD")
    return {"branch": branch, "head": head, "uncommitted_paths": dirty,
            "unexpected_uncommitted": unexpected, "problems": problems}


def verify_feature_contract(analyzer, frozen, preprocessing, anchors=None):
    anchors = ANCHORS if anchors is None else anchors
    problems = []
    if rf.FEATURE_SCHEMA_VERSION != anchors["feature_schema"]:
        problems.append("feature schema version != request-features/v2")
    if len(ha.FEATURE_FIELDS) != 34:
        problems.append(f"{len(ha.FEATURE_FIELDS)} feature fields != 34")
    if list(ha.FEATURE_FIELDS) != list(frozen.get("feature_order", [])):
        problems.append("feature order != frozen feature_order")
    if getattr(analyzer, "version", None) != anchors["model_version"]:
        problems.append("artifact version != frozen")
    for name in ("attack_encoder", "category_encoder"):
        enc = getattr(analyzer, name, None)
        if enc is None or list(enc.fields) != list(ha.FEATURE_FIELDS):
            problems.append(f"{name} fields != the 34 RequestFeatures in order")
    fam = frozen.get("winner_attack")
    expected_cols = preprocessing.get(fam, {}).get("attack", {}).get("columns")
    if expected_cols is None or analyzer.attack_encoder.columns != expected_cols:
        problems.append("attack encoder columns != run-002 preprocessing.json")
    fam_c = frozen.get("winner_category")
    expected_cat = preprocessing.get(fam_c, {}).get("category", {}).get("columns")
    if expected_cat is None or analyzer.category_encoder.columns != expected_cat:
        problems.append("category encoder columns != run-002 preprocessing.json")
    return problems


def load_model(path, expected_sha256):
    """Read the bytes once, verify them, then unpickle those same bytes. Read-only."""
    with open(path, "rb") as f:
        data = f.read()
    if hashlib.sha256(data).hexdigest() != expected_sha256:
        raise PreflightError("artifact SHA-256 != frozen")
    return pickle.loads(data)


# ── scoring ─────────────────────────────────────────────────────────────────
def extract(texts):
    return [rf.extract_features(t) for t in texts]


def score(analyzer, features):
    """Batch probabilities (the metric input) + the per-request contract path, compared."""
    p_attack = np.asarray(analyzer.attack_proba(features), dtype=float)
    p_cat = np.asarray(analyzer.category_proba(features), dtype=float)
    violations, mismatch = 0, 0
    for i, feat in enumerate(features):
        try:
            out = analyzer.analyze(feat)
        except ValueError:
            violations += 1
            continue
        if out.signals[contracts.ATTACK] != min(1.0, max(0.0, float(p_attack[i]))):
            mismatch += 1
    return p_attack, p_cat, {"contract_violations": violations,
                             "analyze_vs_batch_attack_mismatches": mismatch,
                             "non_finite_attack": int((~np.isfinite(p_attack)).sum())}


# ── metrics (pure; synthetic-testable) ──────────────────────────────────────
def wilson(k, n, z=WILSON_Z):
    if n == 0:
        return None
    p = k / n
    den = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / den
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return [_f(max(0.0, centre - half)), _f(min(1.0, centre + half))]


def rate(k, n):
    return {"num": int(k), "den": int(n), "value": _f(k / n) if n else None,
            "wilson95": wilson(k, n)}


def support_status(n):
    return "OK" if n >= MIN_SUPPORT else ("INSUFFICIENT DATA" if n > 0 else "NOT EVALUABLE")


def rule_of_three(errors, n):
    return (f"zero errors on {n}: one-sided approximate 95% upper bound on the error rate "
            f"~ 3/{n} = {3 / n:.3f} (rule of three; the two-sided Wilson upper bound is "
            f"{wilson(0, n)[1]})") if errors == 0 and n > 3 else None


def reliability_suppressed(y, p, n_bins=15, min_n=MIN_BIN):
    """Bins with n < min_n are hidden. Because ECE covers every bin, the hidden pool's
    contribution is derivable from the published bins, so the pool itself must hold 0 or
    >= min_n cases: if it holds 1..min_n-1, the smallest published bins are hidden too."""
    rb = ha.reliability_bins(y, p, n_bins)
    show = [b["n"] >= min_n for b in rb["bins"]]
    hidden = sum(b["n"] for b, s in zip(rb["bins"], show) if not s)
    while 0 < hidden < min_n and any(show):
        i = min((b["n"], i) for i, (b, s) in enumerate(zip(rb["bins"], show)) if s)[1]
        show[i] = False
        hidden += rb["bins"][i]["n"]
    bins = []
    for b, s in zip(rb["bins"], show):
        if s:
            bins.append(b)
        else:
            bins.append({"bin": b["bin"], "n": "suppressed"})
    return {"n_bins": n_bins, "ece": rb["ece"], "mce_over_published_bins":
            _f(max([abs(b["mean_predicted"] - b["observed_frequency"]) for b in bins
                    if "mean_predicted" in b] or [0.0])),
            "suppression_rule": f"bins with fewer than {min_n} cases publish no n, mean or "
                                f"frequency; if the hidden pool would hold 1-{min_n - 1} cases, "
                                "the smallest published bins are hidden as well",
            "hidden_cases": hidden,
            "bins": bins}


def stratified_bootstrap(y, p, n_boot=BOOT_N, seed=BOOT_SEED):
    """Percentile 95% intervals; class-stratified case resampling."""
    y, p = np.asarray(y), np.asarray(p, dtype=float)
    rng = np.random.default_rng(seed)
    pos, neg = np.flatnonzero(y == 1), np.flatnonzero(y == 0)
    stats = {"roc_auc": [], "pr_auc": [], "brier": [], "log_loss": []}
    for _ in range(n_boot):
        idx = np.concatenate([rng.choice(pos, len(pos)), rng.choice(neg, len(neg))])
        yb, pb = y[idx], p[idx]
        stats["roc_auc"].append(skm.roc_auc_score(yb, pb))
        stats["pr_auc"].append(skm.average_precision_score(yb, pb))
        stats["brier"].append(skm.brier_score_loss(yb, pb, pos_label=1))
        stats["log_loss"].append(ha.binary_log_loss(yb, pb))
    return {"method": "class-stratified case bootstrap, percentile",
            "n_boot": n_boot, "seed": seed,
            "caveat": "cases share one lab application and its flows; not independent draws, "
                      "so the intervals are optimistic",
            "ci95": {k: [_f(np.percentile(v, 2.5)), _f(np.percentile(v, 97.5))]
                     for k, v in stats.items()}}


def headline(y, p, prevalence_note="50/50 by construction (D42); not an operational prevalence"):
    m = ha.attack_metrics(y, p, threshold=THRESHOLD, with_bins=False)
    tp, tn, fp, fn = m["tp"], m["tn"], m["fp"], m["fn"]
    return {
        "n": m["n"], "positives_block": m["positives"], "negatives_allow": m["negatives"],
        "prevalence_block": m["prevalence"],
        "prevalence_note": prevalence_note,
        "threshold_free": {"roc_auc": m["roc_auc"], "pr_auc": m["pr_auc"],
                           "pr_auc_chance_level": m["prevalence"], "brier": m["brier"],
                           "log_loss": m["log_loss"]},
        "at_reporting_threshold_0_5": {
            "note": "D55: reporting-only; not an operating point; nothing tuned on it",
            "tp": tp, "tn": tn, "fp": fp, "fn": fn,
            "confusion_matrix (methodology §6)": {"Real ALLOW": {"Pred ALLOW": tn, "Pred BLOCK": fp},
                                                  "Real BLOCK": {"Pred ALLOW": fn, "Pred BLOCK": tp}},
            "accuracy": rate(tp + tn, m["n"]), "precision_block": rate(tp, tp + fp),
            "recall_block": rate(tp, tp + fn), "f1_block": m["f1"],
            "fpr": rate(fp, fp + tn), "fnr": rate(fn, fn + tp),
            "zero_error_bounds": {"fpr": rule_of_three(fp, fp + tn),
                                  "fnr": rule_of_three(fn, fn + tp)}},
    }


def _auc_against(y, p, mask_cell, opposite):
    sel = mask_cell | opposite
    return _f(skm.roc_auc_score(y[sel], p[sel])) if len(set(y[sel].tolist())) == 2 else None


def per_cell(y, p, cells):
    y, p, cells = np.asarray(y), np.asarray(p, dtype=float), np.asarray(cells)
    pred = (p >= THRESHOLD).astype(int)
    out = {}
    for c in CELLS:
        mask = cells == c
        n = int(mask.sum())
        e = {"n": n, "support_status": support_status(n),
             "mean_attack": _f(p[mask].mean()) if n else None,
             "brier_within_cell": _f(((p[mask] - y[mask]) ** 2).mean()) if n else None}
        if c in BENIGN_CELLS:
            fp = int(((pred == 1) & mask).sum())
            e.update({"fp": fp, "tn": n - fp, "fpr_at_0_5": rate(fp, n),
                      "zero_error_bound": rule_of_three(fp, n),
                      "roc_auc_vs_all_block": _auc_against(y, p, mask, y == 1)})
        else:
            tp = int(((pred == 1) & mask).sum())
            e.update({"tp": tp, "fn": n - tp, "recall_at_0_5": rate(tp, n),
                      "zero_error_bound": rule_of_three(n - tp, n),
                      "roc_auc_all_allow_vs_cell": _auc_against(y, p, mask, y == 0)})
        out[c] = e
    return out


def category_block(true_cells, p_cat):
    """Category head over ground-truth BLOCK cases, D47 / D49 mapping; 5 sampled classes."""
    cats = list(ha.CATEGORIES)
    sampled = [CATEGORY_MAP[c] for c in ATTACK_CELLS]
    y = np.array([cats.index(CATEGORY_MAP[c]) for c in true_cells], dtype=int)
    p_cat = np.asarray(p_cat, dtype=float)
    pred = p_cat.argmax(axis=1)
    labels = [cats.index(c) for c in sampled]
    pr, rc, f1, sup = skm.precision_recall_fscore_support(y, pred, labels=labels, zero_division=0)
    cm = skm.confusion_matrix(y, pred, labels=list(range(len(cats))))
    correct = int((pred == y).sum())
    onehot = np.eye(len(cats))[y]
    return {
        "n": int(len(y)), "mapping": CATEGORY_MAP,
        "note": "auxiliary context (D46), not a security decision; evaluated on ground-truth "
                "BLOCK cases; macro-F1 over the 5 sampled categories is NOT comparable with "
                "the 8-class internal macro-F1",
        "top1_accuracy": rate(correct, len(y)),
        "macro_f1_5_sampled": _f(np.mean(f1)),
        "per_category": {c: {"precision": _f(pr[i]), "recall": _f(rc[i]), "f1": _f(f1[i]),
                             "support": int(sup[i]), "support_status": support_status(int(sup[i]))}
                         for i, c in enumerate(sampled)},
        "not_evaluable_not_sampled": [c for c in cats if c not in sampled],
        "confusion_true_rows": {"labels_pred_cols": cats, "rows": {
            c: [int(v) for v in cm[cats.index(c)]] for c in sampled}},
        "predicted_into_unsampled_categories": int(sum(cm[cats.index(c)][cats.index(u)]
                                                       for c in sampled for u in cats
                                                       if u not in sampled)),
        "log_loss_multiclass": _f(-np.log(np.clip(p_cat[np.arange(len(y)), y], ha.EPS, 1)).mean()),
        "brier_multiclass": _f(((p_cat - onehot) ** 2).sum(axis=1).mean()),
        "mean_top1_probability": _f(p_cat.max(axis=1).mean()),
    }


def vector_hash(features):
    """Same relation as build_hybrid_analyzer_v1.vector_hash(feature_vector(f))."""
    vec = [getattr(features, name) for name in ha.FEATURE_FIELDS]
    return sha_text(json.dumps(vec, ensure_ascii=False))


def dev_vector_set(rows):
    """Vectors of TRAIN u VALIDATION fitted rows (JWT out), as at the v2 build."""
    used = [r for r in rows if r["role"] in ("train", "validation") and r["slice"] is None]
    recomputed_ok = sum(1 for r in used if vector_hash(r["features"]) == r["meta_feature_vector_sha256"])
    return {r["meta_feature_vector_sha256"] for r in used}, len(used), recomputed_ok


def descriptive(y, features, analyzer, dev_vectors):
    y = np.asarray(y)
    hashes = [vector_hash(f) for f in features]
    labels_by_vec = {}
    for h, lab in zip(hashes, y.tolist()):
        labels_by_vec.setdefault(h, set()).add(lab)
    mixed = sum(1 for h in hashes if len(labels_by_vec[h]) == 2)
    in_dev = np.array([h in dev_vectors for h in hashes])
    enc = analyzer.attack_encoder
    unseen = {}
    for name in ("method", "content_type"):
        levels = enc.levels[name]
        flags = np.array([getattr(f, name) not in levels for f in features])
        unseen[name] = {"allow": int((flags & (y == 0)).sum()), "block": int((flags & (y == 1)).sum())}
    return {
        "distinct_feature_vectors": len(labels_by_vec),
        "cases_in_vectors_shared_by_allow_and_block": int(mixed),
        "feature_vector_in_dev_train_validation": {
            "allow": int((in_dev & (y == 0)).sum()), "block": int((in_dev & (y == 1)).sum())},
        "encoded_as_unseen_other": unseen,
    }, in_dev


def parts_ok(*keys):
    """k-rule over input-determined partitions: anyone holding the cases can compute
    membership (cell, vector in development, group size) without the model, so every
    published sum restricted to such a partition can be differenced against the per-cell sums.
    Publishing is safe only if every non-empty part of the cross-classification holds >= K_MIN
    cases; then any linear combination of published sums covers whole parts."""
    sizes = Counter(zip(*[np.asarray(k).tolist() for k in keys]))
    return all(v >= K_MIN for v in sizes.values()), (min(sizes.values()) if sizes else 0)


def feature_disjoint_view(y, p, in_dev, cells):
    y, p = np.asarray(y), np.asarray(p, dtype=float)
    keep = ~np.asarray(in_dev)
    n_allow, n_block = int((keep & (y == 0)).sum()), int((keep & (y == 1)).sum())
    ex_allow, ex_block = int((~keep & (y == 0)).sum()), int((~keep & (y == 1)).sum())
    if ex_allow + ex_block == 0:
        return {"status": "IDENTICAL TO THE FULL SET (no case has a vector in development)",
                "allow": n_allow, "block": n_block}
    ok, smallest = parts_ok(cells, in_dev)
    if not ok:
        return {"status": f"SUPPRESSED (k-rule: a cell x in-development part holds {smallest} < "
                          f"{K_MIN} cases; differencing with the per-cell figures would reveal "
                          "individual cases)", "allow": n_allow, "block": n_block}
    if min(n_allow, n_block) < MIN_SUPPORT:
        return {"status": "INSUFFICIENT DATA (a class has < 30 cases); metrics not reported",
                "allow": n_allow, "block": n_block}
    out = headline(y[keep], p[keep], prevalence_note="prevalence of this view (not 50/50): precision "
                   "and accuracy are not comparable with the full set; test-specific (D42)")
    out["status"] = "OK"
    return out


def canonical_request(text):
    """D51 canonical request (headers other than Content-Type excluded), as at the v2 build."""
    method, path, query, ctype, body = design.parse_text(text)
    return gen.canonical_key(f"{method} {path}?{query}\n{ctype}\n{body}")


def d54_groups(texts, features):
    """Group of each case: connected components of "same canonical request OR same feature
    vector" inside the given set — the D54 relation without its generator-family component,
    which External v1 does not have. Group ids are internal and never written."""
    parent = {}

    def find(x):
        while parent.setdefault(x, x) != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    keys = []
    for i, (t, f) in enumerate(zip(texts, features)):
        a, b = "c:" + canonical_request(t), "v:" + vector_hash(f)
        parent[find(a)] = find(b)
        keys.append(a)
    return np.array([find(k) for k in keys])


def error_concentration_counts(y, p, groups):
    """Numbers only: errors, distinct groups holding them, share in the two largest."""
    y, p, groups = np.asarray(y), np.asarray(p, dtype=float), np.asarray(groups)
    pred = p >= THRESHOLD
    out = {}
    for kind, mask in (("false_positives", pred & (y == 0)), ("false_negatives", ~pred & (y == 1))):
        by = Counter(groups[mask].tolist())
        n = int(mask.sum())
        top2 = sum(c for _, c in by.most_common(2))
        out[kind] = {"errors": n, "distinct_groups": len(by),
                     "largest_error_group": max(by.values()) if by else 0,
                     "share_in_top_2_groups": _f(top2 / n) if n else None}
    return out


def group_weighted(y, p, groups, cells, in_dev=None):
    """`in_dev` is passed when the feature-disjoint view is published, so the k-rule covers
    cell x in-development x group size jointly."""
    y, p, groups = np.asarray(y), np.asarray(p, dtype=float), np.asarray(groups)
    sizes = Counter(groups.tolist())
    mixed = sum(1 for g in sizes if len(set(y[groups == g].tolist())) == 2)

    def auc(idx):
        return skm.roc_auc_score(y[idx], p[idx]) if len(set(y[idx].tolist())) == 2 else None

    def brier(idx):
        return float(((p[idx] - y[idx]) ** 2).mean())

    pooled = sum(v for v in sizes.values() if v > 1)
    base = {"n_groups": len(sizes), "groups_with_more_than_one_case": sum(1 for v in sizes.values() if v > 1),
            "cases_in_groups_with_more_than_one_case": pooled}
    group_size = np.array([sizes[g] for g in groups.tolist()])
    keys = (cells, group_size) if in_dev is None else (cells, in_dev, group_size)
    ok, smallest = parts_ok(*keys)
    if not ok:
        return {**base, "status": f"SUPPRESSED (k-rule: a cell x {'in-development x ' if in_dev is not None else ''}"
                                  f"group-size part holds {smallest} < {K_MIN} cases)"}
    return {
        "status": "OK",
        "relation": "D54 without the generator-family component (not defined for External v1): "
                    "connected components of same D51 canonical request OR same 34-feature vector, "
                    "inside External v1. Diagnostic only; never replaces the row-weighted metrics",
        **base, "groups_with_both_labels": mixed,
        "metrics_each_group_weighs_1": ha.attack_metrics_group_weighted(y, p, groups),
        "error_concentration": error_concentration_counts(y, p, groups),
        "group_bootstrap": {k: ha.group_bootstrap(groups, fn, n_boot=GROUP_BOOT_N, seed=BOOT_SEED)
                            for k, fn in (("roc_auc", auc), ("brier", brier))},
    }


def by_placement_visibility(y, p, placements):
    """BLOCK recall by whether the payload sits where RequestFeatures can see it."""
    y, p = np.asarray(y), np.asarray(p, dtype=float)
    vis = np.array([PLACEMENT_VISIBILITY.get(pl, "unmapped") for pl in placements])
    out = {"mapping": PLACEMENT_VISIBILITY,
           "note": "header / cookie payloads are invisible to the Analyzer by construction (D44): "
                   "a structural blind spot like JWT (D48), not a generalization result"}
    parts = [v for v in ("visible", "invisible", "unmapped")
             if not (v == "unmapped" and not ((y == 1) & (vis == v)).any())]
    # the parts partition the BLOCK cases, whose total is derivable from the cells: a mean is
    # published only if every part holds >= K_MIN cases (k-rule)
    means_ok = all(int(((y == 1) & (vis == v)).sum()) >= K_MIN for v in parts)
    for v in parts:
        mask = (y == 1) & (vis == v)
        n = int(mask.sum())
        tp = int((mask & (p >= THRESHOLD)).sum())
        out[v] = {"block_cases": n, "support_status": support_status(n), "tp": tp, "fn": n - tp,
                  "recall_at_0_5": rate(tp, n),
                  "mean_attack": (_f(p[mask].mean()) if n else None) if means_ok
                  else f"suppressed (a part has < {K_MIN} cases)"}
    return out


def internal_reference(path=None):
    """Frozen run-002 INTERNAL TEST figures of the same Analyzer (feature-disjoint view, D51
    primary), read as published. Second look, not untouched (D54)."""
    path = INTERNAL_RESULTS if path is None else path
    d = load_json(path)
    v = d["views"]["internal_test_feature_disjoint"]
    h = v["attack"]["hist_gb"]
    gw = h.get("group_weighted (diagnostic)", {})
    return {"source": rel(path), "sha256": sha256_file(path), "label": d["label"],
            "view": "internal_test_feature_disjoint", "n": h["n"], "prevalence_block": h["prevalence"],
            "comparable": {k: h[k] for k in ("roc_auc", "brier", "log_loss", "ece", "recall", "fpr")},
            "pr_auc_note": "PR-AUC, precision and accuracy depend on prevalence (internal "
                           f"{h['prevalence']}, External v1 0.5): not compared",
            "group_weighted_fpr_recall": {"fpr": gw.get("fpr"), "recall": gw.get("recall")},
            "category_macro_f1_8_classes": v["category"]["hist_gb"]["macro_f1"]}


def compute_aggregates(y, p_attack, cells, cat_true_cells, p_cat_block, features, analyzer,
                       dev_vectors, texts, placements, n_boot=BOOT_N):
    y = np.asarray(y)
    desc, in_dev = descriptive(y, features, analyzer, dev_vectors)
    groups = d54_groups(texts, features)
    fd = feature_disjoint_view(y, p_attack, in_dev, cells)
    gw = group_weighted(y, p_attack, groups, cells, in_dev if fd["status"] == "OK" else None)
    return {
        "attack_headline": headline(y, p_attack),
        "attack_calibration": {"ece_15_bins": ha.reliability_bins(y, p_attack)["ece"],
                               "reliability": reliability_suppressed(y, p_attack)},
        "attack_bootstrap": stratified_bootstrap(y, p_attack, n_boot=n_boot),
        "per_cell": per_cell(y, p_attack, cells),
        "block_by_payload_visibility": by_placement_visibility(y, p_attack, placements),
        "group_weighted_diagnostic (D55)": gw,
        "category_on_block": category_block(cat_true_cells, p_cat_block),
        "descriptive": desc,
        "feature_disjoint_view": fd,
        "not_applicable": NOT_APPLICABLE,
    }


NOT_APPLICABLE = {
    "generator-family component of the D54 group relation":
        "NOT APPLICABLE: External v1 has no generator; groups use the other two D54 relations",
    "unsupported_jwt (D48)": "NOT EVALUABLE: no JWT case in External v1",
    "categories ssti, open_redirect, other_attack": "NOT EVALUABLE: not sampled",
    "14 of 19 V4 attack reasons": "NOT EVALUABLE: External v1 samples 5 categories",
    "L2 / L3 / latency": "NOT APPLICABLE: offline evaluation",
    "secondary breakdowns": "NOT COMPUTED: not pre-registered for the Analyzer",
    "operating threshold / threshold sweep / calibrator": "NOT COMPUTED (D53, D55)",
    "joint V4 x Analyzer counts": "NOT COMPUTED: disagreement analysis starts on development "
                                  "or diagnostic data; on External v1 it would size a Hybrid "
                                  "component from test cases (D45)",
}


# ── aggregate-only guard ────────────────────────────────────────────────────
def assert_aggregate_only(obj, forbidden_strings, max_list=MAX_LIST):
    """Refuse output that could carry per-case data: a forbidden string (case id, request
    SHA-256, request text) anywhere, a `request_text` key, or a list longer than max_list."""
    forbidden = [s for s in forbidden_strings if s]
    found = []

    def walk(o, path):
        if isinstance(o, (np.ndarray, np.generic)):
            found.append(f"numpy value at {path}")
            return
        if isinstance(o, dict):
            if len(o) > MAX_DICT:
                found.append(f"dict of {len(o)} > {MAX_DICT} keys at {path}")
            for k, v in o.items():
                if str(k) in ("request_text", "case_id", "case_ids", "predictions",
                              "probabilities"):
                    found.append(f"forbidden key at {path}")
                walk(k, path + "/<key>")
                walk(v, f"{path}/{k}")
        elif isinstance(o, (list, tuple)):
            if len(o) > max_list:
                found.append(f"list of {len(o)} > {max_list} at {path}")
            for i, v in enumerate(o):
                walk(v, f"{path}[{i}]")
        elif isinstance(o, str):
            if any(s in o for s in forbidden):
                found.append(f"forbidden string at {path}")

    walk(obj, "")
    if found:
        # The paths name JSON keys of our own output, never case data.
        raise PreflightError(f"aggregate-only check failed at {len(found)} place(s)")
    return True


def forbidden_from_cases(rows):
    out = set()
    for r in rows:
        out.add(r["case_id"])
        out.add(r["request_sha256"])
        text = r["request_text"]
        if len(text) >= 24:
            out.add(text)
    return out


# ── the single run ──────────────────────────────────────────────────────────
class Console:
    """Prints and keeps what was printed; nothing case-level is ever passed to it."""

    def __init__(self):
        self.lines = []

    def __call__(self, msg):
        print(msg, flush=True)
        self.lines.append(msg)


def preflight(allow_real_external):
    """Every check that needs no model call. Returns (record, rows, frozen, problems).
    Paths are the module's, resolved at call time."""
    cases_path, manifest_path, sums_path, report_dir = REAL_CASES, REAL_MANIFEST, REAL_EXT_SUMS, REPORT_DIR
    problems = []
    for name in ("run_attempt.json", "aggregate_results.json", "run_failure.json"):
        if os.path.exists(os.path.join(report_dir, name)):
            problems.append(f"{name} already exists: the single run was already started")
    git = verify_git()
    prereg_path = os.path.join(report_dir, "PREREGISTRATION.json")
    prereg = load_json(prereg_path) if os.path.exists(prereg_path) else None
    if prereg is None:
        problems.append("PREREGISTRATION.json missing")
    elif prereg.get("sha256") != _prereg_hashes(report_dir) or None in prereg["sha256"].values():
        problems.append("protocol / evaluator / tests differ from PREREGISTRATION.json")
    elif prereg.get("git_head") != git.get("head"):
        problems.append("HEAD differs from the commit recorded in PREREGISTRATION.json")
    problems += git["problems"]
    env, env_problems = verify_environment()
    problems += env_problems
    frozen, model_checks = verify_model_and_reports()
    problems += model_checks["problems"]
    rows, ext = verify_external(cases_path, manifest_path, sums_path,
                                allow_real_external=allow_real_external)
    problems += ext["problems"]
    # model contract and development relation: no External v1 data, no inference
    ctx, ctx_checks = {}, {}
    if not model_checks["problems"]:
        analyzer = load_model(os.path.join(REPO_ROOT, ANCHORS["model_path"]), ANCHORS["model_sha256"])
        contract_problems = verify_feature_contract(
            analyzer, frozen, load_json(os.path.join(RUN002_DIR, "preprocessing.json")))
        problems += contract_problems
        dev_rows = ha.load_dataset(DATASET_V2, DATASET_V2_MANIFEST, verify=True,
                                   roles={"train", "validation"})
        dev_vectors, dev_used, dev_recomputed = dev_vector_set(dev_rows)
        del dev_rows
        if dev_recomputed != dev_used or dev_used == 0:
            problems.append("development vector relation does not recompute")
        ctx = {"analyzer": analyzer, "dev_vectors": dev_vectors}
        ctx_checks = {"feature_contract_problems": contract_problems, "dev_rows_used": dev_used,
                      "dev_hash_recomputed_ok": dev_recomputed}
    protocol = os.path.join(report_dir, "PROTOCOL.md")
    record = {
        "run_id": RUN_ID, "utc": now(), "model_called": False,
        "model_loaded_and_contract_checked_no_inference": bool(ctx), **ctx_checks,
        "git": git, "environment": env, "environment_problems": env_problems,
        "model_and_frozen_reports": model_checks, "external_v1": ext,
        "protocol_sha256": sha256_file(protocol) if os.path.exists(protocol) else None,
        "evaluator_sha256": sha256_file(os.path.abspath(__file__)),
        "tests_sha256": _tests_sha(),
        "preregistration": prereg,
        "problems": problems, "passed": not problems,
    }
    return record, rows, frozen, problems, ctx


PREREG_FILES = ("PROTOCOL.md", "evaluator", "tests")


def _prereg_hashes(report_dir):
    protocol = os.path.join(report_dir, "PROTOCOL.md")
    return {"PROTOCOL.md": sha256_file(protocol) if os.path.exists(protocol) else None,
            "evaluator": sha256_file(os.path.abspath(__file__)), "tests": _tests_sha()}


def write_prereg(report_dir=None):
    """Pre-registration record, created exclusively before exposure. Not a commit (the owner
    asked for none): it is self-attested, so the same hashes are also published in the session
    transcript before the run, and the owner is asked to commit protocol, code and results."""
    report_dir = REPORT_DIR if report_dir is None else report_dir
    rec = {"run_id": RUN_ID, "utc": now(), "git_head": _git("rev-parse", "HEAD").stdout.strip(),
           "sha256": _prereg_hashes(report_dir), "model_called": False,
           "note": "written before any Analyzer call on External v1; `run` refuses to start unless "
                   "these hashes still match"}
    write_exclusive(os.path.join(report_dir, "PREREGISTRATION.json"), dumps(rec))
    return rec


def _tests_sha():
    p = os.path.join(REPO_ROOT, "tests", "test_analyzer_external_v1.py")
    return sha256_file(p) if os.path.exists(p) else None


def run_synthetic_tests():
    r = subprocess.run([sys.executable, "-m", "unittest", TEST_MODULE],
                       cwd=REPO_ROOT, capture_output=True, text=True)
    tail = (r.stderr or "").strip().splitlines()[-1:] or [""]
    return r.returncode == 0, tail[0]


def v4_published_marginals(path=None):
    path = V4_SUMMARY if path is None else path
    l1 = load_json(path)["L1"]
    return {"source": rel(path), "measured_as": "L1 of the gateway run external-v1-run-001 "
            "(repetition 1, full gateway); NOT offline, NOT a cascade component",
            "tp": l1["TP"], "tn": l1["TN"], "fp": l1["FP"], "fn": l1["FN"],
            "recall_block": l1["recall_block_ADR"], "fpr": l1["FPR"],
            "per_cell_fpr_or_recall": {c: (v["fpr"] or v["recall_block"])
                                       for c, v in l1["per_cell"].items()}}


def cmd_preflight(args):
    record, _, _, problems, _ = preflight(allow_real_external=True)
    if args.record:
        write_exclusive(os.path.join(REPORT_DIR, "preflight.json"), dumps(record))
    print(dumps({k: record[k] for k in ("passed", "problems")}))
    print(f"external_v1: {record['external_v1']['n_cases']} cases, "
          f"{record['external_v1']['allow']} ALLOW / {record['external_v1']['block']} BLOCK; "
          f"model called: no")
    return 0 if not problems else 2


def cmd_prereg(args):
    rec = write_prereg()
    print(dumps(rec))
    return 0


def cmd_run(args):
    say = Console()
    if not args.confirm_single_run:
        say("REFUSED: pass --confirm-single-run (External v1 is evaluated exactly once)")
        return 2
    attempt_path = os.path.join(REPORT_DIR, "run_attempt.json")
    if any(os.path.exists(os.path.join(REPORT_DIR, n))
           for n in ("run_attempt.json", "aggregate_results.json", "run_failure.json")):
        say("REFUSED: run_attempt.json exists — the single run was already started; no retry")
        return 2
    say(f"[{now()}] {RUN_ID}: preflight (artifact loaded and checked; no inference)")
    record, rows, frozen, problems, ctx = preflight(allow_real_external=True)
    if problems:
        say(f"PREFLIGHT FAILED ({len(problems)} problem(s)); the run did not start:")
        for p in problems:
            say(f"  - {p}")
        return 2
    say("preflight: all checks passed")
    ok, tail = run_synthetic_tests()
    say(f"synthetic tests: {'passed' if ok else 'FAILED'} ({tail})")
    if not ok:
        say("the run did not start")
        return 2

    # ── START: from here on this counts as the single run ──
    command = " ".join([os.path.relpath(sys.executable, REPO_ROOT)] +
                       [rel(os.path.abspath(sys.argv[0]))] + sys.argv[1:])
    attempt = {"run_id": RUN_ID, "started_utc": now(), "command": command,
               "git_head": record["git"]["head"], "branch": record["git"]["branch"],
               "uncommitted_paths_at_start": record["git"]["uncommitted_paths"],
               "protocol_sha256": record["protocol_sha256"],
               "evaluator_sha256": record["evaluator_sha256"],
               "tests_sha256": record["tests_sha256"], "synthetic_tests": "passed",
               "model_sha256": record["model_and_frozen_reports"]["model_sha256"],
               "cases_sha256": record["external_v1"]["cases_sha256"],
               "integrity_hash": record["external_v1"]["integrity_hash"],
               "note": "created exclusively before any inference; its existence blocks every later start",
               "preflight_at_start": record}
    write_exclusive(attempt_path, dumps(attempt))
    say(f"[{attempt['started_utc']}] run_attempt.json written — single run started")

    stage = "extract-features"
    try:
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            analyzer, dev_vectors = ctx["analyzer"], ctx["dev_vectors"]
            dev_used, dev_recomputed = record["dev_rows_used"], record["dev_hash_recomputed_ok"]
            stage = "extract-features"
            y = np.array([LABEL[r["expected_decision"]] for r in rows], dtype=int)
            cells = [r["primary_cell"] for r in rows]
            features = extract([r["request_text"] for r in rows])
            stage = "inference"
            p_attack, p_cat, contract = score(analyzer, features)
            if contract["non_finite_attack"]:
                raise PreflightError("non-finite probability")
            stage = "metrics"
            block = np.flatnonzero(y == 1)
            aggregates = compute_aggregates(y, p_attack, cells, [cells[i] for i in block],
                                            p_cat[block], features, analyzer, dev_vectors,
                                            [r["request_text"] for r in rows],
                                            [r.get("payload_placement") for r in rows])
            aggregates["internal_reference_second_look"] = internal_reference()
            aggregates["contract_check"] = contract
            stage = "aggregate-check"
            forbidden = forbidden_from_cases(rows)
        result = {
            "run_id": RUN_ID, "type": "EVALUATION — offline, aggregate only (D53)",
            "label": "One post-freeze aggregate evaluation of the frozen Analyzer on External "
                     "Test v1. Not a gateway or cascade evaluation. 0.5 is reporting-only (D55).",
            "analyzer_version": analyzer.version, "model_sha256": ANCHORS["model_sha256"],
            "external_v1": {"cases_sha256": record["external_v1"]["cases_sha256"],
                            "integrity_hash": record["external_v1"]["integrity_hash"],
                            "n": int(len(y)), "allow": int((y == 0).sum()), "block": int((y == 1).sum()),
                            "per_cell": record["external_v1"]["per_cell"]},
            "input": "frozen D1 text of each case, verbatim -> request_features.extract_features "
                     "(request-features/v2, 34 fields) -> encoders frozen in the artifact",
            "dev_vector_relation": {"dev_rows_used": dev_used, "hash_recomputed_ok": dev_recomputed},
            **aggregates,
            "v4_published_marginals_for_side_by_side": v4_published_marginals(),
            "warnings_during_run": dict(Counter(w.category.__name__ for w in caught)),
        }
        assert_aggregate_only(result, forbidden)
        stage = "write"
        finished = now()
        write_exclusive(os.path.join(REPORT_DIR, "aggregate_results.json"), dumps(result))
        meta = {"run_id": RUN_ID, "started_utc": attempt["started_utc"], "finished_utc": finished,
                "command": command, "git_head": record["git"]["head"],
                "environment": record["environment"],
                "evaluator_sha256": record["evaluator_sha256"],
                "protocol_sha256": record["protocol_sha256"], "tests_sha256": record["tests_sha256"],
                "frozen_selection_sha256": record["model_and_frozen_reports"]["frozen_selection_sha256"],
                "aggregate_results_sha256": sha256_file(os.path.join(REPORT_DIR, "aggregate_results.json")),
                "runs_started": 1, "retries": 0}
        write_exclusive(os.path.join(REPORT_DIR, "run_metadata.json"), dumps(meta))
    except BaseException as exc:   # noqa: BLE001 — record class only, never message / traceback
        failure = {"run_id": RUN_ID, "failed_utc": now(), "stage": stage,
                   "exception_class": type(exc).__name__, "detail": SAFE,
                   "policy": "no automatic retry; External v1 is not re-run; owner decides"}
        try:
            write_exclusive(os.path.join(REPORT_DIR, "run_failure.json"), dumps(failure))
        except OSError:
            pass
        say(f"RUN FAILED at stage '{stage}' ({type(exc).__name__}); recorded; no retry")
        _write_console(say)
        return 3

    h, t = result["attack_headline"], result["attack_headline"]["at_reporting_threshold_0_5"]
    say(f"[{finished}] done — n {h['n']} ({h['positives_block']} BLOCK / {h['negatives_allow']} ALLOW)")
    say(f"  ROC-AUC {h['threshold_free']['roc_auc']} · PR-AUC {h['threshold_free']['pr_auc']} · "
        f"Brier {h['threshold_free']['brier']} · log loss {h['threshold_free']['log_loss']} · "
        f"ECE {result['attack_calibration']['ece_15_bins']}")
    say(f"  @0.5 (reporting-only): TP {t['tp']} · TN {t['tn']} · FP {t['fp']} · FN {t['fn']}")
    say("  wrote run_attempt.json, aggregate_results.json, run_metadata.json, console.log")
    _write_console(say)
    return 0


def _write_console(say):
    try:
        write_exclusive(os.path.join(REPORT_DIR, "console.log"), "\n".join(say.lines) + "\n")
    except OSError:
        pass


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.strip().split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    pf = sub.add_parser("preflight", help="integrity checks only; the model is never called")
    pf.add_argument("--record", action="store_true", help="also write preflight.json (exclusive)")
    sub.add_parser("prereg", help="write PREREGISTRATION.json (exclusive); no model call")
    rn = sub.add_parser("run", help="the single aggregate evaluation")
    rn.add_argument("--confirm-single-run", action="store_true")
    args = ap.parse_args(argv)
    try:
        return {"preflight": cmd_preflight, "prereg": cmd_prereg, "run": cmd_run}[args.cmd](args)
    except PreflightError as exc:
        # Our own messages: fixed text and counts only.
        print(f"STOPPED: {exc}", flush=True)
        return 2
    except BaseException as exc:   # noqa: BLE001
        print(f"STOPPED: {type(exc).__name__} ({SAFE})", flush=True)
        return 2


if __name__ == "__main__":
    sys.exit(main())
