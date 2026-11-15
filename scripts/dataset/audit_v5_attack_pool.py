#!/usr/bin/env python3
"""Issue #64 / subagent B: quality & label audit of the PATT attack-payload pool.

Audit population = output of the V4 extraction (``parse_dataset_v4.extract_sources``
over PayloadsAllTheThings at a pinned commit) plus the hardcoded categories of
``build_hardcoded_sources``. No protected set (External Test v1, V4 eval /
INTERNAL TEST, probes) is read. No model is run. Nothing is written into PATT.

Subcommands
  extract    run the V4 extraction in memory, print per-category counts (JSON)
  sample     deterministic stratified sample -> sample.jsonl (+ sampling block
             in summary.json)
  summarize  read annotations.jsonl -> per-category / overall label counts and
             Wilson 95% intervals -> summary.json ("results" block)
  filters    evaluate candidate NEGATIVE structural filters on the full pool and
             against the annotations -> summary.json ("filter_evaluation" block)
  agreement  compare annotations.jsonl with the blind second annotation
             (annotations_second.jsonl, different model), apply the coordinator's
             adjudication_overrides.jsonl -> adjudicated.jsonl and
             summary.json ("second_annotation" block). LLM-LLM agreement is not
             human validation.
  human-sample  stratified, deterministic, label-blind subsample for independent
             human review -> human_review/human_review_sample.csv (never overwritten
             without --force)
  human-batch   print one label-blind batch (--batch N, --size 12); creates the empty
             human_review/human_labels.csv template once, never overwrites it
  human-compare after the human review is COMPLETE: agreement with adjudicated.jsonl,
             human per-category rates, disagreement list -> human_review/comparison.json

Annotation is a separate manual step (LLM-assisted audit, single annotator,
NOT independent ground truth); see the README in the output folder.

Run with an interpreter that can import parse_dataset_v4 (stdlib only), e.g.
``python3 scripts/dataset/audit_v5_attack_pool.py extract``.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import subprocess
import sys
from collections import Counter, OrderedDict

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))
DEFAULT_OUT_DIR = os.path.join(REPO_ROOT, "reports", "v5", "freeze-prep",
                               "E_attack_pool_audit")
DEFAULT_PATT = os.path.expanduser("~/PayloadsAllTheThings")
PINNED_PATT_COMMIT = "e961fef231d8327bae83b563fab50aec2e6b77c0"
DEFAULT_SEED = "v5-attack-audit-v1"

# Tiers follow the (not yet approved) V5 plan; they only drive the allocation floors.
TIERS: "OrderedDict[str, tuple[str, int]]" = OrderedDict([
    # category -> (tier, minimum n)
    ("SQL Injection", ("ml_primary", 30)),
    ("XSS Injection", ("ml_primary", 30)),
    ("Directory Traversal", ("ml_primary", 30)),
    ("File Inclusion", ("ml_primary", 30)),
    ("Command Injection", ("ml_primary", 30)),
    ("Server Side Template Injection", ("ml_primary", 30)),
    ("Server Side Request Forgery", ("ml_primary", 30)),
    ("Open Redirect", ("ml_primary", 30)),
    ("NoSQL Injection", ("report_only", 15)),
    ("LDAP Injection", ("report_only", 15)),
    ("XPath Injection", ("report_only", 15)),
    ("CRLF Injection", ("report_only", 15)),
    ("XXE Injection", ("conditional", 15)),
    ("GraphQL Injection", ("conditional", 15)),
    ("JSON Web Token", ("out_of_ml", 10)),
    ("Cross-Site Request Forgery", ("out_of_ml", 10)),
    ("HTTP Parameter Pollution", ("out_of_ml", 10)),
    ("Request Smuggling", ("out_of_ml", 10)),
    ("Insecure Deserialization", ("out_of_ml", 10)),
])
PROPORTIONAL_TOTAL = 300   # nominal total used for the proportional term
PROPORTIONAL_CAP = 36      # cap on the proportional term (keeps annotation effort bounded)

LABEL_CLASSES = ("VERIFIABLE", "PROBABLY_CORRECT", "UNCERTAIN", "INCORRECT")
FAILURE_MODES = ("prose", "tool_output", "placeholder", "markdown_residue",
                 "setup_command", "reference_url", "wrong_category", "truncated",
                 "encoding_garbage", "other")
Z95 = 1.959963984540054


# ───────────────────────── pure helpers ─────────────────────────
def sha256_hex(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def wilson_interval(k: int, n: int, z: float = Z95) -> tuple[float, float]:
    """Wilson score interval for a binomial proportion. (0,1) when n == 0."""
    if n <= 0:
        return (0.0, 1.0)
    if not 0 <= k <= n:
        raise ValueError(f"k={k} outside [0, n={n}]")
    p = k / n
    z2 = z * z
    denom = 1.0 + z2 / n
    centre = (p + z2 / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z2 / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def build_pool(rows: list[dict], canon) -> "OrderedDict[str, list[dict]]":
    """Group extracted rows into per-category pools of unique canonical payloads.

    ``rows`` are dicts with payload/category/source[/structural]. The first
    occurrence (extraction order) is the representative. Structural rows
    (JSON blobs) use the raw payload as identity, as in the V4 pipeline.
    Returns category -> list of {category, payload, canonical_key,
    canonical_sha256, source_file}; each pool sorted by canonical_sha256 of the
    key only for output stability (sampling order is defined separately).
    """
    pools: dict[str, dict[str, dict]] = {}
    for r in rows:
        key = r["payload"] if r.get("structural") else canon(r["payload"])
        cat = r["category"]
        d = pools.setdefault(cat, {})
        if key not in d:
            d[key] = {"category": cat, "payload": r["payload"], "canonical_key": key,
                      "canonical_sha256": sha256_hex(key), "source_file": r["source"]}
    out: "OrderedDict[str, list[dict]]" = OrderedDict()
    for cat in sorted(pools):
        out[cat] = sorted(pools[cat].values(), key=lambda e: e["canonical_key"])
    return out


def pool_listing_sha256(pools: dict[str, list[dict]]) -> str:
    """sha256 of the sorted listing 'category<TAB>sha256(canonical_key)' lines."""
    lines = sorted(f"{cat}\t{e['canonical_sha256']}" for cat, es in pools.items() for e in es)
    return sha256_hex("\n".join(lines))


def allocate(pool_sizes: dict[str, int], tiers=TIERS, total: int = PROPORTIONAL_TOTAL,
             cap: int = PROPORTIONAL_CAP) -> dict[str, int]:
    """n_c = min(pool_c, max(floor_tier(c), min(cap, round(total * pool_c / sum_pool)))).

    The floor protects small categories that proportional allocation would starve;
    the cap bounds annotation effort on the huge wordlist-dominated pools.
    """
    s = sum(pool_sizes.values()) or 1
    n = {}
    for cat, size in pool_sizes.items():
        floor = tiers[cat][1] if cat in tiers else 10
        prop = int(round(total * size / s))
        n[cat] = min(size, max(floor, min(cap, prop)))
    return n


def order_key(seed: str, category: str, canonical_key: str) -> str:
    return sha256_hex(f"{seed}\x00{category}\x00{canonical_key}")


def stratified_sample(pools: dict[str, list[dict]], n_per_cat: dict[str, int],
                      seed: str) -> list[dict]:
    """Deterministic, order-independent: rank each pool by sha256(seed NUL cat NUL key)."""
    out = []
    for cat in sorted(pools):
        ranked = sorted(pools[cat], key=lambda e: order_key(seed, cat, e["canonical_key"]))
        for rank, e in enumerate(ranked[: n_per_cat.get(cat, 0)], start=1):
            out.append({"category": cat, "payload": e["payload"],
                        "canonical_sha256": e["canonical_sha256"],
                        "source_file": e["source_file"], "pool_rank": rank})
    # sample ids assigned in (category, rank) order -> stable
    for i, row in enumerate(out, start=1):
        row["sample_id"] = f"A{i:04d}"
    return [{k: r[k] for k in ("sample_id", "category", "payload", "canonical_sha256",
                               "source_file", "pool_rank")} for r in out]


def validate_annotations(sample: list[dict], ann: list[dict]) -> list[str]:
    errs = []
    ids = {r["sample_id"] for r in sample}
    seen = Counter(a.get("sample_id") for a in ann)
    for sid, c in seen.items():
        if c > 1:
            errs.append(f"duplicate annotation for {sid}")
        if sid not in ids:
            errs.append(f"annotation for unknown sample_id {sid}")
    for sid in sorted(ids - set(seen)):
        errs.append(f"sample_id {sid} has no annotation")
    for a in ann:
        if a.get("label_class") not in LABEL_CLASSES:
            errs.append(f"{a.get('sample_id')}: bad label_class {a.get('label_class')!r}")
        fm = a.get("failure_mode")
        if a.get("label_class") == "INCORRECT" and fm not in FAILURE_MODES:
            errs.append(f"{a.get('sample_id')}: INCORRECT needs failure_mode in vocabulary")
        if fm not in (None, "none") and fm not in FAILURE_MODES:
            errs.append(f"{a.get('sample_id')}: bad failure_mode {fm!r}")
    return errs


def _stat_block(counts: Counter, n: int) -> dict:
    bad = counts["UNCERTAIN"] + counts["INCORRECT"]
    inc = counts["INCORRECT"]
    lo_b, hi_b = wilson_interval(bad, n)
    lo_i, hi_i = wilson_interval(inc, n)
    return {
        "n": n,
        "counts": {c: counts[c] for c in LABEL_CLASSES},
        "not_usable_uncertain_or_incorrect": {
            "k": bad, "rate": (bad / n if n else None), "wilson95": [lo_b, hi_b]},
        "incorrect_only": {
            "k": inc, "rate": (inc / n if n else None), "wilson95": [lo_i, hi_i]},
    }


def summarize(sample: list[dict], ann: list[dict]) -> dict:
    """Per-category and overall label counts + Wilson intervals.

    Also reports failure-mode counts (by label class) and a per-source-file
    family breakdown (category, source file) -> label counts.
    """
    meta = {r["sample_id"]: r for r in sample}
    by_cat: dict[str, Counter] = {}
    fm_by_cat: dict[str, Counter] = {}
    better: dict[str, Counter] = {}
    fam: dict[str, Counter] = {}
    overall, fm_all = Counter(), Counter()
    for a in ann:
        m = meta[a["sample_id"]]
        cat, lc, fm = m["category"], a["label_class"], a.get("failure_mode")
        by_cat.setdefault(cat, Counter())[lc] += 1
        overall[lc] += 1
        fam.setdefault(f"{cat} :: {m['source_file']}", Counter())[lc] += 1
        if fm not in (None, "none"):
            key = f"{lc}:{fm}"
            fm_by_cat.setdefault(cat, Counter())[key] += 1
            fm_all[key] += 1
        if a.get("better_category"):
            better.setdefault(cat, Counter())[a["better_category"]] += 1
    per_cat = {}
    for cat in sorted(by_cat):
        blk = _stat_block(by_cat[cat], sum(by_cat[cat].values()))
        blk["failure_modes_by_class"] = dict(sorted(fm_by_cat.get(cat, Counter()).items()))
        blk["better_category_for_wrong_category"] = dict(sorted(better.get(cat, Counter()).items()))
        per_cat[cat] = blk
    ov = _stat_block(overall, sum(overall.values()))
    ov["failure_modes_by_class"] = dict(sorted(fm_all.items()))
    families = {k: {c: v[c] for c in LABEL_CLASSES} for k, v in sorted(fam.items())}
    return {"overall_unweighted_sample": ov, "per_category": per_cat,
            "family_breakdown_by_source_file": families}


def read_jsonl(path: str) -> list[dict]:
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def write_jsonl(path: str, rows: list[dict]) -> None:
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")


# ───────────────────────── candidate NEGATIVE structural filters ─────────────────────────
# Proposed V5 acceptance filters. They detect documentation / tool / code residue and
# broken encodings. They deliberately contain NO attack-keyword signatures (no SELECT,
# <script, ../ ...), to avoid CSIC-style circular labelling (audit F6).
_HEX_ESC = re.compile(r"%(?:[0-9a-fA-F]{2}|u[0-9a-fA-F]{4})")
_URLENC_CATS = {"Directory Traversal", "File Inclusion", "Open Redirect",
                "Server Side Request Forgery", "CRLF Injection"}
_PATH_CATS = {"Directory Traversal", "File Inclusion"}
_CODE_START = re.compile(
    r"^(import |from \w+ import |def |class |require |puts\(|print\(|echo var_dump|if \(|"
    r"if [^=]*:\s*$|for \w+ in |while |fields\.|\$\w+ = |var |const |let |\w+ = (open|f?\")|"
    r"f = |flag = |payload = )")
_ASSIGN = re.compile(r"^[A-Za-z_][\w.]*(\[\d+\])?\s*\+?=\s*\S")
_TOOL_START = re.compile(r"^(\./)?(sqlmap|ysoserial(\.exe)?|iconv|python3?|nmap|pip|npm|gem|git)\b")
_PROSE_WORD = re.compile(r"[A-Za-z][a-z'’,.()*\-]*")


def structural_flags(payload: str, category: str) -> list[str]:
    """Names of negative structural rules that fire on ``payload`` (pure, no I/O)."""
    s = payload.strip()
    f: list[str] = []
    n_pct = s.count("%")
    if n_pct and category in _URLENC_CATS:
        bad = n_pct - len(_HEX_ESC.findall(s))
        if bad >= 1 and bad / n_pct >= 0.2:
            f.append("malformed_percent")
    if category in _PATH_CATS:
        if len(re.findall(r"0x[0-9a-fA-F]{2}", s)) >= 2:
            f.append("literal_0x_escape")
        if "??" in s or ".?" in s:
            f.append("qmark_runs")
    if category == "XSS Injection" and re.search(r"\\x[0-9A-Fa-f]{2}", s):
        f.append("literal_backslash_x")
    if re.search(r"\{[a-z_]{3,}\}|%\([a-z_]+\)s|COLLABORATOR", s):
        f.append("placeholder_token")
    if re.search(r"\s:\s*(OK|KO)\s*$", s):
        f.append("doc_annotation")
    if (" " in s and re.match(r"^(https?://|0x|\d)", s)
            and re.match(r"^\S+\s+(=|-|:)?\s*[A-Z][a-z]+(\s+\(?[A-Za-z+]+\)?){0,5}$", s)):
        f.append("url_plus_label")
    if (re.search(r"\s(//|#)\s+[A-Z][\w-]*(\s+[\w-]+){0,4}\s*$", s)
            and not re.search(r"['\"]\s*(//|#)", s)):
        f.append("trailing_doc_comment")
    if (re.match(r"^\w+@[\w.-]+:[~/\w.]*[$#] ", s) or re.match(r"^\[[+*!\-]\]", s)
            or re.match(r"^(ERROR|Traceback|Exception|Warning)\b", s)
            or re.search(r"Unhandled \w+ exception", s) or re.match(r"^Name:\s", s)
            or s.endswith("?:") or s.endswith("):")):
        f.append("tool_output_marker")
    if _CODE_START.match(s) or (_ASSIGN.match(s) and not re.match(r"^[\w.]+=\S", s)):
        f.append("source_code_line")
    if re.search(r"[\{\(\[,]\s*$", s) and not re.search(r"[\}\)\]]", s):
        f.append("dangling_opener")
    if re.match(r"^[A-Za-z_]\w*$", s) and len(s) <= 24 and category != "SQL Injection":
        f.append("bare_word")
    if re.match(r"^</?[a-zA-Z0-9]+>$", s):
        f.append("bare_html_tag")
    if _TOOL_START.match(s) or (category != "Command Injection" and re.match(r"^(curl|wget|cat) ", s)):
        f.append("tool_invocation")
    words = s.split()
    if len(words) >= 7 and sum(bool(_PROSE_WORD.fullmatch(w)) for w in words) / len(words) >= 0.7:
        f.append("prose_sentence")
    return f


def evaluate_filters(pools: dict[str, list[dict]], sample: list[dict],
                     ann: list[dict]) -> dict:
    """Apply structural_flags to the whole pool and cross-tab against annotations.

    ``estimated_clean``: N_after_filter * share(VERIFIABLE+PROBABLY_CORRECT) among the
    annotated sample items that SURVIVE the filters (Wilson 95% on that share, scaled).
    The filters were designed after inspecting this very sample, so the survivor
    shares are in-sample (optimistic); a fresh sample would be needed to confirm.
    """
    lab = {a["sample_id"]: a["label_class"] for a in ann}
    out = {}
    for cat in sorted(pools):
        n_pool = len(pools[cat])
        flagged = [bool(structural_flags(e["payload"], cat)) for e in pools[cat]]
        n_flag = sum(flagged)
        rule_counts = Counter(r for e in pools[cat] for r in structural_flags(e["payload"], cat))
        srows = [r for r in sample if r["category"] == cat]
        tab = {"flagged": Counter(), "survivors": Counter()}
        for r in srows:
            key = "flagged" if structural_flags(r["payload"], cat) else "survivors"
            tab[key][lab[r["sample_id"]]] += 1
        n_surv_s = sum(tab["survivors"].values())
        good = tab["survivors"]["VERIFIABLE"] + tab["survivors"]["PROBABLY_CORRECT"]
        verif = tab["survivors"]["VERIFIABLE"]
        n_after = n_pool - n_flag
        lo, hi = wilson_interval(good, n_surv_s)
        vlo, vhi = wilson_interval(verif, n_surv_s)
        bad_s = tab["survivors"]["INCORRECT"] + tab["survivors"]["UNCERTAIN"]
        blo, bhi = wilson_interval(bad_s, n_surv_s)
        bad_all = sum(1 for r in srows if lab[r["sample_id"]] in ("INCORRECT", "UNCERTAIN"))
        out[cat] = {
            "pool_unique": n_pool,
            "pool_flagged": n_flag,
            "pool_flagged_rate": n_flag / n_pool if n_pool else None,
            "pool_rule_counts": dict(sorted(rule_counts.items())),
            "sample_flagged": {c: tab["flagged"][c] for c in LABEL_CLASSES},
            "sample_survivors": {c: tab["survivors"][c] for c in LABEL_CLASSES},
            "sample_bad_total_uncertain_or_incorrect": bad_all,
            "sample_bad_caught_by_filters": bad_all - bad_s,
            "survivor_bad_rate_uncertain_or_incorrect": {
                "k": bad_s, "n": n_surv_s, "rate": (bad_s / n_surv_s if n_surv_s else None),
                "wilson95": [blo, bhi]},
            "estimated_clean_verifiable_or_probable": {
                "point": (round(n_after * good / n_surv_s) if n_surv_s else None),
                "wilson95": ([round(n_after * lo), round(n_after * hi)] if n_surv_s else None),
                "share_in_survivor_sample": (good / n_surv_s if n_surv_s else None)},
            "estimated_clean_verifiable_only": {
                "point": (round(n_after * verif / n_surv_s) if n_surv_s else None),
                "wilson95": ([round(n_after * vlo), round(n_after * vhi)] if n_surv_s else None)},
        }
    return out


# ───────────────────────── PATT / extraction ─────────────────────────
def check_patt(patt: str) -> str:
    head = subprocess.run(["git", "-C", patt, "rev-parse", "HEAD"], capture_output=True,
                          text=True, check=True).stdout.strip()
    if head != PINNED_PATT_COMMIT:
        raise SystemExit(f"FATAL: PATT HEAD {head} != pinned {PINNED_PATT_COMMIT}")
    dirty = subprocess.run(["git", "-C", patt, "status", "--porcelain"], capture_output=True,
                           text=True, check=True).stdout.strip()
    if dirty:
        raise SystemExit("FATAL: PATT working tree is not clean:\n" + dirty[:500])
    return head


def run_extraction(patt: str) -> dict:
    """Run the V4 extraction in memory; record per-category rejection reasons."""
    head = check_patt(patt)
    sys.path.insert(0, HERE)
    import parse_dataset_v4 as p4  # stdlib-only, no import-time side effects
    p4.PAYLOADS_REPO = patt
    rej: dict[str, Counter] = {}
    orig_qf = p4.quality_filter

    def recording_qf(raw, category):
        res = orig_qf(raw, category)
        rej.setdefault(category, Counter())[res[1]] += 1
        return res

    p4.quality_filter = recording_qf
    try:
        stats = {"reject_reasons": Counter(), "candidates_per_category": Counter()}
        patt_rows = p4.extract_sources(stats)
    finally:
        p4.quality_filter = orig_qf
    hard_rows = p4.build_hardcoded_sources()
    rows = patt_rows + hard_rows
    pools = build_pool(rows, p4.canonical_key)
    acc = Counter(r["category"] for r in rows)
    info = {}
    for cat in pools:
        info[cat] = {
            "candidates_pre_filter": stats["candidates_per_category"].get(cat, 0),
            "accepted_rows": acc[cat],
            "unique_canonical": len(pools[cat]),
            "origin": "hardcoded" if cat in ("CRLF Injection", "XPath Injection",
                                             "HTTP Parameter Pollution") else
                      ("patt+hardcoded" if cat == "Request Smuggling" else "patt"),
            "reject_reasons": dict(sorted(rej.get(cat, Counter()).items())),
            "unique_canonical_by_source_file": dict(sorted(
                Counter(e["source_file"] for e in pools[cat]).items(),
                key=lambda kv: (-kv[1], kv[0]))),
        }
    return {"patt_commit": head, "category_info": info, "pools": pools,
            "global_reject_reasons": dict(sorted(stats["reject_reasons"].items())),
            "bounds": {"MIN_LEN": p4.MIN_LEN, "MAX_LEN": p4.MAX_LEN}}


# ─────────────── second annotation, adjudication, human-review sample ───────────────
USABLE = ("VERIFIABLE", "PROBABLY_CORRECT")
# Categories whose payloads V5 trains on (D57): primary + report-only. Human review covers these.
HUMAN_REVIEW_N = OrderedDict([
    ("SQL Injection", 10), ("XSS Injection", 10), ("Directory Traversal", 10),
    ("File Inclusion", 10), ("Command Injection", 10), ("Server Side Template Injection", 10),
    ("Server Side Request Forgery", 10), ("Open Redirect", 10),
    ("NoSQL Injection", 5), ("CRLF Injection", 5), ("XPath Injection", 5),
])
HUMAN_REVIEW_SEED = "v5-attack-human-review-v1"


def binary_agreement(a: list[str], b: list[str], event) -> dict:
    """2x2 agreement and Cohen's kappa for a binary event over paired labels."""
    if len(a) != len(b):
        raise ValueError("label lists differ in length")
    both = sum(1 for x, y in zip(a, b) if event(x) and event(y))
    only_a = sum(1 for x, y in zip(a, b) if event(x) and not event(y))
    only_b = sum(1 for x, y in zip(a, b) if not event(x) and event(y))
    neither = len(a) - both - only_a - only_b
    n = len(a)
    po = (both + neither) / n if n else 0.0
    pe = (((both + only_a) * (both + only_b) + (neither + only_b) * (neither + only_a)) / (n * n)
          if n else 0.0)
    kappa = (po - pe) / (1 - pe) if pe < 1 else 1.0
    return {"n": n, "both": both, "only_first": only_a, "only_second": only_b,
            "neither": neither, "observed_agreement": round(po, 4), "cohen_kappa": round(kappa, 4)}


def adjudicate(first: dict, second: dict, overrides: dict) -> dict:
    """Per sample_id final class. Rules, in order: an explicit override wins; equal labels are
    kept; a VERIFIABLE/PROBABLY_CORRECT split resolves to the conservative PROBABLY_CORRECT;
    any other disagreement without an override is an error (it must be adjudicated)."""
    out, missing = {}, []
    for sid in sorted(first):
        a, b = first[sid], second[sid]
        if sid in overrides:
            out[sid] = (overrides[sid], "override")
        elif a == b:
            out[sid] = (a, "agreement")
        elif {a, b} == set(USABLE):
            out[sid] = ("PROBABLY_CORRECT", "conservative_v_p")
        else:
            missing.append(sid)
    if missing:
        raise ValueError(f"{len(missing)} disagreements lack an adjudication override: {missing[:10]}")
    return out


def human_review_sample(sample: list[dict], n_per_cat=HUMAN_REVIEW_N,
                        seed: str = HUMAN_REVIEW_SEED) -> list[dict]:
    """Stratified, deterministic subsample for blind human review. Within a category, rows are
    ranked by sha256(seed NUL sample_id); output is re-ordered by sha256(seed NUL "order" NUL id)
    so categories are interleaved and nothing hints at prior labels."""
    picked = []
    for cat, n in n_per_cat.items():
        rows = sorted((r for r in sample if r["category"] == cat),
                      key=lambda r: sha256_hex(f"{seed}\0{r['sample_id']}"))
        picked.extend(rows[:n])
    return sorted(picked, key=lambda r: sha256_hex(f"{seed}\0order\0{r['sample_id']}"))


# ─────────────── blind human review: batches, label template, comparison ───────────────
HUMAN_LABEL_FIELDS = ["batch", "sample_id", "label_class", "failure_mode", "better_category",
                      "justification"]


def batches(rows: list[dict], size: int) -> list[list[dict]]:
    """Consecutive, order-preserving batches (the sample CSV order is already label-blind)."""
    if size < 1:
        raise ValueError("batch size must be >= 1")
    return [rows[i:i + size] for i in range(0, len(rows), size)]


def validate_human_labels(sample_ids: list[str], labels: list[dict]) -> list[str]:
    """Completeness and vocabulary checks; empty label_class means 'not yet reviewed'."""
    errs = []
    by_id = {}
    for r in labels:
        sid = r.get("sample_id", "")
        if sid in by_id:
            errs.append(f"duplicate sample_id {sid}")
        by_id[sid] = r
    for sid in sample_ids:
        r = by_id.get(sid)
        if r is None:
            errs.append(f"{sid}: missing row")
            continue
        lc = (r.get("label_class") or "").strip()
        if not lc:
            errs.append(f"{sid}: not reviewed yet")
        elif lc not in LABEL_CLASSES:
            errs.append(f"{sid}: bad label_class {lc!r}")
        fm = (r.get("failure_mode") or "").strip()
        if lc == "INCORRECT" and fm not in FAILURE_MODES:
            errs.append(f"{sid}: INCORRECT needs failure_mode in vocabulary")
        if fm and fm not in FAILURE_MODES:
            errs.append(f"{sid}: bad failure_mode {fm!r}")
    for sid in set(by_id) - set(sample_ids):
        errs.append(f"{sid}: not in the human-review sample")
    return errs


def compare_human(human: dict, adjudicated: dict, category: dict) -> dict:
    """Agreement between human labels and the adjudicated LLM labels on the same ids, plus
    human per-category INCORRECT rates. Disagreements are listed, never resolved here."""
    ids = sorted(human)
    h, l = [human[i] for i in ids], [adjudicated[i] for i in ids]
    per = {}
    for cat in sorted({category[i] for i in ids}):
        cid = [i for i in ids if category[i] == cat]
        k_inc = sum(1 for i in cid if human[i] == "INCORRECT")
        k_bad = sum(1 for i in cid if human[i] not in USABLE)
        per[cat] = {"n": len(cid),
                    "human_incorrect": {"k": k_inc, "wilson95": list(wilson_interval(k_inc, len(cid)))},
                    "human_uncertain_or_incorrect": {"k": k_bad,
                                                     "wilson95": list(wilson_interval(k_bad, len(cid)))}}
    return {"n": len(ids),
            "exact_class_agreement": sum(1 for x, y in zip(h, l) if x == y),
            "usable_vs_not": binary_agreement(h, l, lambda c: c in USABLE),
            "incorrect_vs_not": binary_agreement(h, l, lambda c: c == "INCORRECT"),
            "per_category_human": per,
            "disagreements": [{"sample_id": i, "category": category[i], "human": human[i],
                               "llm_adjudicated": adjudicated[i]}
                              for i in ids if human[i] != adjudicated[i]]}


# ───────────────────────── CLI ─────────────────────────
def cmd_extract(a) -> None:
    res = run_extraction(a.patt)
    info = res["category_info"]
    out = {"patt_commit": res["patt_commit"], "bounds": res["bounds"],
           "categories": info,
           "totals": {"candidates_pre_filter": sum(v["candidates_pre_filter"] for v in info.values()),
                      "accepted_rows": sum(v["accepted_rows"] for v in info.values()),
                      "unique_canonical": sum(v["unique_canonical"] for v in info.values())},
           "global_reject_reasons": res["global_reject_reasons"],
           "pool_listing_sha256": pool_listing_sha256(res["pools"])}
    print(json.dumps(out, indent=2, sort_keys=True))


def _load_summary(path: str) -> dict:
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    return {}


def cmd_sample(a) -> None:
    res = run_extraction(a.patt)
    pools = res["pools"]
    sizes = {c: len(v) for c, v in pools.items()}
    n_per = allocate(sizes)
    sample = stratified_sample(pools, n_per, a.seed)
    os.makedirs(a.out_dir, exist_ok=True)
    write_jsonl(os.path.join(a.out_dir, "sample.jsonl"), sample)
    sp = os.path.join(a.out_dir, "summary.json")
    summ = _load_summary(sp)
    summ["sampling"] = {
        "method": "stratified by category; within category rank by "
                  "sha256(seed NUL category NUL canonical_key), take first n_c",
        "seed": a.seed,
        "allocation_rule": f"n_c = min(pool, max(tier_floor, min({PROPORTIONAL_CAP}, "
                           f"round({PROPORTIONAL_TOTAL}*pool/sum_pool))))",
        "tiers": {c: {"tier": t, "floor": f} for c, (t, f) in TIERS.items()},
        "n_per_category": n_per,
        "n_total": sum(n_per.values()),
        "pool_unique_canonical": sizes,
        "pool_unique_total": sum(sizes.values()),
        "pool_listing_sha256": pool_listing_sha256(pools),
        "pool_listing_definition": "sha256 of '\\n'.join(sorted('category\\tsha256(canonical_key)'))",
        "patt_commit": res["patt_commit"],
        "population_info": res["category_info"],
    }
    with open(sp, "w", encoding="utf-8") as f:
        json.dump(summ, f, indent=2, sort_keys=True, ensure_ascii=False)
        f.write("\n")
    print(f"wrote {len(sample)} rows to {os.path.join(a.out_dir, 'sample.jsonl')}")
    print(json.dumps({"n_per_category": n_per, "n_total": len(sample),
                      "pool_listing_sha256": summ["sampling"]["pool_listing_sha256"]}, indent=2))


def cmd_summarize(a) -> None:
    sample = read_jsonl(os.path.join(a.out_dir, "sample.jsonl"))
    ann = read_jsonl(os.path.join(a.out_dir, "annotations.jsonl"))
    errs = validate_annotations(sample, ann)
    if errs:
        raise SystemExit("annotation validation failed:\n  " + "\n  ".join(errs[:50]))
    sp = os.path.join(a.out_dir, "summary.json")
    summ = _load_summary(sp)
    summ["results"] = summarize(sample, ann)
    summ["results"]["note"] = (
        "Wilson intervals reflect sampling uncertainty only (simple random sample "
        "within stratum, no finite-population correction => slightly conservative). "
        "They do NOT capture systematic annotator error: the single annotator is an "
        "LLM (Claude Sonnet subagent) and no second annotator exists. 'overall' is an "
        "unweighted pooled rate over the stratified sample and is NOT a population estimate.")
    with open(sp, "w", encoding="utf-8") as f:
        json.dump(summ, f, indent=2, sort_keys=True, ensure_ascii=False)
        f.write("\n")
    print(json.dumps(summ["results"]["overall_unweighted_sample"], indent=2))


def cmd_filters(a) -> None:
    res = run_extraction(a.patt)
    sample = read_jsonl(os.path.join(a.out_dir, "sample.jsonl"))
    ann = read_jsonl(os.path.join(a.out_dir, "annotations.jsonl"))
    errs = validate_annotations(sample, ann)
    if errs:
        raise SystemExit("annotation validation failed:\n  " + "\n  ".join(errs[:50]))
    sp = os.path.join(a.out_dir, "summary.json")
    summ = _load_summary(sp)
    if summ.get("sampling", {}).get("pool_listing_sha256") != pool_listing_sha256(res["pools"]):
        raise SystemExit("pool listing sha256 differs from the one recorded at sampling time")
    summ["filter_evaluation"] = {
        "rules": ["malformed_percent", "literal_0x_escape", "qmark_runs", "literal_backslash_x",
                  "placeholder_token", "doc_annotation", "url_plus_label",
                  "trailing_doc_comment", "tool_output_marker", "source_code_line",
                  "dangling_opener", "bare_word", "bare_html_tag", "tool_invocation",
                  "prose_sentence"],
        "caveat": "filters designed after inspecting this sample => survivor shares are "
                  "in-sample (optimistic) and the clean-pool estimates are not validated",
        "per_category": evaluate_filters(res["pools"], sample, ann),
    }
    with open(sp, "w", encoding="utf-8") as f:
        json.dump(summ, f, indent=2, sort_keys=True, ensure_ascii=False)
        f.write("\n")
    for cat, v in summ["filter_evaluation"]["per_category"].items():
        e = v["estimated_clean_verifiable_or_probable"]
        print(f"{cat:32s} pool={v['pool_unique']:6d} flagged={v['pool_flagged']:6d} "
              f"bad_caught={v['sample_bad_caught_by_filters']}/{v['sample_bad_total_uncertain_or_incorrect']} "
              f"est_clean={e['point']} {e['wilson95']}")


def cmd_agreement(a) -> None:
    sample = read_jsonl(os.path.join(a.out_dir, "sample.jsonl"))
    first_rows = read_jsonl(os.path.join(a.out_dir, "annotations.jsonl"))
    second_rows = read_jsonl(os.path.join(a.out_dir, "annotations_second.jsonl"))
    for name, rows in (("annotations.jsonl", first_rows), ("annotations_second.jsonl", second_rows)):
        errs = validate_annotations(sample, rows)
        if errs:
            raise SystemExit(f"{name} validation failed:\n  " + "\n  ".join(errs[:50]))
    first = {r["sample_id"]: r["label_class"] for r in first_rows}
    second = {r["sample_id"]: r["label_class"] for r in second_rows}
    ov_rows = read_jsonl(os.path.join(a.out_dir, "adjudication_overrides.jsonl"))
    overrides = {r["sample_id"]: r["label_class"] for r in ov_rows}
    ids = sorted(first)
    fa, fb = [first[i] for i in ids], [second[i] for i in ids]
    final = adjudicate(first, second, overrides)
    write_jsonl(os.path.join(a.out_dir, "adjudicated.jsonl"),
                [{"sample_id": i, "label_class": final[i][0], "basis": final[i][1]} for i in ids])
    fm = {r["sample_id"]: r.get("failure_mode") for r in first_rows}
    fm.update({r["sample_id"]: r.get("failure_mode") for r in second_rows
               if r["label_class"] != first[r["sample_id"]]})
    fm.update({r["sample_id"]: r.get("failure_mode") for r in ov_rows})
    adj_ann = [{"sample_id": i, "label_class": final[i][0], "failure_mode": fm.get(i)}
               for i in ids]
    sp = os.path.join(a.out_dir, "summary.json")
    summ = _load_summary(sp)
    summ["second_annotation"] = {
        "annotators": {"first": "Claude Sonnet subagent", "second": "Claude Opus subagent, blind",
                       "adjudicator": "coordinator (Claude Opus 5.5)"},
        "exact_class_agreement": sum(1 for x, y in zip(fa, fb) if x == y),
        "usable_vs_not": binary_agreement(fa, fb, lambda c: c in USABLE),
        "incorrect_vs_not": binary_agreement(fa, fb, lambda c: c == "INCORRECT"),
        "adjudication_basis": dict(Counter(v[1] for v in final.values())),
        "adjudicated_results": summarize(sample, adj_ann),
        "note": ("Agreement is between two LLM annotators and is NOT human validation. Wilson "
                 "intervals on adjudicated labels reflect sampling uncertainty only."),
    }
    with open(sp, "w", encoding="utf-8") as f:
        json.dump(summ, f, indent=2, sort_keys=True, ensure_ascii=False)
        f.write("\n")
    s = summ["second_annotation"]
    print(json.dumps({k: s[k] for k in ("exact_class_agreement", "usable_vs_not",
                                        "incorrect_vs_not", "adjudication_basis")}, indent=2))


def cmd_human_sample(a) -> None:
    import csv
    sample = read_jsonl(os.path.join(a.out_dir, "sample.jsonl"))
    rows = human_review_sample(sample)
    d = os.path.join(a.out_dir, "human_review")
    os.makedirs(d, exist_ok=True)
    path = os.path.join(d, "human_review_sample.csv")
    if os.path.exists(path) and not getattr(a, "force", False):
        raise SystemExit(f"{path} exists; refusing to overwrite (use --force only to regenerate "
                         "the unlabelled sample; human labels live in human_labels.csv)")
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, quoting=csv.QUOTE_ALL)
        w.writerow(["sample_id", "category", "source_file", "payload",
                    "label_class", "failure_mode", "better_category", "reviewer_note"])
        for r in rows:
            w.writerow([r["sample_id"], r["category"], r["source_file"], r["payload"], "", "", "", ""])
    print(f"wrote {len(rows)} rows to {path}")


def _read_csv(path: str) -> list[dict]:
    import csv
    with open(path, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def cmd_human_batch(a) -> None:
    """Print one label-blind batch and make sure human_labels.csv exists (never overwritten)."""
    import csv
    d = os.path.join(a.out_dir, "human_review")
    rows = _read_csv(os.path.join(d, "human_review_sample.csv"))
    groups = batches(rows, a.size)
    lab = os.path.join(d, "human_labels.csv")
    if not os.path.exists(lab):
        with open(lab, "w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=HUMAN_LABEL_FIELDS, quoting=csv.QUOTE_ALL)
            w.writeheader()
            for b, grp in enumerate(groups, 1):
                for r in grp:
                    w.writerow({"batch": b, "sample_id": r["sample_id"], "label_class": "",
                                "failure_mode": "", "better_category": "", "justification": ""})
        print(f"created {lab} (empty template, {len(rows)} rows)")
    if not 1 <= a.batch <= len(groups):
        raise SystemExit(f"batch must be in 1..{len(groups)}")
    print(f"batch {a.batch}/{len(groups)} (size {a.size}); no prior labels are shown")
    for r in groups[a.batch - 1]:
        print(f"\n[{r['sample_id']}] category: {r['category']} | source: {r['source_file']}")
        print(f"payload: {r['payload']!r}")


def cmd_human_compare(a) -> None:
    """Only after the human review is complete: compare with the adjudicated LLM labels."""
    d = os.path.join(a.out_dir, "human_review")
    sample_rows = _read_csv(os.path.join(d, "human_review_sample.csv"))
    ids = [r["sample_id"] for r in sample_rows]
    labels = _read_csv(os.path.join(d, "human_labels.csv"))
    errs = validate_human_labels(ids, labels)
    if errs:
        raise SystemExit(f"human review incomplete or invalid ({len(errs)} issues), comparison "
                         "refused:\n  " + "\n  ".join(errs[:20]))
    human = {r["sample_id"]: r["label_class"].strip() for r in labels}
    adjudicated = {r["sample_id"]: r["label_class"]
                   for r in read_jsonl(os.path.join(a.out_dir, "adjudicated.jsonl"))}
    category = {r["sample_id"]: r["category"] for r in sample_rows}
    res = compare_human(human, adjudicated, category)
    res["note"] = ("Human labels are the reference for this comparison; LLM labels were not shown "
                   "to the reviewer. Disagreements are listed, not resolved automatically.")
    out = os.path.join(d, "comparison.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2, sort_keys=True)
        f.write("\n")
    print(json.dumps({k: res[k] for k in ("n", "exact_class_agreement", "usable_vs_not",
                                          "incorrect_vs_not")}, indent=2))
    print(f"{len(res['disagreements'])} disagreements listed in {out}")


def main(argv=None) -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name, fn in (("extract", cmd_extract), ("sample", cmd_sample),
                     ("summarize", cmd_summarize), ("filters", cmd_filters),
                     ("agreement", cmd_agreement), ("human-sample", cmd_human_sample),
                     ("human-batch", cmd_human_batch), ("human-compare", cmd_human_compare)):
        sp = sub.add_parser(name)
        sp.add_argument("--patt", default=DEFAULT_PATT)
        sp.add_argument("--out-dir", default=DEFAULT_OUT_DIR)
        sp.add_argument("--seed", default=DEFAULT_SEED)
        if name == "human-sample":
            sp.add_argument("--force", action="store_true")
        if name == "human-batch":
            sp.add_argument("--batch", type=int, required=True)
            sp.add_argument("--size", type=int, default=12)
        sp.set_defaults(fn=fn)
    a = ap.parse_args(argv)
    a.fn(a)


if __name__ == "__main__":
    main()
