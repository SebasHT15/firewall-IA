#!/usr/bin/env python3.12
"""
firewall-IA — E0: DATASET INTEGRITY GATE

ANALYSIS ONLY. This script never writes to, mutates, or regenerates the dataset.
It opens train/eval JSONL read-only and reports measurements.

PURPOSE
    Detect the failure modes that make an accuracy number uninterpretable:
      - envelope shortcuts (a non-payload feature that predicts the label)
      - train/eval leakage (eval examples memorised from train)
      - duplication, category collapse, format artifacts

GATE RULE
    No training run starts while this reports FAIL.

USAGE
    python3.12 scripts/dataset/check_dataset.py          # defaults: datasets/v4_clean/{train,eval}.jsonl
    python3.12 scripts/dataset/check_dataset.py --train datasets/v4_clean/train.jsonl --eval datasets/v4_clean/eval.jsonl
    python3.12 scripts/dataset/check_dataset.py --out reports/e0_dataset_integrity_<new-id>.txt

    Existing reports under reports/ are records and are never overwritten. The historical
    root train.jsonl/eval.jsonl are not distributed (docs/data_sources.md); pass them
    explicitly only to re-check the historical corpus from a local copy.

EXIT CODES
    0 = PASS      1 = WARNING      2 = FAIL      3 = could not run

NOTE ON MEASUREMENTS
    Every number in the output is computed from the input files at run time.
    Nothing is hardcoded. Re-running against a regenerated dataset re-measures
    from scratch. Thresholds (and only thresholds) are constants, declared in
    the THRESHOLDS block below and echoed into the report.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

# ── Thresholds ──────────────────────────────────────────────────────────────
# These are policy, not measurements. They are echoed into every report so a
# reader can see what standard the verdict was issued against.

# A non-payload feature that predicts the label this well is a shortcut.
SHORTCUT_ACC_FAIL = 0.80      # absolute eval accuracy from one envelope feature
SHORTCUT_ACC_WARN = 0.65
SHORTCUT_MARGIN_FAIL = 0.20   # accuracy above the majority-class baseline
SHORTCUT_MARGIN_WARN = 0.10

# A single envelope VALUE that is this pure toward one label, at this coverage,
# is reported as deterministic leakage of the label.
PURITY_FAIL = 0.99
PURITY_MIN_COVERAGE = 0.01    # fraction of the dataset the value must cover

# Exact train->eval overlap.
LEAKAGE_FAIL = 0.01           # >=1% of eval seen verbatim in train
LEAKAGE_WARN = 0.0            # any overlap at all is a defect

# Within-split exact duplication.
DUP_WARN = 0.10

# Per-category volume.
CATEGORY_RATIO_WARN = 100.0   # largest:smallest BLOCK category
CATEGORY_MIN_SHARE_WARN = 0.001   # 0.1% of the dataset

# Headers treated as non-causal envelope metadata. A shortcut here is a defect.
# Headers that can legitimately carry attack signal (Origin/Referer for CSRF,
# Content-Length/Transfer-Encoding for smuggling) are EXCLUDED from the gate —
# see DECISIONS.md D1 — and reported separately as informational.
CAUSAL_HEADERS = {
    "origin", "referer", "referrer",
    "content-length", "transfer-encoding",
    "x-forwarded-host", "x-original-url", "x-rewrite-url",
}


# ── I/O helpers ─────────────────────────────────────────────────────────────
class Tee:
    """Write to stdout and (optionally) a report file simultaneously."""

    def __init__(self, path: str | None):
        self.fh = open(path, "w", encoding="utf-8") if path else None

    def __call__(self, line: str = ""):
        print(line)
        if self.fh:
            self.fh.write(line + "\n")

    def close(self):
        if self.fh:
            self.fh.close()


def sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_jsonl(path: str) -> list[dict]:
    rows = []
    with open(path, encoding="utf-8") as f:
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as e:
                raise SystemExit(f"FATAL: {path}:{n} is not valid JSON: {e}")
    return rows


def git_rev(repo: str) -> str:
    try:
        out = subprocess.run(
            ["git", "-C", os.path.expanduser(repo), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=10,
        )
        if out.returncode == 0:
            return out.stdout.strip()
        return "<not a git repository>"
    except Exception as e:  # noqa: BLE001
        return f"<unavailable: {e}>"


def git_dirty(repo: str) -> str:
    try:
        out = subprocess.run(
            ["git", "-C", os.path.expanduser(repo), "status", "--porcelain"],
            capture_output=True, text=True, timeout=10,
        )
        if out.returncode != 0:
            return "<unknown>"
        return "dirty" if out.stdout.strip() else "clean"
    except Exception:  # noqa: BLE001
        return "<unknown>"


# ── Parsing ─────────────────────────────────────────────────────────────────
REQUEST_LINE_RE = re.compile(r"^(?P<method>[A-Z]+)\s+(?P<target>.*)\s+(?P<version>HTTP/[\d.]+)$")


def parse_request(raw: str) -> dict:
    """Split a raw HTTP request into method / target / headers / body.

    Tolerant by design: this dataset is known to contain malformed request
    lines (see CONTEXT.md §12 F1), and detecting that malformation is one of
    the checks, so parse failures are recorded rather than raised.
    """
    head, _, body = raw.partition("\n\n")
    lines = head.split("\n")
    first = lines[0] if lines else ""

    m = REQUEST_LINE_RE.match(first)
    if m:
        method = m.group("method")
        target = m.group("target")
        malformed = " " in target          # raw space inside the request-target
    else:
        method, target, malformed = "<unparsed>", "", True

    headers: dict[str, str] = {}
    for ln in lines[1:]:
        if ":" in ln:
            k, _, v = ln.partition(":")
            headers.setdefault(k.strip().lower(), v.strip())

    return {
        "method": method,
        "target": target,
        "malformed_target": malformed,
        "headers": headers,
        "has_body": bool(body.strip()),
        "n_headers": len(headers),
    }


def label_of(example: dict) -> str:
    out = (example.get("output") or "").strip()
    return "BLOCK" if out.upper().startswith("BLOCK") else "ALLOW"


REASON_CLEAN_RE = re.compile(r"\s*###END###\s*$")


def category_of(example: dict) -> str:
    """Attack category = the reason string. Tolerates presence or absence of
    ###END### so this keeps working after DECISIONS.md D5 is implemented."""
    out = (example.get("output") or "").strip()
    out = REASON_CLEAN_RE.sub("", out).strip()
    _, sep, reason = out.partition("|")
    reason = (reason if sep else out).strip().rstrip(".")
    return reason or "<empty reason>"


# ── Baselines ───────────────────────────────────────────────────────────────
def fit_predict_accuracy(train_feats, train_labels, eval_feats, eval_labels, fallback):
    """Fit a lookup table feature-value -> majority label on TRAIN, evaluate on EVAL.

    This is the honest form of a trivial baseline: it may not peek at eval
    labels. Feature values unseen in train fall back to the global majority.
    """
    tally: dict[object, Counter] = defaultdict(Counter)
    for f, y in zip(train_feats, train_labels):
        tally[f][y] += 1
    table = {f: c.most_common(1)[0][0] for f, c in tally.items()}

    correct = sum(
        1 for f, y in zip(eval_feats, eval_labels)
        if table.get(f, fallback) == y
    )
    coverage = sum(1 for f in eval_feats if f in table) / max(1, len(eval_feats))
    return correct / max(1, len(eval_labels)), coverage, len(table)


def feature_extractors() -> dict:
    """name -> (callable(parsed, raw) -> hashable, is_envelope_feature)

    is_envelope_feature=True means a shortcut here counts toward the gate.
    Payload content (target/query/body) is deliberately NOT used: it is the
    legitimate causal signal, and a baseline built on it would not be trivial.
    """
    return {
        "Host (header value)":
            (lambda p, r: p["headers"].get("host", "<absent>"), True),
        "User-Agent (present/absent)":
            (lambda p, r: "present" if "user-agent" in p["headers"] else "absent", True),
        "User-Agent (header value)":
            (lambda p, r: p["headers"].get("user-agent", "<absent>"), True),
        "Cookie (present/absent)":
            (lambda p, r: "present" if "cookie" in p["headers"] else "absent", True),
        "Content-Type (header value)":
            (lambda p, r: p["headers"].get("content-type", "<absent>"), True),
        "HTTP method":
            (lambda p, r: p["method"], True),
        "Malformed request-target (raw space)":
            (lambda p, r: p["malformed_target"], True),
        "Body present/absent":
            (lambda p, r: p["has_body"], True),
        "Header-name set (structural fingerprint)":
            (lambda p, r: tuple(sorted(p["headers"].keys())), True),
        "Header count":
            (lambda p, r: p["n_headers"], True),
    }


# ── Report sections ─────────────────────────────────────────────────────────
def section(out: Tee, title: str):
    out()
    out("=" * 78)
    out(title)
    out("=" * 78)


def pct(x: float) -> str:
    return f"{100 * x:.2f}%"


def main() -> int:
    ap = argparse.ArgumentParser(description="firewall-IA E0 dataset integrity gate (read-only)")
    # Defaults resolve from the repository root; this file lives in scripts/dataset/.
    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    # The current V4-clean dataset. Not the historical root train.jsonl/eval.jsonl, which
    # are superseded and not distributed (docs/data_sources.md).
    ap.add_argument("--train", default=os.path.join(repo_root, "datasets", "v4_clean", "train.jsonl"))
    ap.add_argument("--eval", dest="eval_path",
                    default=os.path.join(repo_root, "datasets", "v4_clean", "eval.jsonl"))
    ap.add_argument("--payloads-repo", default="~/PayloadsAllTheThings")
    ap.add_argument("--repo", default=repo_root)
    ap.add_argument("--out", default=None, help="also write the report to this path")
    ap.add_argument("--top", type=int, default=25, help="rows to show in long tables")
    args = ap.parse_args()

    for p in (args.train, args.eval_path):
        if not os.path.isfile(p):
            print(f"FATAL: not found: {p}", file=sys.stderr)
            return 3

    if args.out:
        os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    out = Tee(args.out)

    failures: list[str] = []
    warnings: list[str] = []

    try:
        # ── Header ──────────────────────────────────────────────────────────
        out("=" * 78)
        out("firewall-IA — E0 DATASET INTEGRITY GATE")
        out("=" * 78)
        out(f"Generated (UTC)   : {datetime.now(timezone.utc).isoformat(timespec='seconds')}")
        out(f"Train file        : {args.train}")
        out(f"Eval file         : {args.eval_path}")
        out("Mode              : ANALYSIS ONLY — no file is modified")
        out()
        out("Thresholds in force for this run:")
        out(f"  shortcut accuracy   FAIL >= {SHORTCUT_ACC_FAIL:.2f}   WARN >= {SHORTCUT_ACC_WARN:.2f}")
        out(f"  shortcut margin     FAIL >= {SHORTCUT_MARGIN_FAIL:.2f}   WARN >= {SHORTCUT_MARGIN_WARN:.2f}")
        out(f"  value purity        FAIL >= {PURITY_FAIL:.2f} at coverage >= {pct(PURITY_MIN_COVERAGE)}")
        out(f"  train->eval leakage FAIL >= {pct(LEAKAGE_FAIL)}    WARN >  {pct(LEAKAGE_WARN)}")
        out(f"  within-split dup    WARN >  {pct(DUP_WARN)}")
        out(f"  category ratio      WARN >  {CATEGORY_RATIO_WARN:.0f}:1")
        out(f"  category min share  WARN <  {pct(CATEGORY_MIN_SHARE_WARN)}")

        train = load_jsonl(args.train)
        ev = load_jsonl(args.eval_path)
        allrows = train + ev
        if not train or not ev:
            out("\nFATAL: one of the splits is empty.")
            return 3

        tr_in = [r.get("input", "") for r in train]
        ev_in = [r.get("input", "") for r in ev]
        tr_y = [label_of(r) for r in train]
        ev_y = [label_of(r) for r in ev]
        all_y = tr_y + ev_y

        # ── 1. Dataset summary ──────────────────────────────────────────────
        section(out, "1. DATASET SUMMARY")
        out(f"Total examples : {len(allrows):>8,}")
        out(f"  train        : {len(train):>8,}  ({pct(len(train)/len(allrows))})")
        out(f"  eval         : {len(ev):>8,}  ({pct(len(ev)/len(allrows))})")
        out()
        lab_all, lab_tr, lab_ev = Counter(all_y), Counter(tr_y), Counter(ev_y)
        out(f"{'LABEL':<10}{'TOTAL':>10}{'%':>9}{'TRAIN':>10}{'EVAL':>10}")
        out("-" * 49)
        for lab in ("ALLOW", "BLOCK"):
            out(f"{lab:<10}{lab_all[lab]:>10,}{pct(lab_all[lab]/len(allrows)):>9}"
                f"{lab_tr[lab]:>10,}{lab_ev[lab]:>10,}")

        section(out, "1b. PER-CATEGORY COUNTS")
        cat_all = Counter(category_of(r) for r in allrows)
        cat_tr = Counter(category_of(r) for r in train)
        cat_ev = Counter(category_of(r) for r in ev)
        out(f"{'CATEGORY (reason string)':<52}{'TOTAL':>9}{'%':>8}{'TRAIN':>9}{'EVAL':>8}")
        out("-" * 86)
        for cat, n in cat_all.most_common():
            out(f"{cat[:51]:<52}{n:>9,}{pct(n/len(allrows)):>8}{cat_tr[cat]:>9,}{cat_ev[cat]:>8,}")
        out("-" * 86)
        out(f"{'distinct categories':<52}{len(cat_all):>9,}")

        block_cats: Counter = Counter()
        for r in allrows:
            if label_of(r) == "BLOCK":
                block_cats[category_of(r)] += 1
        if block_cats:
            hi = max(block_cats.values())
            lo = min(block_cats.values())
            ratio = hi / max(1, lo)
            out()
            out(f"BLOCK category volume spread: largest={hi:,}  smallest={lo:,}  ratio={ratio:,.1f}:1")
            if ratio > CATEGORY_RATIO_WARN:
                warnings.append(
                    f"Severe per-category imbalance in BLOCK: {ratio:,.1f}:1 "
                    f"(largest {hi:,}, smallest {lo:,}); threshold {CATEGORY_RATIO_WARN:.0f}:1"
                )
            starved = [(c, n) for c, n in sorted(block_cats.items(), key=lambda kv: kv[1])
                       if n / len(allrows) < CATEGORY_MIN_SHARE_WARN]
            if starved:
                out()
                out(f"Categories below {pct(CATEGORY_MIN_SHARE_WARN)} of the dataset "
                    f"(under-represented — a model cannot be fairly evaluated on these):")
                for c, n in starved:
                    out(f"    {n:>7,}  ({pct(n/len(allrows)):>6})  {c}")
                warnings.append(
                    f"{len(starved)} BLOCK categor{'y' if len(starved)==1 else 'ies'} below "
                    f"{pct(CATEGORY_MIN_SHARE_WARN)} of the dataset: "
                    + ", ".join(f"{c} ({n:,})" for c, n in starved)
                )

        # ── 2. Duplication ──────────────────────────────────────────────────
        section(out, "2. DUPLICATION (exact input string match)")
        tr_set, ev_set = set(tr_in), set(ev_in)
        tr_dup = 1 - len(tr_set) / len(tr_in)
        ev_dup = 1 - len(ev_set) / len(ev_in)
        all_set = set(tr_in) | set(ev_in)
        out(f"{'SPLIT':<10}{'ROWS':>10}{'UNIQUE':>10}{'UNIQUE %':>10}{'DUPLICATE %':>13}")
        out("-" * 53)
        out(f"{'train':<10}{len(tr_in):>10,}{len(tr_set):>10,}"
            f"{pct(len(tr_set)/len(tr_in)):>10}{pct(tr_dup):>13}")
        out(f"{'eval':<10}{len(ev_in):>10,}{len(ev_set):>10,}"
            f"{pct(len(ev_set)/len(ev_in)):>10}{pct(ev_dup):>13}")
        out(f"{'combined':<10}{len(allrows):>10,}{len(all_set):>10,}"
            f"{pct(len(all_set)/len(allrows)):>10}{pct(1-len(all_set)/len(allrows)):>13}")

        for name, d in (("train", tr_dup), ("eval", ev_dup)):
            if d > DUP_WARN:
                warnings.append(
                    f"{name}.jsonl is {pct(d)} exact duplicates "
                    f"(threshold {pct(DUP_WARN)}) — inflates apparent dataset size"
                )

        worst = Counter(tr_in).most_common(5)
        if worst and worst[0][1] > 1:
            out()
            out("Most-replicated train inputs (first line shown):")
            for s, n in worst:
                out(f"  {n:>6,}x  {s.splitlines()[0][:66] if s else '<empty>'}")

        # ── 3. Leakage ──────────────────────────────────────────────────────
        section(out, "3. TRAIN -> EVAL LEAKAGE (exact input string match)")
        leaked = [s for s in ev_in if s in tr_set]
        leak_rate = len(leaked) / len(ev_in)
        out(f"Eval rows whose input appears verbatim in train : {len(leaked):>8,}")
        out(f"Eval rows total                                 : {len(ev_in):>8,}")
        out(f"Leakage rate                                    : {pct(leak_rate):>8}")
        out(f"Distinct leaked inputs                          : {len(set(leaked)):>8,}")
        out()
        if leak_rate >= LEAKAGE_FAIL:
            failures.append(
                f"TRAIN/EVAL LEAKAGE: {pct(leak_rate)} of eval ({len(leaked):,} rows) appears "
                f"verbatim in train (threshold {pct(LEAKAGE_FAIL)}). Eval loss and any "
                f"eval-derived metric measure memorisation, not generalization. Note that "
                f"model selection via load_best_model_at_end/eval_loss would be fit to leaked data."
            )
            out("VERDICT: FAIL — eval is contaminated by train.")
        elif leak_rate > LEAKAGE_WARN:
            warnings.append(f"Train/eval leakage present but below FAIL threshold: {pct(leak_rate)}")
            out("VERDICT: WARNING — non-zero leakage.")
        else:
            out("VERDICT: PASS — no exact train/eval overlap.")

        if leaked:
            out()
            out("Examples of leaked inputs (first line shown):")
            for s, n in Counter(leaked).most_common(5):
                out(f"  {n:>5,}x in eval  |  {s.splitlines()[0][:60] if s else '<empty>'}")

        # ── 4. Envelope confound checks ─────────────────────────────────────
        section(out, "4. ENVELOPE CONFOUND CHECKS")
        parsed_all = [parse_request(s) for s in (tr_in + ev_in)]

        def dist_by_label(keyfn, title, limit):
            out()
            out(f"--- {title} ---")
            tally: dict[object, Counter] = defaultdict(Counter)
            for p, y in zip(parsed_all, all_y):
                tally[keyfn(p)][y] += 1
            rows = sorted(tally.items(), key=lambda kv: -sum(kv[1].values()))
            out(f"{'VALUE':<40}{'TOTAL':>9}{'ALLOW':>9}{'BLOCK':>9}{'PURITY':>9}")
            out("-" * 76)
            impure = 0
            for val, c in rows[:limit]:
                tot = sum(c.values())
                purity = max(c.values()) / tot
                out(f"{str(val)[:39]:<40}{tot:>9,}{c['ALLOW']:>9,}{c['BLOCK']:>9,}{purity:>8.1%}")
            if len(rows) > limit:
                rest = rows[limit:]
                rtot = sum(sum(c.values()) for _, c in rest)
                ra = sum(c["ALLOW"] for _, c in rest)
                rb = sum(c["BLOCK"] for _, c in rest)
                out(f"{f'... {len(rest):,} more values':<40}{rtot:>9,}{ra:>9,}{rb:>9,}")
            # deterministic-reveal detection
            hits = []
            for val, c in rows:
                tot = sum(c.values())
                if tot / len(allrows) >= PURITY_MIN_COVERAGE and max(c.values()) / tot >= PURITY_FAIL:
                    hits.append((val, tot, max(c, key=c.get), max(c.values()) / tot))
            return hits

        host_hits = dist_by_label(lambda p: p["headers"].get("host", "<absent>"),
                                  "4a. Host header by label", args.top)
        ua_pres_hits = dist_by_label(
            lambda p: "present" if "user-agent" in p["headers"] else "absent",
            "4b. User-Agent presence by label", 10)
        ua_hits = dist_by_label(lambda p: p["headers"].get("user-agent", "<absent>")[:60],
                                "4c. User-Agent value by label", 10)
        fmt_hits = dist_by_label(lambda p: f"raw_space_in_target={p['malformed_target']}",
                                 "4d. Request-format artifact: raw space in request-target", 10)
        dist_by_label(lambda p: p["method"], "4e. HTTP method by label", 12)
        dist_by_label(lambda p: "present" if "cookie" in p["headers"] else "absent",
                      "4f. Cookie presence by label", 10)
        dist_by_label(lambda p: tuple(sorted(p["headers"].keys())),
                      "4g. Header-name set (structural fingerprint) by label", 12)

        det = []
        for label_txt, hits in (("Host", host_hits), ("User-Agent presence", ua_pres_hits),
                                ("User-Agent value", ua_hits), ("request-format artifact", fmt_hits)):
            for val, tot, lab, pur in hits:
                det.append(f"{label_txt} = {str(val)[:44]!r} -> {lab} "
                           f"({pur:.1%} pure over {tot:,} rows, {pct(tot/len(allrows))} of dataset)")
        out()
        out("--- Deterministic label reveals "
            f"(purity >= {PURITY_FAIL:.0%} at coverage >= {pct(PURITY_MIN_COVERAGE)}) ---")
        if det:
            for d in det:
                out(f"  ! {d}")
        else:
            out("  none detected")

        # ── 5. Trivial baselines ────────────────────────────────────────────
        section(out, "5. TRIVIAL BASELINES (fit on TRAIN, scored on EVAL)")
        out("A trivial baseline uses ONE non-payload feature and never reads the")
        out("request target, query string, or body. If one of these approaches the")
        out("model's accuracy, the dataset — not the model — is doing the work.")
        out()

        n_tr = len(train)
        parsed_tr = parsed_all[:n_tr]
        parsed_ev = parsed_all[n_tr:]

        maj_label = Counter(tr_y).most_common(1)[0][0]
        maj_acc = sum(1 for y in ev_y if y == maj_label) / len(ev_y)
        out(f"{'BASELINE':<46}{'EVAL ACC':>10}{'vs MAJ':>9}{'COVER':>8}{'CELLS':>8}")
        out("-" * 81)
        out(f"{f'majority class (always {maj_label})':<46}{maj_acc:>9.2%}{'—':>9}{'—':>8}{'—':>8}")

        results = []
        for name, (fn, is_env) in feature_extractors().items():
            ftr = [fn(p, None) for p in parsed_tr]
            fev = [fn(p, None) for p in parsed_ev]
            acc, cov, cells = fit_predict_accuracy(ftr, tr_y, fev, ev_y, maj_label)
            results.append((name, acc, acc - maj_acc, cov, cells, is_env))

        for name, acc, margin, cov, cells, _ in sorted(results, key=lambda r: -r[1]):
            out(f"{name[:45]:<46}{acc:>9.2%}{margin:>+9.2%}{cov:>8.1%}{cells:>8,}")

        # generic scan across every header actually present
        out()
        out("--- Generic per-header scan (every header name observed) ---")
        seen_headers: Counter = Counter()
        for p in parsed_all:
            seen_headers.update(p["headers"].keys())
        gen_results = []
        for hname, _cnt in seen_headers.most_common():
            ftr = [p["headers"].get(hname, "<absent>") for p in parsed_tr]
            fev = [p["headers"].get(hname, "<absent>") for p in parsed_ev]
            acc, cov, cells = fit_predict_accuracy(ftr, tr_y, fev, ev_y, maj_label)
            gen_results.append((hname, acc, acc - maj_acc, cells, hname in CAUSAL_HEADERS))
        out(f"{'HEADER':<40}{'EVAL ACC':>10}{'vs MAJ':>9}{'CELLS':>8}  NOTE")
        out("-" * 78)
        for hname, acc, margin, cells, causal in sorted(gen_results, key=lambda r: -r[1]):
            note = "security-relevant, excluded from gate (D1)" if causal else ""
            out(f"{hname[:39]:<40}{acc:>9.2%}{margin:>+9.2%}{cells:>8,}  {note}")

        # gate evaluation — envelope features only
        gate_pool = [(n, a, m) for n, a, m, _c, _k, is_env in results if is_env]
        gate_pool += [(f"header:{h}", a, m) for h, a, m, _k, causal in gen_results if not causal]

        if gate_pool:
            best_name, best_acc, best_margin = max(gate_pool, key=lambda r: r[1])
            out()
            out(f"Strongest non-payload baseline: {best_name} -> {best_acc:.2%} "
                f"({best_margin:+.2%} vs majority class)")
            if best_acc >= SHORTCUT_ACC_FAIL or best_margin >= SHORTCUT_MARGIN_FAIL:
                failures.append(
                    f"DATASET SHORTCUT: '{best_name}' alone classifies {best_acc:.2%} of eval "
                    f"({best_margin:+.2%} over the majority-class baseline) without reading the "
                    f"payload. Thresholds: FAIL at {SHORTCUT_ACC_FAIL:.0%} absolute or "
                    f"{SHORTCUT_MARGIN_FAIL:+.0%} margin. Any accuracy measured on this dataset "
                    f"is uninterpretable as evidence of attack detection."
                )
            elif best_acc >= SHORTCUT_ACC_WARN or best_margin >= SHORTCUT_MARGIN_WARN:
                warnings.append(
                    f"Non-payload feature '{best_name}' reaches {best_acc:.2%} "
                    f"({best_margin:+.2%} vs majority) — below FAIL, still a confound risk"
                )

        if det:
            failures.append(
                f"DETERMINISTIC LABEL REVEAL: {len(det)} envelope value(s) predict the label at "
                f">= {PURITY_FAIL:.0%} purity with >= {pct(PURITY_MIN_COVERAGE)} coverage. "
                f"First: {det[0]}"
            )

        # ── 6. Reproducibility ──────────────────────────────────────────────
        section(out, "6. REPRODUCIBILITY INFORMATION")
        out("Artifact hashes (SHA-256):")
        for p in (args.train, args.eval_path,
                  os.path.join(args.repo, "scripts", "dataset", "parse_dataset.py"),
                  os.path.join(args.repo, "csic_database.csv")):
            if os.path.isfile(p):
                out(f"  {os.path.basename(p):<24} {sha256(p)}")
                out(f"  {'':<24} ({os.path.getsize(p):,} bytes)")
            else:
                out(f"  {os.path.basename(p):<24} <not present>")
        out()
        patt = os.path.expanduser(args.payloads_repo)
        out(f"PayloadsAllTheThings path   : {patt}"
            f"{'' if os.path.isdir(patt) else '  <NOT PRESENT>'}")
        out(f"PayloadsAllTheThings commit : {git_rev(args.payloads_repo)}")
        out(f"firewall-IA commit          : {git_rev(args.repo)} ({git_dirty(args.repo)})")
        out()
        out(f"Python                      : {platform.python_version()} ({sys.executable})")
        out(f"Platform                    : {platform.platform()}")
        hashseed = os.environ.get(
            "PYTHONHASHSEED",
            "<unset — set this before regenerating if determinism is required>",
        )
        out(f"PYTHONHASHSEED              : {hashseed}")

        # ── 7. Verdict ──────────────────────────────────────────────────────
        section(out, "7. FINAL STATUS")
        if failures:
            status, code = "FAIL", 2
        elif warnings:
            status, code = "WARNING", 1
        else:
            status, code = "PASS", 0

        out()
        out(f"    INTEGRITY RESULT: {status}")
        out()

        if failures:
            out(f"BLOCKING FAILURES ({len(failures)}) — evidence:")
            out("-" * 78)
            for i, f in enumerate(failures, 1):
                out(f"  [F{i}] {f}")
                out()
        if warnings:
            out(f"WARNINGS ({len(warnings)}) — not blocking, but affect interpretation:")
            out("-" * 78)
            for i, w in enumerate(warnings, 1):
                out(f"  [W{i}] {w}")
                out()

        if status == "FAIL":
            out("GATE RULE: no training run starts while this reports FAIL.")
            out("See DECISIONS.md (D1, D6, D7) and CONTEXT.md §12 for the agreed remediation.")
        elif status == "WARNING":
            out("Dataset is usable, but the warnings above must be disclosed alongside any")
            out("metric derived from it.")
        else:
            out("No blocking defect detected under the thresholds declared at the top of")
            out("this report. This is a necessary, not sufficient, condition for validity.")

        out()
        out("=" * 78)
        out(f"END OF REPORT — exit code {code}")
        out("=" * 78)
        return code

    finally:
        out.close()


if __name__ == "__main__":
    sys.exit(main())
