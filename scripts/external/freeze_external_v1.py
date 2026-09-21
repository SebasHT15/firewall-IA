"""External Test v1 — Phase E: deterministic selection + FREEZE.

NO MODEL. NO /classify. NO V4. Reading the dataset / review / gate artifacts is allowed.

Selects exactly 40 Phase-D-eligible cases per primary cell (400 total, 200 ALLOW / 200 BLOCK)
by a fixed, seeded, content-independent rule, validates every freeze invariant, and — only if
all hold — writes the immutable frozen artifacts and flips status DRAFT -> FROZEN. It never
edits a captured request_text, never selects a case by hand, and refuses to overwrite an
existing frozen manifest.

DETERMINISTIC SELECTION RULE (documented BEFORE selection; the protocol fixes only
"deterministic, seeded trim", §9/§10, so this exact rule is declared here):

    seed = "external-v1-freeze-v1"
    selection_key(case) = SHA256(seed + "|" + primary_cell + "|" + case_id + "|"
                                 + request_sha256).hexdigest()
    within each cell: sort ascending by selection_key, take the first 40 (selected),
                      leave the rest as unselected reserves.

The browser-forms-session cell combines original + supplemental eligible cases before the rule
is applied. Selection is purely a function of (seed, cell, case_id, request_sha256) — never of
case content, order, or any model output.

INTEGRITY HASH (documented): order the 400 frozen cases by (cell order, selection_key asc),
build the newline-joined list of "case_id|request_sha256", and SHA-256 that canonical list.

Run:
    python3 scripts/external/freeze_external_v1.py
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import spec_lib  # noqa: E402

REPO_ROOT = spec_lib.REPO_ROOT
EXT = os.path.join(REPO_ROOT, "datasets", "external_v1")
CAND = os.path.join(EXT, "candidates", "cases_draft.jsonl")
SUP_CAND = os.path.join(EXT, "candidates_supplement", "browser-forms-session-supplement.jsonl")
GATE = os.path.join(EXT, "gate")
GATE_SUP = os.path.join(EXT, "gate_supplement")
REVIEW = os.path.join(EXT, "review", "ground_truth_review.jsonl")
REVIEW_SUP = os.path.join(EXT, "review_supplement", "ground_truth_review.jsonl")

SEED = "external-v1-freeze-v1"
PER_CELL = 40
CELLS = spec_lib.BENIGN_SLICES + spec_lib.ATTACK_CATEGORIES

FROZEN_FIELDS = [
    "case_id", "primary_cell", "expected_decision", "attack_category", "benign_slice",
    "client_profile", "method", "route", "path", "host", "host_type", "port", "http_version",
    "body_type", "payload_placement", "payload_decoded", "technique", "ground_truth_basis",
    "label_confidence", "final_review_status", "source", "source_artifact",
    "capture", "request_bytes", "request_text", "request_sha256", "selection_key",
]


def sha_text(t):
    return hashlib.sha256(t.encode("utf-8")).hexdigest()


def load_jsonl(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


def selection_key(cell, case_id, request_sha256, seed=SEED):
    return hashlib.sha256(f"{seed}|{cell}|{case_id}|{request_sha256}".encode("utf-8")).hexdigest()


def select_per_cell(pool, per_cell=PER_CELL, cells=CELLS):
    """Deterministic per-cell selection: sort ascending by selection_key, take first `per_cell`.
    Returns (selected_list, reserves_by_cell). Independent of input order and of content."""
    selected, reserves = [], {}
    for cell in cells:
        ordered = sorted(pool.get(cell, []), key=lambda r: r["selection_key"])
        selected.extend(ordered[:per_cell])
        reserves[cell] = [r["case_id"] for r in ordered[per_cell:]]
    return selected, reserves


def load_review_decisions(path):
    """case_id -> pass2 decision (ACCEPT/EXCLUDE/NEEDS_REVIEW) or None."""
    out = {}
    if os.path.exists(path):
        for r in load_jsonl(path):
            p2 = r.get("pass2")
            out[r["case_id"]] = p2["decision"] if p2 else None
    return out


def build_frozen_record(c, cell, source, artifact, review_dec):
    key = selection_key(cell, c["case_id"], c["request_sha256"])
    final_review = ("reviewed-accepted" if review_dec == "ACCEPT"
                    else "auto-accepted" if review_dec is None else review_dec)
    rec = {
        "case_id": c["case_id"], "primary_cell": cell,
        "expected_decision": c["expected_decision"],
        "attack_category": c.get("attack_category"),
        "benign_slice": c.get("benign_slice"),
        "client_profile": c.get("client_profile"),
        "method": c.get("method"), "route": c.get("route"), "path": c.get("path"),
        "host": c.get("host"), "host_type": c.get("host_type"), "port": c.get("port"),
        "http_version": c.get("http_version"), "body_type": c.get("body_type"),
        "payload_placement": c.get("payload_placement"),
        "payload_decoded": c.get("payload_decoded"),
        "technique": c.get("technique"), "ground_truth_basis": c.get("ground_truth_basis"),
        "label_confidence": c.get("label_confidence"),
        "final_review_status": final_review,
        "source": source, "source_artifact": artifact,
        "capture": c.get("capture"),
        "request_bytes": c.get("request_bytes"),
        "request_text": c["request_text"], "request_sha256": c["request_sha256"],
        "selection_key": key,
    }
    return rec


class FreezeError(SystemExit):
    pass


def validate(selected, eligible_ids, gt_excluded, collided, review_all):
    problems = []
    n = len(selected)
    allow = [s for s in selected if s["expected_decision"] == "ALLOW"]
    block = [s for s in selected if s["expected_decision"] == "BLOCK"]
    if n != 400:
        problems.append(f"total selected {n} != 400")
    if len(allow) != 200:
        problems.append(f"ALLOW {len(allow)} != 200")
    if len(block) != 200:
        problems.append(f"BLOCK {len(block)} != 200")
    from collections import Counter
    per = Counter(s["primary_cell"] for s in selected)
    for cell in CELLS:
        if per.get(cell, 0) != PER_CELL:
            problems.append(f"cell {cell} has {per.get(cell,0)} != {PER_CELL}")
    ids = [s["case_id"] for s in selected]
    if len(set(ids)) != len(ids):
        problems.append("duplicate case_id among selected")
    shas = [s["request_sha256"] for s in selected]
    if len(set(shas)) != len(shas):
        problems.append("duplicate request_sha256 among selected (internal duplicate leaked)")
    for s in selected:
        if s["case_id"] not in eligible_ids:
            problems.append(f"{s['case_id']} selected but NOT Phase-D eligible")
        if s["case_id"] in gt_excluded:
            problems.append(f"{s['case_id']} is a ground-truth exclusion")
        if s["case_id"] in collided:
            problems.append(f"{s['case_id']} has an exact/canonical collision")
        if sha_text(s["request_text"]) != s["request_sha256"]:
            problems.append(f"{s['case_id']} request_text SHA-256 does not recompute")
        if not s["expected_decision"]:
            problems.append(f"{s['case_id']} missing final ground truth")
        if review_all.get(s["case_id"]) == "NEEDS_REVIEW":
            problems.append(f"{s['case_id']} is an unresolved NEEDS_REVIEW case")
        if s["source"] == "supplement" and not (s.get("capture") or {}).get("run_tag"):
            problems.append(f"{s['case_id']} supplement provenance (run_tag) missing")
    return problems


def integrity_hash(frozen):
    ordered = sorted(frozen, key=lambda r: (CELLS.index(r["primary_cell"]), r["selection_key"]))
    canonical = "\n".join(f"{r['case_id']}|{r['request_sha256']}" for r in ordered)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest(), ordered


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=EXT, help="output root (default datasets/external_v1)")
    ap.add_argument("--force", action="store_true", help="allow re-write of a non-frozen dir")
    args = ap.parse_args(argv)

    manifest_path = os.path.join(args.out, "manifest.json")
    if os.path.exists(manifest_path):
        m = json.load(open(manifest_path))
        if m.get("frozen") or m.get("status") == "FROZEN":
            raise FreezeError(f"REFUSING: {manifest_path} is already FROZEN (immutable; "
                              "any change requires external_v2).")
        if not args.force:
            raise FreezeError(f"{manifest_path} exists and is not frozen; pass --force to rewrite")

    # ── load candidates + eligibility ──
    orig = {c["case_id"]: c for c in load_jsonl(CAND)}
    sup = {c["case_id"]: c for c in load_jsonl(SUP_CAND)} if os.path.exists(SUP_CAND) else {}
    orig_elig = json.load(open(os.path.join(GATE, "eligible_case_ids.json")))
    sup_new = set(json.load(open(os.path.join(GATE_SUP, "gate_summary.json")))["new_eligible_case_ids"]) \
        if os.path.exists(os.path.join(GATE_SUP, "gate_summary.json")) else set()

    review_all = load_review_decisions(REVIEW)
    review_all.update(load_review_decisions(REVIEW_SUP))
    gt_excluded = {cid for cid, d in review_all.items() if d == "EXCLUDE"}
    collided = set()
    for gp in (GATE, GATE_SUP):
        cpath = os.path.join(gp, "collisions.jsonl")
        if os.path.exists(cpath):
            for r in load_jsonl(cpath):
                if r.get("exact") or r.get("canonical"):
                    collided.add(r["case_id"])

    # ── build eligible pool per cell ──
    pool = {cell: [] for cell in CELLS}
    eligible_ids = set()
    for cell in CELLS:
        for cid in orig_elig.get(cell, []):
            pool[cell].append(build_frozen_record(orig[cid], cell, "original",
                                                   "candidates/cases_draft.jsonl",
                                                   review_all.get(cid)))
            eligible_ids.add(cid)
    for cid in sorted(sup_new):
        pool["browser-forms-session"].append(build_frozen_record(
            sup[cid], "browser-forms-session", "supplement",
            "candidates_supplement/browser-forms-session-supplement.jsonl", review_all.get(cid)))
        eligible_ids.add(cid)

    # ── deterministic selection ──
    for cell in CELLS:
        if len(pool[cell]) < PER_CELL:
            raise FreezeError(f"cell {cell} has only {len(pool[cell])} eligible < {PER_CELL}; "
                              "cannot freeze")
    selected, reserves = select_per_cell(pool)

    # ── validate (hard-fail, no partial write) ──
    problems = validate(selected, eligible_ids, gt_excluded, collided, review_all)
    if problems:
        print("FREEZE VALIDATION FAILED — not freezing:")
        for p in problems:
            print(f"  - {p}")
        raise FreezeError(1)

    ihash, ordered = integrity_hash(selected)

    # ── write frozen artifacts ──
    os.makedirs(args.out, exist_ok=True)
    freeze_dir = os.path.join(args.out, "freeze")
    os.makedirs(freeze_dir, exist_ok=True)
    cases_path = os.path.join(args.out, "cases.jsonl")
    with open(cases_path, "w", encoding="utf-8") as f:
        for r in ordered:
            f.write(json.dumps({k: r.get(k) for k in FROZEN_FIELDS}, ensure_ascii=False) + "\n")
    artifact_sha = hashlib.sha256(open(cases_path, "rb").read()).hexdigest()

    frozen_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
    from collections import Counter
    n_supp = sum(1 for r in selected
                 if r["source"] == "supplement" and r["primary_cell"] == "browser-forms-session")
    n_orig_bfs = sum(1 for r in selected
                     if r["source"] == "original" and r["primary_cell"] == "browser-forms-session")

    manifest = {
        "name": "External Test v1", "version": "external_v1", "status": "FROZEN",
        "frozen": True, "frozen_utc": frozen_utc, "protocol": "docs/external_test_v1_protocol.md",
        "total": len(selected),
        "ALLOW": sum(1 for r in selected if r["expected_decision"] == "ALLOW"),
        "BLOCK": sum(1 for r in selected if r["expected_decision"] == "BLOCK"),
        "per_cell": {cell: PER_CELL for cell in CELLS},
        "per_cell_selected": dict(Counter(r["primary_cell"] for r in selected)),
        "browser_forms_session_composition": {"original_selected": n_orig_bfs,
                                              "supplement_selected": n_supp},
        "artifact_sha256": artifact_sha,
        "integrity_hash": ihash,
        "integrity_hash_method": ("SHA-256 of the newline-joined 'case_id|request_sha256' list, "
                                  "cases ordered by (cell order, selection_key ascending)."),
        "selection": {
            "method": "seeded, content-independent per-cell SHA-256 key; sort ascending; first 40",
            "seed": SEED,
            "key_formula": "SHA256(seed|primary_cell|case_id|request_sha256)",
            "note": "No manual choice; no model output; independent of input order and content.",
        },
        "v4_exposure_at_freeze": "zero",
        "classify_contacted": False,
        "freeze_before_any_classify": True,
        "provenance": {
            "original_draft": "candidates/cases_draft.jsonl (Phase C capture)",
            "supplement": "candidates_supplement/browser-forms-session-supplement.jsonl "
                          "(pre-freeze supplemental capture; run_tag "
                          "pre-freeze-supplement-browser-forms-session)",
            "phase_d_evidence": ["review/", "gate/"],
            "supplement_evidence": ["review_supplement/", "gate_supplement/"],
            "capture_files": ["extv1-draft.jsonl", "extv1-browser-forms-supplement.jsonl"],
            "preserved": "All pre-freeze evidence retained; the frozen set is a DERIVED subset.",
        },
        "eligible_totals": {cell: len(pool[cell]) for cell in CELLS},
        "reserves_unselected": {cell: len(reserves[cell]) for cell in CELLS},
        "immutability": ("External v1 is immutable at the commit containing this manifest.json "
                         "with status FROZEN, artifact_sha256 and frozen_utc. Any later change "
                         "to any case requires external_v2, including correcting a mislabel."),
        "d37_tripwire": ("Reporting aggregate/per-slice metrics does not consume the set. The "
                         "moment individual External v1 errors are used to develop/train/select "
                         "V5, External v1 becomes V5 development data and external_v2 is required "
                         "before any V5 claim."),
        "independence_claim": ("No exact or canonical collision vs checked V4 dev data "
                               "(train+eval, 31,340 rows), real-http-fp-v1, or smoke fixtures. "
                               "No claim re TinyLlama pretraining, global novelty, or OOD."),
        "limitations_pointer": "docs/external_test_v1_protocol.md section 13",
    }
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)

    with open(os.path.join(freeze_dir, "selected_case_ids.json"), "w", encoding="utf-8") as f:
        sel = {cell: [] for cell in CELLS}
        for r in selected:
            sel[r["primary_cell"]].append(r["case_id"])
        json.dump({cell: sorted(sel[cell]) for cell in CELLS}, f, indent=2)
    with open(os.path.join(freeze_dir, "reserve_case_ids.json"), "w", encoding="utf-8") as f:
        json.dump({cell: sorted(reserves[cell]) for cell in CELLS}, f, indent=2)
    with open(os.path.join(freeze_dir, "selection_keys.jsonl"), "w", encoding="utf-8") as f:
        selected_ids = {r["case_id"] for r in selected}
        for cell in CELLS:
            for r in pool[cell]:
                f.write(json.dumps({"case_id": r["case_id"], "primary_cell": cell,
                                    "request_sha256": r["request_sha256"],
                                    "selection_key": r["selection_key"],
                                    "selected": r["case_id"] in selected_ids},
                                   ensure_ascii=False) + "\n")

    sums_path = os.path.join(args.out, "SHA256SUMS")
    with open(sums_path, "w", encoding="utf-8") as f:
        for rel in ("cases.jsonl", "freeze/selected_case_ids.json",
                    "freeze/reserve_case_ids.json", "freeze/selection_keys.jsonl"):
            p = os.path.join(args.out, rel)
            f.write(f"{hashlib.sha256(open(p,'rb').read()).hexdigest()}  {rel}\n")

    # ── report ──
    print("FROZEN — External Test v1")
    print(f"  total: {manifest['total']} | ALLOW {manifest['ALLOW']} | BLOCK {manifest['BLOCK']}")
    for cell in CELLS:
        print(f"    {cell:24s} selected {PER_CELL} / eligible {len(pool[cell])} "
              f"/ reserve {len(reserves[cell])}")
    print(f"  browser-forms-session selected: {n_orig_bfs} original + {n_supp} supplement")
    print(f"  artifact_sha256: {artifact_sha}")
    print(f"  integrity_hash:  {ihash}")
    print(f"  frozen_utc: {frozen_utc}")
    print(f"  V4 exposure at freeze: zero | /classify contacted: never")
    print(f"  wrote -> {os.path.relpath(cases_path, REPO_ROOT)}, manifest.json, SHA256SUMS, freeze/")
    return 0


if __name__ == "__main__":
    sys.exit(main())
