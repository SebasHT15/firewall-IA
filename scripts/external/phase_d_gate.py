"""External Test v1 — Phase D: ground-truth review + pre-freeze independence gate.

NO MODEL. NO /classify. NO V4 INFERENCE. Reading the V4 train/eval DATASET for collision
checking is expected and allowed (protocol section 7, K). This tool:

  1. re-reviews all captured candidates against ground-truth rules (two independent passes);
  2. runs the pre-freeze independence gate — exact, canonical, internal-duplicate,
     prior-experiment (real-http-fp-v1 + smoke) and near-duplicate checks — using the
     repository's approved parse_dataset_v4.canonical_key();
  3. derives ELIGIBLE counts per cell from review/gate STATUS, without deleting or editing
     any captured evidence.

IT NEVER MUTATES THE CAPTURED DRAFT. candidates/*.jsonl and every request_text / SHA-256 are
read-only evidence; rejections live in derived review/ and gate/ artifacts keyed by case_id.
It does NOT freeze, does NOT trim to 40/cell, and does NOT author replacements.

The two "passes" are two independent, documented rule sets (this is an automated,
reproducible adjudication, not a human panel): Pass 1 validates every candidate; Pass 2
re-examines only the flagged + pre-marked cases against a stricter "confidently defensible?"
policy and resolves each to ACCEPT / EXCLUDE / NEEDS_REVIEW.

Run:
    python3 scripts/external/phase_d_gate.py
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import sys
from collections import Counter, defaultdict, OrderedDict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "dataset"))

import spec_lib          # noqa: E402
from parse_dataset_v4 import canonical_key  # noqa: E402  — the APPROVED canonicalization (D16)

REPO_ROOT = spec_lib.REPO_ROOT
EXT_DIR = os.path.join(REPO_ROOT, "datasets", "external_v1")
CAND = os.path.join(EXT_DIR, "candidates", "cases_draft.jsonl")
REVIEW_DIR = os.path.join(EXT_DIR, "review")
GATE_DIR = os.path.join(EXT_DIR, "gate")

CELLS = spec_lib.BENIGN_SLICES + spec_lib.ATTACK_CATEGORIES
MIN_SUPPORT = 40   # planned 400-case primary design; Phase E (not here) trims to exactly 40

# ── category signatures (heuristics, NO V4): is a payload characteristic of its class? ──
# Broad by design: these must recognise EVERY authored technique so a genuine payload is
# never wrongly flagged non-characteristic. They only ever run on a payload already declared
# to be of that category, so within-category breadth carries no cross-category cost.
CATEGORY_SIGNATURES = {
    "sqli": re.compile(
        r"(--|#|/\*|\bunion\b|\bselect\b|\binsert\b|\bupdate\b|\bdrop\b|\bdelete\b|\bwaitfor\b|"
        r"\bsleep\s*\(|\bbenchmark\s*\(|\bpg_sleep\b|\bexists\s*\(|\bcase\s+when\b|\bhaving\b|"
        r"\blike\b|\border\s+by\b|\bprocedure\s+analyse\b|information_schema|sqlite_master|"
        r"updatexml|extractvalue|group_concat|load_file|outfile|xp_cmdshell|dbms_pipe|pg_read_file|"
        r"['\"]\s*(or|and)\b|\b(or|and)\s+['\"(]?\w*\s*(=|<|>|like)|\)\s*(or|and)\s*\(|"
        r"['\"]\s*(=|\)|--|#)|\bconvert\s*\(|\bcast\s*\(|0x[0-9a-f]{6})", re.I),
    "cmdi": re.compile(
        r"(;|\||&|`|\$\(|\$\{ifs\}|\(\)\s*\{|\{[a-z]+,|/bin/|/etc/|%0a|%0d|\b(cat|id|whoami|uname|"
        r"ls|dir|pwd|env|ping|nslookup|curl|wget|bash|sh|python3?|perl|powershell|netstat|ps|find|"
        r"hostname|sleep|type|ipconfig|nc|mkfifo|base64|arp|echo)\b)", re.I),
    "xss": re.compile(r"(</?script|<img|<svg|<iframe|<body|<details|<video|<audio|<input|<marquee|"
                      r"<object|<embed|<a\s+href|<base|<meta|<form|<math|<style|<textarea|<isindex|"
                      r"<table|<keygen|<select|<div|<b\s|<maction|javascript:|on(error|load|focus|"
                      r"mouseover|toggle|start|pointerover|animationstart)\s*=|alert\(|confirm\(|"
                      r"document\.(cookie|domain)|eval\(|sendbeacon|new\s+image|expression\(|@import)", re.I),
    "path-traversal": re.compile(
        r"(\.\./|\.\.\\|\.\.%2f|\.\.%5c|%2e%2e|%252f|%c0%af|\.\.;/|\.\.//|\\\\[a-z]|::\$data|\.\.%00|"
        r"^~/|/~/|/etc/|/proc/|/root/|/var/|/opt/|/srv/|/home/|windows|system32|boot\.ini|web\.config|"
        r"web-inf|\bpasswd\b|\bshadow\b|gshadow|\.env|\.bash_history|id_rsa|nginx\.conf|app\.py|"
        r"config\.yaml|adapter_config|\.git/|\bsam\b|sources\.list|crontab|sshd_config|machine-id|"
        r"login\.defs|resolv\.conf|timezone|daemon\.json|master\.key|secret\.key|keys\.pem|orders\.db|"
        r"auth\.log|/version|/environ|/cmdline|[a-z]:\\)", re.I),
    "ssrf": re.compile(r"(https?://|file://|gopher://|dict://|ftp://|ldap://|sftp://|tftp://|"
                       r"127\.0\.0\.1|127\.1\b|169\.254|100\.100\.100\.200|metadata|localhost|"
                       r"control-plane|data-plane|lab-app|capture-proxy|destination|10\.\d|192\.168|"
                       r"172\.\d|0x7f|0177|2130706433|\[::1\]|::ffff|nip\.io|\.internal|\.invalid|:8000|"
                       r":8080|:9100|:6379|:389|:22|:69)", re.I),
}
# obvious attack markers that must NOT appear in a benign ALLOW request
BENIGN_ATTACK_MARKERS = re.compile(
    r"(</?script|<img\s|<svg[/ ]|onerror\s*=|onload\s*=|javascript:|\.\./|\.\.%2f|union\s+select|"
    r"['\"]\s*or\s+['\"]?\d|;\s*(cat|id|whoami|ls|uname)\b|\$\(|/etc/passwd|169\.254\.169\.254)", re.I)

LAB_HOSTS = spec_lib.LAB_HOSTS


# ══════════════════════════════════════════════════════════════════════════
# loading
# ══════════════════════════════════════════════════════════════════════════
def load_candidates(path=CAND):
    with open(path, encoding="utf-8") as f:
        return [json.loads(l) for l in f if l.strip()]


def load_v4(root=REPO_ROOT):
    """Return (exact_input_set, canonical_inputs list). Reading the DATASET is allowed (K)."""
    exact, canon = set(), []
    for fn in ("train.jsonl", "eval.jsonl"):
        p = os.path.join(root, "datasets", "v4_clean", fn)
        if not os.path.exists(p):
            continue
        with open(p, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                text = json.loads(line).get("input", "")
                exact.add(text)
                canon.append(canonical_key(text))
    return exact, canon


def load_diag(root=REPO_ROOT):
    p = os.path.join(root, "reports", "diagnostics", "real-http-fp-v1", "cases.jsonl")
    rows = []
    if os.path.exists(p):
        with open(p, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    r = json.loads(line)
                    if r.get("text"):
                        rows.append({"id": r.get("case_id"), "text": r["text"],
                                     "sha": r.get("text_sha256"),
                                     "canon": canonical_key(r["text"])})
    return rows


def load_smoke():
    """The two Docker smoke fixtures baked into docker/client/smoke_test.py."""
    fixtures = [
        {"id": "smoke-ALLOW", "text": "GET /index.html", "canon": canonical_key("/index.html")},
        {"id": "smoke-BLOCK", "text": "GET /products.html?id=1' OR '1'='1",
         "canon": canonical_key("/products.html?id=1' OR '1'='1"),
         "payload_canon": canonical_key("1' OR '1'='1")},
    ]
    return fixtures


# ══════════════════════════════════════════════════════════════════════════
# B. two-pass ground-truth review
# ══════════════════════════════════════════════════════════════════════════
def review_pass1(candidates):
    """Validate every candidate. Returns {case_id: {status, reasons}}."""
    out = {}
    for c in candidates:
        cid, reasons = c["case_id"], []
        dec, cell = c["expected_decision"], c["primary_slice"]
        # structural consistency
        if dec == "BLOCK":
            if c.get("attack_category") != cell or cell not in spec_lib.ATTACK_CATEGORIES:
                reasons.append("category/primary_slice inconsistent")
            if c.get("benign_slice") is not None:
                reasons.append("BLOCK carries a benign_slice")
        elif dec == "ALLOW":
            if c.get("benign_slice") != cell or cell not in spec_lib.BENIGN_SLICES:
                reasons.append("slice/primary_slice inconsistent")
            if c.get("attack_category") is not None:
                reasons.append("ALLOW carries an attack_category")
        else:
            reasons.append(f"invalid expected_decision {dec!r}")
        if not c.get("ground_truth_basis"):
            reasons.append("missing ground_truth_basis")
        if c.get("label_confidence") not in {"high", "medium", "review"}:
            reasons.append("invalid label_confidence")
        # provenance matches the captured flow
        if c.get("capture", {}).get("flow") != cell:
            reasons.append("capture flow != primary_slice")
        if c.get("host") not in LAB_HOSTS:
            reasons.append(f"off-lab host {c.get('host')!r}")
        # semantics
        canon_req = canonical_key(c["request_text"])
        if dec == "BLOCK":
            pay = c.get("payload_decoded", "")
            if not pay:
                reasons.append("BLOCK missing payload_decoded")
            else:
                if canonical_key(pay) not in canon_req:
                    reasons.append("declared payload not present in captured request")
                if not CATEGORY_SIGNATURES[cell].search(pay):
                    reasons.append(f"payload not characteristic of {cell}")
        else:  # ALLOW
            if BENIGN_ATTACK_MARKERS.search(c["request_text"]):
                reasons.append("benign request contains an obvious attack marker")
        # confidence/review flag
        pre_flag = c.get("review_status") == "needs-review" or \
            c.get("label_confidence") in {"medium", "review"}
        status = "FLAG" if (reasons or pre_flag) else "OK"
        out[cid] = {"status": status, "reasons": reasons,
                    "pre_marked_needs_review": c.get("review_status") == "needs-review"}
    return out


def review_pass2(candidates, pass1):
    """Independently adjudicate every FLAGged case to ACCEPT / EXCLUDE / NEEDS_REVIEW.

    Policy (documented): a case is ACCEPTED only if its label is CONFIDENTLY defensible from
    the captured request alone. Otherwise it is EXCLUDED (never force-relabelled). Concretely:
      - a hard Pass-1 structural/semantic inconsistency  -> EXCLUDE
      - a BLOCK case whose payload is not present in the captured request -> EXCLUDE
      - an SSRF case placed in a HEADER whose payload has no URL scheme (bare host/IP in a
        forwarding header) -> EXCLUDE: not confidently an SSRF pattern a firewall must block
      - otherwise (self-evident category pattern present; benign genuinely benign) -> ACCEPT
    """
    by_id = {c["case_id"]: c for c in candidates}
    out = {}
    HARD = {"category/primary_slice inconsistent", "BLOCK carries a benign_slice",
            "slice/primary_slice inconsistent", "ALLOW carries an attack_category",
            "invalid expected_decision", "missing ground_truth_basis",
            "capture flow != primary_slice", "declared payload not present in captured request",
            "BLOCK missing payload_decoded", "benign request contains an obvious attack marker"}
    for cid, p1 in pass1.items():
        if p1["status"] != "FLAG":
            continue
        c = by_id[cid]
        reasons = set(p1["reasons"])
        hard = reasons & HARD
        decision, why, conf = "ACCEPT", "", "high"
        if hard:
            decision, why, conf = "EXCLUDE", "hard consistency/semantic failure: " + \
                "; ".join(sorted(hard)), "high"
        elif c["primary_slice"] == "ssrf" and c.get("payload_placement") == "header" \
                and "://" not in (c.get("payload_decoded") or ""):
            decision = "EXCLUDE"
            why = ("SSRF payload is a bare host/IP in a forwarding header with no URL scheme; "
                   "not confidently a security-relevant SSRF pattern the firewall must block "
                   "(cannot be distinguished from benign forwarding metadata)")
            conf = "medium"
        elif "payload not characteristic of " in " ".join(reasons):
            decision, why, conf = "EXCLUDE", "payload not characteristic of its category", "medium"
        else:
            # pre-marked-needs-review or medium-confidence but self-evident pattern present
            bits = []
            if p1["pre_marked_needs_review"]:
                bits.append("pre-marked needs-review")
            if c["expected_decision"] == "BLOCK":
                bits.append("self-evident category pattern present in captured request")
            else:
                bits.append("genuinely benign lab interaction")
            why, conf = "confidently defensible: " + "; ".join(bits), \
                ("medium" if c.get("label_confidence") == "medium" else "high")
        out[cid] = {
            "case_id": cid, "original_label": c["expected_decision"],
            "final_proposed_label": c["expected_decision"],   # never relabelled here
            "decision": decision, "reason": why, "confidence": conf,
            "reviewer": "phase-d-automated", "pass": 2,
            "pass1_reasons": p1["reasons"],
        }
    return out


# ══════════════════════════════════════════════════════════════════════════
# C/D. independence gate — collisions
# ══════════════════════════════════════════════════════════════════════════
def collision_check(candidates, v4_exact, v4_canon, diag, smoke):
    v4_canon_set = set(v4_canon)
    diag_exact = {d["text"] for d in diag}
    diag_canon = {d["canon"]: d["id"] for d in diag}
    smoke_canon = {s["canon"]: s["id"] for s in smoke}
    smoke_payload_canon = {s["payload_canon"]: s["id"] for s in smoke if "payload_canon" in s}
    out = {}
    for c in candidates:
        cid = c["case_id"]
        text = c["request_text"]
        creq = canonical_key(text)
        cpay = canonical_key(c["payload_decoded"]) if c.get("payload_decoded") else None
        rec = {"case_id": cid, "primary_slice": c["primary_slice"],
               "exact": None, "canonical": None}

        # 1. EXACT (full captured request) vs V4 / diag / smoke
        if text in v4_exact:
            rec["exact"] = {"source": "v4", "detail": "exact request_text in V4 train/eval"}
        elif text in diag_exact:
            rec["exact"] = {"source": "real-http-fp-v1", "detail": "exact request_text"}

        # 2. CANONICAL (approved canonical_key) — whole-request equality, then payload logic
        if rec["exact"] is None:
            if creq in v4_canon_set:
                rec["canonical"] = {"source": "v4", "kind": "request",
                                    "detail": "canonical request equals a V4 row"}
            elif creq in diag_canon:
                rec["canonical"] = {"source": "real-http-fp-v1", "kind": "request",
                                    "matched_id": diag_canon[creq]}
            elif creq in smoke_canon:
                rec["canonical"] = {"source": "smoke", "kind": "request",
                                    "matched_id": smoke_canon[creq]}
            elif cpay and len(cpay) >= 6:
                # payload-level logical collision: the payload's canonical form appears inside
                # a V4/diag/smoke canonical text (protocol 7 check 2, approved canonical_key)
                if cpay in smoke_payload_canon:
                    rec["canonical"] = {"source": "smoke", "kind": "payload",
                                        "matched_id": smoke_payload_canon[cpay]}
                else:
                    for d in diag:
                        if cpay in d["canon"]:
                            rec["canonical"] = {"source": "real-http-fp-v1", "kind": "payload",
                                                "matched_id": d["id"]}
                            break
                    if rec["canonical"] is None:
                        for i, rc in enumerate(v4_canon):
                            if cpay in rc:
                                rec["canonical"] = {"source": "v4", "kind": "payload",
                                                    "matched_row": i}
                                break
        out[cid] = rec
    return out


def internal_duplicates(candidates):
    """Exact (SHA) and canonical(request_text) internal duplicates across the WHOLE set
    (protocol 7 check 3 / task G — global, not per-cell). Deterministic keeper rule:
    the lexicographically smallest case_id in a group is eligible; every other member is
    excluded as an internal duplicate. Byte-identical duplicates are also canonically
    identical, so a canonical group is only reported when it adds members beyond the exact
    groups (a canonical-only duplicate)."""
    by_sha, by_canon = defaultdict(list), defaultdict(list)
    for c in candidates:
        by_sha[c["request_sha256"]].append(c["case_id"])
        by_canon[canonical_key(c["request_text"])].append(c["case_id"])

    result = {c["case_id"]: {"exact_dup_of": None, "canonical_dup_of": None,
                             "is_keeper": True} for c in candidates}
    groups = []
    exact_member_sets = []
    for ids in by_sha.values():
        if len(ids) > 1:
            keeper = sorted(ids)[0]
            exact_member_sets.append(frozenset(ids))
            groups.append({"kind": "exact", "keeper": keeper, "members": sorted(ids)})
            for cid in ids:
                if cid != keeper:
                    result[cid]["exact_dup_of"] = keeper
                    result[cid]["is_keeper"] = False
    for ids in by_canon.values():
        if len(ids) > 1 and frozenset(ids) not in exact_member_sets:
            keeper = sorted(ids)[0]
            groups.append({"kind": "canonical-only", "keeper": keeper, "members": sorted(ids)})
            for cid in ids:
                if cid != keeper:
                    result[cid]["canonical_dup_of"] = keeper
                    result[cid]["is_keeper"] = False
    return result, groups


# ══════════════════════════════════════════════════════════════════════════
# D.5 near-duplicate WARNING (advisory only; never excludes)
# ══════════════════════════════════════════════════════════════════════════
NEAR_DUP_THRESHOLD = 0.60
_TOKEN = re.compile(r"[a-z0-9]{3,}")


def _tokens(s):
    return set(_TOKEN.findall(s))


def near_duplicates(candidates, v4_canon, threshold=NEAR_DUP_THRESHOLD, df_cap=3000):
    """Deterministic heuristic, documented exactly:

      representation : canonical_key(payload_decoded) for BLOCK, else canonical_key(request_text)
      tokens         : set of [a-z0-9]{3,} words of that representation
      similarity     : Jaccard = |A n B| / |A u B|
      prefilter      : inverted index over V4 tokens with document frequency <= df_cap
                       (ultra-common tokens are non-discriminative and skipped); a candidate is
                       only Jaccard-compared to V4 rows sharing >=1 indexed token
      WARN           : Jaccard >= threshold (0.60); a WARN is manual-review evidence and does
                       NOT exclude the candidate.
    """
    v4_tokens = [_tokens(rc) for rc in v4_canon]
    index = defaultdict(list)
    for i, toks in enumerate(v4_tokens):
        for t in toks:
            index[t].append(i)
    index = {t: ids for t, ids in index.items() if len(ids) <= df_cap}

    warns = []
    for c in candidates:
        rep = canonical_key(c["payload_decoded"]) if c["expected_decision"] == "BLOCK" \
            and c.get("payload_decoded") else canonical_key(c["request_text"])
        A = _tokens(rep)
        if not A:
            continue
        cand_rows = set()
        for t in A:
            cand_rows.update(index.get(t, ()))
        best, best_i = 0.0, -1
        for i in cand_rows:
            B = v4_tokens[i]
            j = len(A & B) / len(A | B)
            if j > best:
                best, best_i = j, i
        if best >= threshold:
            warns.append({"case_id": c["case_id"], "primary_slice": c["primary_slice"],
                          "jaccard": round(best, 3), "matched_v4_row": best_i,
                          "note": "WARN only — manual-review evidence, not an exclusion"})
    return warns


# ══════════════════════════════════════════════════════════════════════════
# eligibility + per-cell support
# ══════════════════════════════════════════════════════════════════════════
def derive_eligibility(candidates, pass2, collisions, internal):
    """One primary exclusion reason per case, by priority:
       gt_ambiguity > exact_collision > canonical_collision > internal_duplicate."""
    elig = {}
    for c in candidates:
        cid = c["case_id"]
        reasons = []
        gt = pass2.get(cid)
        if gt and gt["decision"] == "EXCLUDE":
            reasons.append(("gt_ambiguity", gt["reason"]))
        col = collisions[cid]
        if col["exact"]:
            reasons.append(("exact_collision", col["exact"]))
        if col["canonical"]:
            reasons.append(("canonical_collision", col["canonical"]))
        idup = internal[cid]
        if not idup["is_keeper"]:
            keeper = idup["exact_dup_of"] or idup["canonical_dup_of"]
            kind = "exact" if idup["exact_dup_of"] else "canonical"
            reasons.append(("internal_duplicate", {"kind": kind, "keeper": keeper}))
        eligible = not reasons
        primary = reasons[0][0] if reasons else None
        elig[cid] = {"case_id": cid, "primary_slice": c["primary_slice"],
                     "eligible": eligible, "primary_exclusion": primary,
                     "exclusion_reasons": reasons}
    return elig


def summarize(candidates, pass1, pass2, collisions, internal, warns, elig):
    by_cell = defaultdict(lambda: dict(captured=0, gt_accepted=0, excluded_gt=0,
                                       excluded_exact_collision=0, excluded_canonical_collision=0,
                                       excluded_internal_duplicate=0, near_dup_warn=0,
                                       final_eligible=0))
    warn_ids = {w["case_id"] for w in warns}
    for c in candidates:
        cid, cell = c["case_id"], c["primary_slice"]
        cellrec = by_cell[cell]
        cellrec["captured"] += 1
        e = elig[cid]
        if e["primary_exclusion"] != "gt_ambiguity":
            cellrec["gt_accepted"] += 1
        if cid in warn_ids:
            cellrec["near_dup_warn"] += 1
        if e["eligible"]:
            cellrec["final_eligible"] += 1
        else:
            key = {"gt_ambiguity": "excluded_gt",
                   "exact_collision": "excluded_exact_collision",
                   "canonical_collision": "excluded_canonical_collision",
                   "internal_duplicate": "excluded_internal_duplicate"}[e["primary_exclusion"]]
            cellrec[key] += 1
    ordered = OrderedDict((cell, by_cell[cell]) for cell in CELLS)
    deficits = {cell: rec["final_eligible"] for cell, rec in ordered.items()
                if rec["final_eligible"] < MIN_SUPPORT}
    return ordered, deficits


# ══════════════════════════════════════════════════════════════════════════
# driver
# ══════════════════════════════════════════════════════════════════════════
def run(candidates, v4, diag, smoke):
    v4_exact, v4_canon = v4
    pass1 = review_pass1(candidates)
    pass2 = review_pass2(candidates, pass1)
    collisions = collision_check(candidates, v4_exact, v4_canon, diag, smoke)
    internal, dup_groups = internal_duplicates(candidates)
    warns = near_duplicates(candidates, v4_canon)
    elig = derive_eligibility(candidates, pass2, collisions, internal)
    cells, deficits = summarize(candidates, pass1, pass2, collisions, internal, warns, elig)
    return dict(pass1=pass1, pass2=pass2, collisions=collisions, internal=internal,
                dup_groups=dup_groups, warns=warns, elig=elig, cells=cells, deficits=deficits)


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def write_artifacts(candidates, R):
    os.makedirs(REVIEW_DIR, exist_ok=True)
    os.makedirs(GATE_DIR, exist_ok=True)

    # ground-truth review
    with open(os.path.join(REVIEW_DIR, "ground_truth_review.jsonl"), "w", encoding="utf-8") as f:
        for c in candidates:
            cid = c["case_id"]
            rec = {"case_id": cid, "original_label": c["expected_decision"],
                   "primary_slice": c["primary_slice"],
                   "pass1": R["pass1"][cid], "pass2": R["pass2"].get(cid)}
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    pass2_dec = Counter(v["decision"] for v in R["pass2"].values())
    with open(os.path.join(REVIEW_DIR, "ground_truth_review_summary.json"), "w",
              encoding="utf-8") as f:
        json.dump({"generated_utc": _now(), "total": len(candidates),
                   "pass1_flagged": sum(1 for v in R["pass1"].values() if v["status"] == "FLAG"),
                   "pass2_reviewed": len(R["pass2"]),
                   "pass2_decisions": dict(pass2_dec),
                   "note": "Two independent automated rule passes; ambiguous cases EXCLUDED, "
                           "never force-relabelled. No V4 predictions consulted."},
                  f, indent=2, ensure_ascii=False)

    # gate: collisions, internal dups, near-dups, eligibility
    with open(os.path.join(GATE_DIR, "collisions.jsonl"), "w", encoding="utf-8") as f:
        for cid in (c["case_id"] for c in candidates):
            f.write(json.dumps(R["collisions"][cid], ensure_ascii=False) + "\n")
    with open(os.path.join(GATE_DIR, "internal_duplicates.json"), "w", encoding="utf-8") as f:
        json.dump({"groups": R["dup_groups"]}, f, indent=2, ensure_ascii=False)
    with open(os.path.join(GATE_DIR, "near_duplicates.jsonl"), "w", encoding="utf-8") as f:
        for w in R["warns"]:
            f.write(json.dumps(w, ensure_ascii=False) + "\n")
    with open(os.path.join(GATE_DIR, "eligibility.jsonl"), "w", encoding="utf-8") as f:
        for c in candidates:
            f.write(json.dumps(R["elig"][c["case_id"]], ensure_ascii=False) + "\n")
    eligible_ids = defaultdict(list)
    for c in candidates:
        if R["elig"][c["case_id"]]["eligible"]:
            eligible_ids[c["primary_slice"]].append(c["case_id"])
    with open(os.path.join(GATE_DIR, "eligible_case_ids.json"), "w", encoding="utf-8") as f:
        json.dump({k: sorted(v) for k, v in eligible_ids.items()}, f, indent=2)

    summary = {
        "schema": "external-v1-phase-d-gate/1", "status": "DRAFT", "generated_utc": _now(),
        "frozen": False, "trimmed_to_40": False, "classify_contacted": False,
        "v4_inference": "none",
        "canonicalization": "scripts/dataset/parse_dataset_v4.canonical_key (D16, approved)",
        "sources_checked": ["V4 train split", "V4 eval split",
                            "reports/diagnostics/real-http-fp-v1/cases.jsonl",
                            "Docker smoke fixtures (docker/client/smoke_test.py)",
                            "internal (other External v1 candidates)"],
        "near_duplicate_heuristic": near_duplicates.__doc__.strip(),
        "claim": ("No exact or canonical collision was found against the checked V4 "
                  "development data (train+eval, 31,340 rows) and prior project evaluation "
                  "fixtures. No claim is made about TinyLlama pretraining, global payload "
                  "novelty, formal OOD, or absence of semantic similarity.")
        if not any(R["collisions"][c["case_id"]]["exact"] or R["collisions"][c["case_id"]]["canonical"]
                   for c in candidates) else
        ("Collisions were found; see per-cell counts. Colliding candidates are preserved in "
         "the DRAFT and marked excluded from External v1 eligibility."),
        "per_cell": R["cells"],
        "deficits_below_40": R["deficits"],
        "all_cells_meet_40": not R["deficits"],
    }
    with open(os.path.join(GATE_DIR, "gate_summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    return summary


REVIEW_SUP_DIR = os.path.join(EXT_DIR, "review_supplement")
GATE_SUP_DIR = os.path.join(EXT_DIR, "gate_supplement")
SUP_CAND = os.path.join(EXT_DIR, "candidates_supplement",
                        "browser-forms-session-supplement.jsonl")


def supplement_gate(existing, supplement, v4, diag, smoke):
    """Apply the SAME Phase D checks to supplemental candidates, plus an internal-duplicate
    check AGAINST the existing DRAFT. Keeper preference is EXISTING-WINS: a supplement request
    that duplicates any existing candidate is dropped (the existing case is kept), so no other
    cell — and no existing eligible case — is ever displaced. Thresholds are unchanged."""
    v4_exact, v4_canon = v4
    existing_sha = {c["request_sha256"] for c in existing}
    existing_canon = {canonical_key(c["request_text"]) for c in existing}

    pass1 = review_pass1(supplement)
    pass2 = review_pass2(supplement, pass1)
    collisions = collision_check(supplement, v4_exact, v4_canon, diag, smoke)
    warns = near_duplicates(supplement, v4_canon)

    # internal duplicates: first vs existing DRAFT, then within the supplement (lowest id keeps)
    seen_sha, seen_canon = {}, {}
    dup = {}
    for c in sorted(supplement, key=lambda x: x["case_id"]):
        cid = c["case_id"]
        sha, ck = c["request_sha256"], canonical_key(c["request_text"])
        if sha in existing_sha or ck in existing_canon:
            dup[cid] = {"kind": "duplicate_of_existing_draft"}
        elif sha in seen_sha:
            dup[cid] = {"kind": "internal_supplement_exact", "keeper": seen_sha[sha]}
        elif ck in seen_canon:
            dup[cid] = {"kind": "internal_supplement_canonical", "keeper": seen_canon[ck]}
        else:
            seen_sha[sha] = cid
            seen_canon[ck] = cid
            dup[cid] = None

    elig = {}
    for c in supplement:
        cid = c["case_id"]
        reasons = []
        gt = pass2.get(cid)
        if gt and gt["decision"] == "EXCLUDE":
            reasons.append(("gt_ambiguity", gt["reason"]))
        if collisions[cid]["exact"]:
            reasons.append(("exact_collision", collisions[cid]["exact"]))
        if collisions[cid]["canonical"]:
            reasons.append(("canonical_collision", collisions[cid]["canonical"]))
        if dup[cid]:
            reasons.append(("internal_duplicate", dup[cid]))
        elig[cid] = {"case_id": cid, "eligible": not reasons,
                     "primary_exclusion": reasons[0][0] if reasons else None,
                     "exclusion_reasons": reasons}

    new_eligible = [cid for cid, e in elig.items() if e["eligible"]]
    return dict(pass1=pass1, pass2=pass2, collisions=collisions, dup=dup, warns=warns,
                elig=elig, new_eligible=sorted(new_eligible))


def run_supplement_cli(sup_path):
    existing = load_candidates(CAND)
    supplement = load_candidates(sup_path)
    print(f"existing DRAFT: {len(existing)} | supplement captured: {len(supplement)}")
    v4, diag, smoke = load_v4(), load_diag(), load_smoke()
    S = supplement_gate(existing, supplement, v4, diag, smoke)

    # baseline existing eligible for the cell (from the preserved Phase D gate)
    base = None
    gs = os.path.join(GATE_DIR, "gate_summary.json")
    ids = os.path.join(GATE_DIR, "eligible_case_ids.json")
    if os.path.exists(gs):
        base = json.load(open(gs))["per_cell"]["browser-forms-session"]["final_eligible"]
    elif os.path.exists(ids):
        base = len(json.load(open(ids)).get("browser-forms-session", []))
    else:
        raise SystemExit("existing Phase D gate evidence not found; run the full gate first")
    updated = base + len(S["new_eligible"])

    os.makedirs(REVIEW_SUP_DIR, exist_ok=True)
    os.makedirs(GATE_SUP_DIR, exist_ok=True)
    with open(os.path.join(REVIEW_SUP_DIR, "ground_truth_review.jsonl"), "w",
              encoding="utf-8") as f:
        for c in supplement:
            f.write(json.dumps({"case_id": c["case_id"], "pass1": S["pass1"][c["case_id"]],
                                "pass2": S["pass2"].get(c["case_id"])}, ensure_ascii=False) + "\n")
    with open(os.path.join(GATE_SUP_DIR, "collisions.jsonl"), "w", encoding="utf-8") as f:
        for c in supplement:
            f.write(json.dumps(S["collisions"][c["case_id"]], ensure_ascii=False) + "\n")
    with open(os.path.join(GATE_SUP_DIR, "eligibility.jsonl"), "w", encoding="utf-8") as f:
        for c in supplement:
            f.write(json.dumps({**S["elig"][c["case_id"]],
                                "dup": S["dup"][c["case_id"]]}, ensure_ascii=False) + "\n")
    with open(os.path.join(GATE_SUP_DIR, "near_duplicates.jsonl"), "w", encoding="utf-8") as f:
        for w in S["warns"]:
            f.write(json.dumps(w, ensure_ascii=False) + "\n")
    summary = {
        "schema": "external-v1-phase-d-supplement-gate/1", "status": "DRAFT",
        "generated_utc": _now(), "frozen": False, "trimmed_to_40": False,
        "classify_contacted": False, "v4_inference": "none",
        "run_tag": "pre-freeze-supplement-browser-forms-session",
        "cell": "browser-forms-session",
        "existing_eligible": base, "supplement_captured": len(supplement),
        "supplement_new_eligible": len(S["new_eligible"]),
        "updated_eligible": updated,
        "meets_40": updated >= MIN_SUPPORT,
        "new_eligible_case_ids": S["new_eligible"],
        "keeper_rule": "existing DRAFT wins over supplement; other 9 cells untouched by design",
        "gate_unchanged": "same thresholds/checks as Phase D; no request modified",
        "pass2_decisions": dict(Counter(v["decision"] for v in S["pass2"].values())),
        "exact_collisions": sum(1 for c in supplement if S["collisions"][c["case_id"]]["exact"]),
        "canonical_collisions": sum(1 for c in supplement
                                    if S["collisions"][c["case_id"]]["canonical"]),
        "duplicate_of_existing": sum(1 for c in supplement
                                     if S["dup"][c["case_id"]]
                                     and S["dup"][c["case_id"]]["kind"] == "duplicate_of_existing_draft"),
        "internal_supplement_dups": sum(1 for c in supplement
                                        if S["dup"][c["case_id"]]
                                        and "internal_supplement" in S["dup"][c["case_id"]]["kind"]),
        "near_dup_warn": len(S["warns"]),
    }
    with open(os.path.join(GATE_SUP_DIR, "gate_summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    print("\n=== supplement ground-truth review ===")
    print(f"  pass2 decisions: {summary['pass2_decisions']}")
    print("\n=== supplement gate ===")
    print(f"  exact collisions:        {summary['exact_collisions']}")
    print(f"  canonical collisions:    {summary['canonical_collisions']}")
    print(f"  duplicate of existing:   {summary['duplicate_of_existing']}")
    print(f"  internal supplement dup: {summary['internal_supplement_dups']}")
    print(f"  near-dup warnings:       {summary['near_dup_warn']}")
    print(f"\n  browser-forms-session: existing {base} + new {len(S['new_eligible'])} "
          f"= {updated} eligible  ({'MEETS >=40' if updated >= MIN_SUPPORT else 'STILL < 40'})")
    print(f"  new eligible case_ids: {S['new_eligible']}")
    print("\n  other 9 cells untouched (not recomputed). status: DRAFT | not frozen | "
          "not trimmed | /classify never | V4 inference none")
    print(f"  artifacts -> datasets/external_v1/{{review_supplement,gate_supplement}}/")
    return 0 if updated >= MIN_SUPPORT else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--candidates", default=CAND)
    ap.add_argument("--supplement", action="store_true",
                    help="run the browser-forms-session SUPPLEMENT gate instead of the full gate")
    ap.add_argument("--supplement-candidates", default=SUP_CAND)
    args = ap.parse_args(argv)

    if args.supplement:
        return run_supplement_cli(args.supplement_candidates)

    candidates = load_candidates(args.candidates)
    print(f"loaded {len(candidates)} captured candidates (read-only)")
    print("loading V4 train+eval + diagnostic + smoke corpora (dataset read only; no model)...")
    v4 = load_v4()
    diag = load_diag()
    smoke = load_smoke()
    print(f"  V4 rows: {len(v4[0])} exact / {len(v4[1])} canonical | diag: {len(diag)} | "
          f"smoke: {len(smoke)}")

    R = run(candidates, v4, diag, smoke)
    summary = write_artifacts(candidates, R)

    # report
    print("\n=== ground-truth review ===")
    print(f"  pass1 flagged: {sum(1 for v in R['pass1'].values() if v['status']=='FLAG')}")
    print(f"  pass2 decisions: {Counter(v['decision'] for v in R['pass2'].values())}")
    for cid, v in sorted(R["pass2"].items()):
        print(f"    {cid:24s} {v['decision']:12s} {v['reason'][:80]}")
    print("\n=== per-cell eligibility ===")
    hdr = ("cell", "cap", "gtOK", "xGT", "xExact", "xCanon", "xIntDup", "nearW", "ELIG")
    print("  {:22s}{:>5}{:>6}{:>5}{:>7}{:>7}{:>8}{:>7}{:>6}".format(*hdr))
    for cell, r in R["cells"].items():
        print("  {:22s}{:>5}{:>6}{:>5}{:>7}{:>7}{:>8}{:>7}{:>6}".format(
            cell, r["captured"], r["gt_accepted"], r["excluded_gt"],
            r["excluded_exact_collision"], r["excluded_canonical_collision"],
            r["excluded_internal_duplicate"], r["near_dup_warn"], r["final_eligible"]))
    print(f"\n  exact collisions:     {sum(1 for c in candidates if R['collisions'][c['case_id']]['exact'])}")
    print(f"  canonical collisions: {sum(1 for c in candidates if R['collisions'][c['case_id']]['canonical'])}")
    print(f"  internal dup groups:  {len(R['dup_groups'])}")
    print(f"  near-dup warnings:    {len(R['warns'])}")
    print(f"\n  status: DRAFT | frozen: False | trimmed: False | /classify: never | V4 inference: none")
    if R["deficits"]:
        print(f"\n  ***** DEFICIT: cells below {MIN_SUPPORT} eligible: {R['deficits']} — STOP for user decision")
    else:
        print(f"\n  all 10 cells have >= {MIN_SUPPORT} eligible.")
    print(f"\n  artifacts -> datasets/external_v1/{{review,gate}}/")
    return 1 if R["deficits"] else 0


if __name__ == "__main__":
    sys.exit(main())
