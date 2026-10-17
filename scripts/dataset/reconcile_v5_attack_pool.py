"""Reconcile the V5 attack pool counts (stage 2, issue #70). Stdlib only, read-only.

Reads the builder outputs (`attack_pool.jsonl`, `attack_excluded.jsonl`, `manifest.json`) and the
deny-list, and writes `reports/v5/dataset-foundation/attack_pool_reconciliation.md`:

1. row ledger per category: every extracted row lands in exactly one bucket (explicit denominators);
2. unique-canonical waterfall per dedup scope, from V4-accepted payloads to the ACCEPTED pool,
   explaining the gap to the spec §2.3 figures (computed after the spec's initial 20-file deny-list);
3. structural exclusions per rule and category;
4. every record excluded by the stage-3 identity admissibility rules (round 3), with its provenance.

It checks, and fails loudly if any does not hold: the ledger sums, accepted unique canonical keys
equal accepted rows per scope, every accepted row is PENDING_ADJUDICATION, the artifact hashes in
the manifest match the files. It never changes a record.

    python3 scripts/dataset/reconcile_v5_attack_pool.py
"""

import argparse
import json
import os
import sys
from collections import Counter, OrderedDict, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import v5_pools_common as C  # noqa: E402

DEFAULT_DIR = os.path.join(C.DEFAULT_OUT_DIR, "attack")
DEFAULT_DENYLIST = os.path.join(HERE, "v5_lexicon", "patt_third_party_denylist_v1.json")
DEFAULT_OUT = os.path.join(C.REPO_ROOT, "reports", "v5", "dataset-foundation", "attack_pool_reconciliation.md")
V4_PASSED = ("accepted", "not_applied_project_authored")
BUCKETS = ("v4_filter", "category_not_extracted_v5", "third_party_file", "structural", "identity_undefined",
           "identity_inadmissible", "duplicate_exact", "duplicate_canonical", "ACCEPTED")
is_inadmissible = C.is_inadmissible          # stage 3 round 3 (owner ruling); one vocabulary in v5_pools_common


def bucket(r):
    if r["status"] == C.ACCEPTED:
        return "ACCEPTED"
    reason = r["exclusion_reason"]
    if is_inadmissible(reason):
        return "identity_inadmissible"
    for prefix in ("v4_filter", "structural", "identity_undefined"):
        if reason.startswith(prefix + ":"):
            return prefix
    if reason in BUCKETS:
        return reason
    raise ValueError(f"unknown exclusion_reason {reason!r} ({r['record_id']})")


def ledger(records):
    out = OrderedDict()
    for cat in sorted({r["category_v4"] for r in records}):
        rs = [r for r in records if r["category_v4"] == cat]
        row = Counter(bucket(r) for r in rs)
        row = OrderedDict((b, row.get(b, 0)) for b in BUCKETS)
        row["extracted"] = len(rs)
        if sum(row[b] for b in BUCKETS) != row["extracted"]:
            raise AssertionError(f"ledger does not sum for {cat}")
        out[cat] = row
    return out


def waterfall(records, spec_initial, denied):
    """Unique canonical keys per dedup scope after each cumulative step."""
    steps = OrderedDict([
        ("U0_v4_accepted", lambda r: r["v4_filter_reason"] in V4_PASSED),
        ("U1_minus_spec_initial_denylist", lambda r: r["v4_filter_reason"] in V4_PASSED
         and r["source_file"] not in spec_initial),
        ("U2_minus_full_proposed_denylist", lambda r: r["v4_filter_reason"] in V4_PASSED
         and r["source_file"] not in denied),
        ("U3_minus_structural_and_denied_categories", lambda r: r["status"] == C.ACCEPTED
         or r["exclusion_reason"] in ("duplicate_exact", "duplicate_canonical")),
    ])
    sets = defaultdict(lambda: defaultdict(set))
    for r in records:
        if r["canonical_key"] is None:
            continue
        for name, pred in steps.items():
            if pred(r):
                sets[r["dedup_scope"]][name].add(r["canonical_key"])
    out = OrderedDict()
    for scope in sorted(sets):
        accepted = sum(1 for r in records if r["dedup_scope"] == scope and r["status"] == C.ACCEPTED)
        row = OrderedDict((name, len(sets[scope][name])) for name in steps)
        row["accepted_rows"] = accepted
        if row["U3_minus_structural_and_denied_categories"] != accepted:
            raise AssertionError(f"accepted rows != unique canonical survivors for {scope}")
        out[scope] = row
    return out


def check_artifacts(attack_dir, manifest):
    for a in manifest["artifacts"]:
        if C.sha256_file(os.path.join(attack_dir, a["path"])) != a["sha256"]:
            raise AssertionError(f"artifact hash mismatch: {a['path']}")


def reconcile(attack_dir, denylist_path):
    accepted = C.read_jsonl(os.path.join(attack_dir, "attack_pool.jsonl"))
    excluded = C.read_jsonl(os.path.join(attack_dir, "attack_excluded.jsonl"))
    with open(os.path.join(attack_dir, "manifest.json"), encoding="utf-8") as fh:
        manifest = json.load(fh)
    with open(denylist_path, encoding="utf-8") as fh:
        deny = json.load(fh)
    check_artifacts(attack_dir, manifest)
    if any(r["label_status"] != C.LABEL_PENDING for r in accepted):
        raise AssertionError("an accepted record is not PENDING_ADJUDICATION")
    records = accepted + excluded
    denied = {e["path"] for e in deny["denied"]}
    spec_initial = {e["path"] for e in deny["denied"] if e["basis"].startswith("spec_initial_list")}
    structural = Counter((r["category_v4"], r["exclusion_reason"]) for r in excluded
                         if r["exclusion_reason"].startswith("structural:"))
    inadmissible = sorted((r for r in excluded if is_inadmissible(r["exclusion_reason"])),
                          key=lambda r: (r["exclusion_reason"], r["category_v4"], r["source_file"], r["line_index"]))
    return {"total_extracted": len(records), "accepted": len(accepted), "excluded": len(excluded),
            "inadmissible": inadmissible,
            "ledger": ledger(records), "waterfall": waterfall(records, spec_initial, denied),
            "structural": structural, "manifest_counts": manifest["counts"]}


def render(res):
    L = ["# V5 attack pool: count reconciliation (generated by `reconcile_v5_attack_pool.py`)", "",
         f"Rows: {res['total_extracted']} extracted = {res['accepted']} ACCEPTED + {res['excluded']} EXCLUDED. "
         "Every extracted row falls in exactly one bucket. Buckets are applied in pipeline order: V4 quality filter → "
         "category deny-list → third-party file deny-list → structural rules → undefined identity (empty `canonical_key`, "
         "owner ruling D-4) → identity admissibility (table borders, reviewed degenerate identities, keys SPL-9 cannot "
         "observe; stage-3 owner ruling, round 3) → duplicates. All ACCEPTED rows are "
         "`PENDING_ADJUDICATION`. Artifact hashes match the manifest.", "",
         "## 1. Row ledger (denominator = extracted rows of the category)", "",
         "| Category | Extracted | V4 filter | Cat. denied | 3rd-party file | Structural | Identity undefined | Identity inadmissible | Dup exact | Dup canonical | Accepted | Accepted / extracted |",
         "|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for cat, r in res["ledger"].items():
        L.append(f"| {cat} | {r['extracted']} | {r['v4_filter']} | {r['category_not_extracted_v5']} | "
                 f"{r['third_party_file']} | {r['structural']} | {r['identity_undefined']} | {r['identity_inadmissible']} | {r['duplicate_exact']} | {r['duplicate_canonical']} | "
                 f"{r['ACCEPTED']} | {100 * r['ACCEPTED'] / r['extracted']:.1f}% |")
    L += ["", "## 2. Unique canonical payloads per dedup scope (cumulative)", "",
          "U0 = canonical keys of V4-accepted rows. U1 = U0 restricted to files outside the spec's initial "
          "20-file deny-list (this is how spec §2.3 computed its figures). U2 = outside the full PROPOSED "
          "deny-list. U3 = survivors of the structural rules (= ACCEPTED rows, one per canonical key).", "",
          "| Scope | U0 | U1 (spec §2.3 basis) | U2 | U3 = accepted |", "|---|---:|---:|---:|---:|"]
    for scope, w in res["waterfall"].items():
        L.append(f"| {scope} | {w['U0_v4_accepted']} | {w['U1_minus_spec_initial_denylist']} | "
                 f"{w['U2_minus_full_proposed_denylist']} | {w['accepted_rows']} |")
    L += ["", "## 3. Structural exclusions (first flag) per category", "",
          "| Category | Rule | Rows |", "|---|---|---:|"]
    for (cat, rule), n in sorted(res["structural"].items()):
        L.append(f"| {cat} | `{rule.split(':', 1)[1]}` | {n} |")
    L += ["", "## 4. Identity admissibility exclusions (stage-3 owner ruling, round 3)", "",
          "Methodological admissibility of the data, not a security statement: no record below is declared "
          "benign. `identity_unobservable_spl9` rows are legitimate payloads whose family key is shorter than "
          "the SPL-9 4-gram, so their near-duplicates cannot be checked; excluding them is a coverage loss.", "",
          "| Reason | Category | Source file | Line | Record | Payload (wire) |", "|---|---|---|---:|---|---|"]
    for r in res["inadmissible"]:
        wire = r["payload_wire"].replace("|", "\\|").replace("`", "\\`")
        L.append(f"| `{r['exclusion_reason']}` | {r['category_v4']} | `{r['source_file']}` | {r['line_index']} | "
                 f"`{r['record_id']}` | `{wire}` |")
    by = Counter(r["exclusion_reason"] for r in res["inadmissible"])
    L += ["", "Totals: " + ", ".join(f"`{k}` {n}" for k, n in sorted(by.items())) + f"; all {len(res['inadmissible'])}."]
    return "\n".join(L) + "\n"


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--attack-dir", default=DEFAULT_DIR)
    ap.add_argument("--denylist", default=DEFAULT_DENYLIST)
    ap.add_argument("--out", default=DEFAULT_OUT)
    args = ap.parse_args(argv)
    res = reconcile(args.attack_dir, args.denylist)
    text = render(res)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(text)
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
