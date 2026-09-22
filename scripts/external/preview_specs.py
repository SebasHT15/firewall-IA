"""External Test v1 — Phase C OFFLINE build (no Docker, no clients, no model).

Produces the authoring artifacts that can be built before any capture runs, and validates
them:

  1. unseen_structure_support.json  structural support counts over datasets/v4_clean/ — the
                                    repository evidence behind the unseen-structure slice.
  2. spec_preview.jsonl             every ENUMERABLE candidate (the 3 client-driven benign
                                    slices + the 5 BLOCK categories) with its pre-exposure
                                    ground truth and provenance intent. request_text is
                                    null: the frozen bytes come from capture, never hand
                                    authoring. The browser slices are captured whole at
                                    runtime and are not previewable here.
  3. counts.json                    per-slice / per-category draft counts + targets.
  4. independence_precheck.json     COURTESY screen (not the Phase D gate).

It also asserts every preview renders in the exact canonical classifier representation
(wire.assert_canonical), so a case authored here can be replayed byte-exactly later.

Run (any Python with the stdlib; no mitmproxy needed):
    python3 scripts/external/preview_specs.py
"""

from __future__ import annotations

import json
import os
import re
import sys
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import wire  # noqa: E402
import spec_lib  # noqa: E402
import benign_specs  # noqa: E402
import attack_specs  # noqa: E402

REPO_ROOT = spec_lib.REPO_ROOT
OUT_DIR = os.path.join(REPO_ROOT, "datasets", "external_v1", "build")

# Final target counts (protocol section 10). Draft aims ~1.2x per cell.
TARGET_PER_CELL = 40
DRAFT_TARGET_PER_CELL = 48
BROWSER_SLICES = ["browser-navigation", "browser-forms-session"]


# ── 1. unseen-structure support evidence ────────────────────────────────────
def build_support_evidence() -> dict:
    """Count the structural axes the unseen-structure slice relies on, directly over the
    V4 fine-tuning corpus. Zero support == a legitimate unseen structural feature (RQ4)."""
    methods, header_names, content_types, ports = Counter(), Counter(), Counter(), Counter()
    total = 0
    for fn in ("train.jsonl", "eval.jsonl"):
        p = os.path.join(REPO_ROOT, "datasets", "v4_clean", fn)
        if not os.path.exists(p):
            continue
        with open(p, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                text = json.loads(line).get("input", "")
                total += 1
                head = text.split("\n\n", 1)[0]
                lines = head.split("\n")
                parts = lines[0].split(" ")
                if len(parts) == 3:
                    methods[parts[0]] += 1
                for hl in lines[1:]:
                    name, colon, value = hl.partition(": ")
                    if not colon:
                        continue
                    header_names[name.lower()] += 1
                    if name.lower() == "host":
                        hv = value.strip()
                        if hv.startswith("["):
                            m = re.match(r"^\[[^\]]+\](?::(\d+))?$", hv)
                            ports[m.group(1) if m and m.group(1) else "<none>"] += 1
                        elif hv.count(":") == 1:
                            ports[hv.split(":", 1)[1]] += 1
                        else:
                            ports["<none>"] += 1
                    if name.lower() == "content-type":
                        content_types[value.split(";")[0].strip().lower()] += 1
    return {
        "corpus": "datasets/v4_clean/ (train.jsonl + eval.jsonl)",
        "rows": total,
        "note": ("Zero-support structural features are the basis of the unseen-structure "
                 "slice (protocol 4.3, RQ4). This is unseen-input robustness, NOT OOD "
                 "detection: no novelty score or calibrated uncertainty is computed."),
        "methods_observed": dict(methods.most_common()),
        "methods_zero_support_examples": [m for m in ("OPTIONS", "TRACE", "CONNECT",
                                                      "PROPFIND", "MKCOL")
                                          if m not in methods],
        "header_names_observed": dict(header_names.most_common()),
        "n_distinct_header_names": len(header_names),
        "content_types_observed": dict(content_types.most_common()),
        "host_ports_observed": dict(ports.most_common()),
        "lab_port_9100_support": ports.get("9100", 0),
    }


# ── 2/3. preview + counts ────────────────────────────────────────────────────
def build_previews():
    specs = benign_specs.build() + attack_specs.build()
    rows, canon_failures = [], []
    for case_id, spec in spec_lib.assign_case_ids(specs):
        rec = spec.to_record(case_id)
        try:
            wire.assert_canonical(rec["preview_text"])
            rec["preview_canonical"] = True
        except wire.WireError as exc:
            rec["preview_canonical"] = False
            canon_failures.append((case_id, str(exc)))
        rows.append(rec)
    return specs, rows, canon_failures


def build_counts(specs) -> dict:
    by_group = Counter(s.group for s in specs)
    by_decision = Counter(s.expected_decision for s in specs)
    review = Counter(s.review_status for s in specs)
    confidence = Counter(s.label_confidence for s in specs)

    benign_enumerable = {s: by_group.get(s, 0)
                         for s in ("api-json", "api-query", "unseen-structure")}
    attack = {spec_lib.ATTACK_CATEGORY_LABEL[c]: by_group.get(c, 0)
              for c in spec_lib.ATTACK_CATEGORIES}
    return {
        "status": "DRAFT",
        "target_per_cell_final": TARGET_PER_CELL,
        "draft_target_per_cell": DRAFT_TARGET_PER_CELL,
        "enumerable_now": {
            "benign_slices_client_driven": benign_enumerable,
            "block_categories": attack,
            "totals": {"ALLOW_enumerable": by_decision.get("ALLOW", 0),
                       "BLOCK_draft": by_decision.get("BLOCK", 0)},
        },
        "captured_at_runtime": {
            "browser_slices": {s: {"target_final": TARGET_PER_CELL,
                                   "method": "captured whole via Playwright/Chromium; count "
                                             "known only after capture"} for s in BROWSER_SLICES},
        },
        "review_status_breakdown": dict(review),
        "label_confidence_breakdown": dict(confidence),
        "final_composition_target": {
            "ALLOW_total": 200, "BLOCK_total": 200,
            "per_benign_slice": 40, "per_block_category": 40,
        },
    }


def build_manifest(counts, support, precheck) -> dict:
    return {
        "schema": "external-v1-manifest/1",
        "name": "External Test v1",
        "phase": "C — pre-exposure DRAFT candidate pool",
        "status": "DRAFT",
        "generated_utc": _now(),
        "protocol": "docs/external_test_v1_protocol.md",
        "pre_exposure_attestation": {
            "v4_exposure": "ZERO",
            "control_plane_started": False,
            "firewall_data_plane_started": False,
            "classify_contacted": False,
            "note": "Capture uses a CAPTURE-ONLY proxy; no model is in the path (D37).",
        },
        "composition_target_final": {
            "total": 400, "ALLOW": 200, "BLOCK": 200,
            "per_benign_slice": 40, "per_block_category": 40,
            "benign_slices": spec_lib.BENIGN_SLICES,
            "block_categories": {k: spec_lib.ATTACK_CATEGORY_LABEL[k]
                                 for k in spec_lib.ATTACK_CATEGORIES},
            "balance": "50/50 ALLOW/BLOCK, fixed before exposure; not changed after results.",
        },
        "draft_counts": counts["enumerable_now"],
        "browser_slices_captured_at_runtime": counts["captured_at_runtime"]["browser_slices"],
        "provenance": {
            "path": "real client -> capture-proxy (capture-only) -> lab-app",
            "renderer_identity": ("capture_addon imports data_plane.render_request; the "
                                  "captured text is exactly what the firewall would hand "
                                  "/classify (protocol 4.2)."),
            "clients": {
                "browser-navigation": "Playwright/Chromium",
                "browser-forms-session": "Playwright/Chromium",
                "api-json": "Python httpx",
                "api-query": "curl",
                "unseen-structure": "mixed (curl + httpx)",
                "sqli/cmdi/xss/path-traversal/ssrf": "curl + httpx",
            },
            "correlation": "capture-file offset windows (boundaries.json); no marker in any "
                           "request under test (protocol 11).",
            "no_hand_editing": "request_text is the captured text, copied verbatim; never "
                               "edited after capture.",
        },
        "ground_truth_fields": [
            "expected_decision", "attack_category", "benign_slice", "ground_truth_basis",
            "label_confidence", "review_status", "client_profile", "host_type", "method",
            "route", "route_family", "body_type", "payload_placement",
            "request_text", "request_sha256", "capture (file/tag/flow/seq/flow_id/utc)",
        ],
        "unseen_structure_evidence": {
            "source": support["corpus"],
            "rows": support["rows"],
            "distinct_header_names_in_corpus": support["n_distinct_header_names"],
            "methods_observed": list(support["methods_observed"].keys()),
            "lab_port_9100_support": support["lab_port_9100_support"],
            "framing": "unseen-input robustness (RQ4); NOT OOD detection, no novelty score.",
            "detail": "build/unseen_structure_support.json",
        },
        "independence": {
            "precheck": {"clean": precheck["clean"],
                         "collisions": len(precheck["collisions"]),
                         "v4_rows_screened": precheck["v4_rows_screened"]},
            "authoritative_gate": "Phase D, protocol section 7 (exact + canonical + duplicate "
                                  "+ diagnostic + smoke + near-dup + CSIC). NOT RUN HERE.",
            "not_reused_from": ["PayloadsAllTheThings (V4 training source @ e961fef)",
                                "reports/diagnostics/real-http-fp-v1/cases.jsonl",
                                "docker/client/smoke_test.py fixtures",
                                "V4 predictions (V4 never consulted)"],
            "claim_limit": ("Independence is verified (in Phase D) against V4 fine-tuning and "
                            "development data only; no claim about TinyLlama pretraining."),
        },
        "artifacts": {
            "build/spec_preview.jsonl": "authored ENUMERABLE candidates + ground truth; "
                                        "request_text pending capture",
            "build/counts.json": "draft counts and targets",
            "build/unseen_structure_support.json": "V4-corpus structural support evidence",
            "build/independence_precheck.json": "courtesy screen result",
            "candidates/": "populated after capture by label_candidates.py",
        },
        "freeze": {"frozen": False, "artifact_sha256": None, "frozen_utc": None,
                   "note": "NOT frozen. Phase D independence gate and deterministic trim to "
                           "40/cell have NOT run. Do not treat as FROZEN."},
        "limitations_pointer": "docs/external_test_v1_protocol.md section 13",
    }


def _now():
    import datetime
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def main() -> int:
    os.makedirs(OUT_DIR, exist_ok=True)

    support = build_support_evidence()
    with open(os.path.join(OUT_DIR, "unseen_structure_support.json"), "w", encoding="utf-8") as f:
        json.dump(support, f, indent=2, ensure_ascii=False)

    specs, rows, canon_failures = build_previews()
    with open(os.path.join(OUT_DIR, "spec_preview.jsonl"), "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    counts = build_counts(specs)
    with open(os.path.join(OUT_DIR, "counts.json"), "w", encoding="utf-8") as f:
        json.dump(counts, f, indent=2, ensure_ascii=False)

    precheck = spec_lib.precheck_independence(specs, check_v4=True)
    with open(os.path.join(OUT_DIR, "independence_precheck.json"), "w", encoding="utf-8") as f:
        json.dump(precheck, f, indent=2, ensure_ascii=False)

    manifest = build_manifest(counts, support, precheck)
    with open(os.path.join(REPO_ROOT, "datasets", "external_v1", "MANIFEST.draft.json"),
              "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)

    # ── report ──
    print("Phase C offline build")
    print(f"  V4 corpus rows screened for support: {support['rows']}")
    print(f"  distinct header names in corpus:      {support['n_distinct_header_names']}")
    print(f"  OPTIONS/TRACE support:                "
          f"{support['methods_observed'].get('OPTIONS', 0)}/"
          f"{support['methods_observed'].get('TRACE', 0)}  (zero => unseen)")
    print(f"  port 9100 support:                    {support['lab_port_9100_support']}")
    print()
    print("  enumerable draft counts:")
    for k, v in counts["enumerable_now"]["benign_slices_client_driven"].items():
        print(f"    ALLOW {k:20s} {v}")
    for k, v in counts["enumerable_now"]["block_categories"].items():
        print(f"    BLOCK {k:28s} {v}")
    print(f"    ALLOW enumerable total: {counts['enumerable_now']['totals']['ALLOW_enumerable']}")
    print(f"    BLOCK draft total:      {counts['enumerable_now']['totals']['BLOCK_draft']}")
    print(f"  review breakdown: {counts['review_status_breakdown']}")
    print()
    print(f"  canonical previews: {len(rows) - len(canon_failures)}/{len(rows)} pass")
    for cid, err in canon_failures[:10]:
        print(f"    NON-CANONICAL {cid}: {err}")
    print(f"  independence pre-check (courtesy): "
          f"{'CLEAN' if precheck['clean'] else str(len(precheck['collisions'])) + ' COLLISION(S)'}"
          f"  (v4 rows screened: {precheck['v4_rows_screened']})")
    for c in precheck["collisions"][:20]:
        print(f"    COLLISION {c}")
    print()
    print(f"  wrote -> {os.path.relpath(OUT_DIR, REPO_ROOT)}/"
          "{unseen_structure_support.json, spec_preview.jsonl, counts.json, "
          "independence_precheck.json}")

    ok = not canon_failures and precheck["clean"]
    print("\nRESULT:", "OK" if ok else "REVIEW NEEDED (see above)")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
