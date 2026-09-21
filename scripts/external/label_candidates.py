"""External Test v1 — Phase C DRAFT assembler (host-side, NO Docker, NO model).

Turns the capture produced by run_capture.py into labelled DRAFT candidates. It runs AFTER
capture and needs no Docker: it reads the capture JSONL and the boundaries manifest off the
shared log directory and writes the candidate artifacts under datasets/external_v1/.

Ground truth is attached here, before any V4 exposure, from the flow that produced each
request (protocol section 8): browser and API/query/unseen flows are ALLOW; the five attack
flows are BLOCK with their category. The captured request_text is copied VERBATIM — it is
never hand-edited after capture — and its SHA-256 is re-verified against the capture record.

Correlation is by capture-file OFFSET (boundaries.json), never by a marker in a request
under test:
  - enumerable flows: the window's records map one-to-one, in order, to the flow's Specs, so
    each captured request inherits that Spec's category/technique/placement/basis. A window
    whose size does not equal the Spec count is reported and that flow is left UNLABELLED
    rather than mis-aligned.
  - browser flows: every captured record in the window is one ALLOW candidate in that slice,
    sub-resources included (declared before exposure, protocol 4.2).

Status stays DRAFT. This tool does NOT run the Phase D independence gate, does NOT freeze,
and never contacts /classify.

Run:
    python3 scripts/external/label_candidates.py \
        --capture docker/.lab-logs/capture/capture.jsonl \
        --boundaries docker/.lab-logs/capture/boundaries.json
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import sys
from collections import Counter, OrderedDict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import wire            # noqa: E402
import spec_lib        # noqa: E402
import benign_specs    # noqa: E402
import attack_specs    # noqa: E402

REPO_ROOT = spec_lib.REPO_ROOT
OUT_DIR = os.path.join(REPO_ROOT, "datasets", "external_v1")
CAND_DIR = os.path.join(OUT_DIR, "candidates")

BROWSER_SLICES = {"browser-navigation", "browser-forms-session"}


def load_jsonl(path):
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def grouped_specs() -> "OrderedDict[str, list]":
    """Re-derive the (case_id, Spec) list per group, in the same deterministic order
    run_capture.py sent them."""
    combined = benign_specs.build() + attack_specs.build()
    out: "OrderedDict[str, list]" = OrderedDict()
    for case_id, spec in spec_lib.assign_case_ids(combined):
        out.setdefault(spec.group, []).append((case_id, spec))
    return out


def infer_body_type(rec) -> str:
    if rec.get("body_bytes", 0) == 0:
        return "none"
    text = rec.get("request_text", "")
    lo = text.lower()
    if "content-type: application/json" in lo:
        return "json"
    if "content-type: application/x-www-form-urlencoded" in lo:
        return "form"
    if "content-type: multipart/form-data" in lo:
        return "multipart"
    return "other"


def base_candidate(rec, capture_file, flow) -> dict:
    """Provenance fields common to every candidate, taken from the CAPTURE record."""
    host = rec.get("host", "")
    return {
        # exact captured classifier representation + hash (never hand-edited)
        "request_text": rec["request_text"],
        "request_sha256": rec["request_sha256"],
        "request_bytes": rec.get("request_bytes"),
        # route / method / host context, from the captured request
        "method": rec.get("method"),
        "route": rec.get("path", "").split("?", 1)[0],
        "path": rec.get("path"),
        "host": host,
        "host_type": "api-alias" if host.startswith("api.") else (
            "shop-alias" if host.startswith("shop.") else "other"),
        "port": rec.get("port"),
        "http_version": rec.get("http_version"),
        # capture / run identity
        "capture": {
            "capture_file": os.path.basename(capture_file),
            "capture_tag": flow,
            "flow": flow,
            "seq": rec.get("seq"),
            "flow_id": rec.get("flow_id"),
            "captured_utc": rec.get("captured_utc"),
        },
    }


def verify_text(rec, problems, case_id):
    """SHA-256 must match the capture record, and the text must be canonical (replay-able)."""
    text = rec["request_text"]
    if wire.sha256_text(text) != rec["request_sha256"]:
        problems.append(f"{case_id}: sha256 mismatch vs capture record")
    try:
        wire.assert_canonical(text)
    except wire.WireError as exc:
        problems.append(f"{case_id}: non-canonical captured text ({exc})")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--capture", default=os.path.join(
        REPO_ROOT, "docker", ".lab-logs", "capture", "capture.jsonl"))
    ap.add_argument("--boundaries", default=os.path.join(
        REPO_ROOT, "docker", ".lab-logs", "capture", "boundaries.json"))
    ap.add_argument("--out", default=CAND_DIR,
                    help="output directory for candidate artifacts (default: "
                         "datasets/external_v1/candidates/)")
    args = ap.parse_args(argv)
    cand_dir = args.out

    if not os.path.exists(args.capture) or not os.path.exists(args.boundaries):
        print("Capture artifacts not found. Run the Docker capture first:\n"
              f"  expected capture:    {args.capture}\n"
              f"  expected boundaries: {args.boundaries}\n"
              "See datasets/external_v1/README.md for the exact commands.", file=sys.stderr)
        return 2

    records = load_jsonl(args.capture)
    boundaries = json.load(open(args.boundaries, encoding="utf-8"))
    by_group = grouped_specs()

    os.makedirs(cand_dir, exist_ok=True)
    problems, skipped_offhost = [], 0
    per_group_rows: "OrderedDict[str, list]" = OrderedDict()

    for fl in boundaries["flows"]:
        flow, kind, group = fl["flow"], fl["kind"], fl["group"]
        window = records[fl["start"]:fl["end"]]
        rows = []

        if kind == "browser":
            counter = 0
            for rec in window:
                host = rec.get("host", "")
                if host not in spec_lib.LAB_HOSTS:
                    skipped_offhost += 1
                    continue
                counter += 1
                case_id = f"{group}-{counter:04d}"
                cand = base_candidate(rec, args.capture, flow)
                cand.update({
                    "case_id": case_id,
                    "expected_decision": "ALLOW",
                    "attack_category": None,
                    "benign_slice": group,
                    "primary_slice": group,
                    "client_profile": "chromium",
                    "body_type": infer_body_type(rec),
                    "payload_placement": "none",
                    "technique": "browser-captured",
                    "ground_truth_basis": ("Real Chromium request (page load, form submission "
                                           "or sub-resource) captured whole; a legitimate "
                                           "interaction the lab app serves. ALLOW by flow "
                                           "intent, before exposure."),
                    "label_confidence": "high",
                    "review_status": "auto-accepted",
                })
                verify_text(rec, problems, case_id)
                rows.append(cand)
            per_group_rows.setdefault(group, []).extend(rows)
            continue

        # enumerable flow: one-to-one with the group's specs, in order
        specs = by_group.get(group, [])
        if len(window) != len(specs):
            problems.append(
                f"flow {flow}: window {len(window)} != {len(specs)} specs; "
                "left UNLABELLED to avoid misalignment (re-run capture for this flow).")
            continue
        for (case_id, spec), rec in zip(specs, window):
            if spec.method != rec.get("method"):
                problems.append(f"{case_id}: method {spec.method} != captured "
                                f"{rec.get('method')}")
            cand = base_candidate(rec, args.capture, flow)
            cand.update({
                "case_id": case_id,
                "expected_decision": spec.expected_decision,
                "attack_category": spec.attack_category,
                "benign_slice": spec.benign_slice,
                "primary_slice": group,
                "client_profile": spec.client,
                "body_type": spec.body_type,
                "payload_placement": spec.payload_placement,
                "payload_decoded": spec.payload,
                "technique": spec.technique,
                "description": spec.description,
                "ground_truth_basis": spec.ground_truth_basis,
                "label_confidence": spec.label_confidence,
                "review_status": spec.review_status,
            })
            verify_text(rec, problems, case_id)
            rows.append(cand)
        per_group_rows.setdefault(group, []).extend(rows)

    # write per-group files + combined draft
    combined = []
    for group, rows in per_group_rows.items():
        with open(os.path.join(cand_dir, f"{group}.jsonl"), "w", encoding="utf-8") as f:
            for r in rows:
                f.write(json.dumps(r, ensure_ascii=False) + "\n")
        combined.extend(rows)
    with open(os.path.join(cand_dir, "cases_draft.jsonl"), "w", encoding="utf-8") as f:
        for r in combined:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    # realized counts
    by_slice = Counter(r.get("primary_slice") for r in combined)
    by_decision = Counter(r["expected_decision"] for r in combined)
    review = Counter(r["review_status"] for r in combined)
    realized = {
        "status": "DRAFT",
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "capture_file": os.path.basename(args.capture),
        "total_candidates": len(combined),
        "by_decision": dict(by_decision),
        "by_primary_cell": {k: by_slice[k] for k in sorted(by_slice)},
        "review_status": dict(review),
        "skipped_off_lab_host": skipped_offhost,
        "problems": problems,
        "note": ("DRAFT realized counts from capture. Targets: 40/cell final, ~48 draft. "
                 "NOT frozen; the Phase D independence gate and deterministic trim have NOT "
                 "run."),
    }
    with open(os.path.join(cand_dir, "realized_counts.json"), "w", encoding="utf-8") as f:
        json.dump(realized, f, indent=2, ensure_ascii=False)

    # report
    print(f"candidates assembled: {len(combined)}  ({dict(by_decision)})")
    for k in sorted(by_slice):
        print(f"  {k:24s} {by_slice[k]}")
    print(f"  review status: {dict(review)}")
    if skipped_offhost:
        print(f"  skipped {skipped_offhost} off-lab-host record(s)")
    if problems:
        print(f"\nPROBLEMS ({len(problems)}):")
        for p in problems[:40]:
            print(f"  - {p}")
    print(f"\nwrote -> {os.path.relpath(cand_dir, REPO_ROOT)}/"
          "{<cell>.jsonl, cases_draft.jsonl, realized_counts.json}")
    print("status: DRAFT (not frozen, gate not run, V4 not contacted)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
