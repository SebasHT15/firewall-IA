"""External Test v1 — assemble the pre-freeze browser-forms-session SUPPLEMENT (host-side).

Reads the supplemental capture + boundaries produced by run_forms_supplement.py and writes a
clearly-identified supplemental candidate artifact. It does NOT touch the Phase C DRAFT or the
Phase D evidence. Every candidate carries the run tag so it is never confused with the original
capture; request_text is copied VERBATIM from the capture and SHA-256 re-verified.

Ground truth is ALLOW (benign browser form/session interactions), assigned before any V4
exposure. Off-lab-host requests are skipped (as in the main assembler).

Run:
    python3 scripts/external/label_supplement.py \
      --capture docker/.lab-logs/capture/extv1-browser-forms-supplement.jsonl \
      --boundaries docker/.lab-logs/capture/boundaries_supplement.json
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import spec_lib          # noqa: E402
import label_candidates as L   # noqa: E402  reuse base_candidate + verify_text

REPO_ROOT = spec_lib.REPO_ROOT
OUT_DIR = os.path.join(REPO_ROOT, "datasets", "external_v1", "candidates_supplement")
RUN_TAG = "pre-freeze-supplement-browser-forms-session"


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--capture", default=os.path.join(
        REPO_ROOT, "docker", ".lab-logs", "capture", "extv1-browser-forms-supplement.jsonl"))
    ap.add_argument("--boundaries", default=os.path.join(
        REPO_ROOT, "docker", ".lab-logs", "capture", "boundaries_supplement.json"))
    ap.add_argument("--out", default=OUT_DIR)
    args = ap.parse_args(argv)

    if not os.path.exists(args.capture) or not os.path.exists(args.boundaries):
        print("Supplemental capture not found. Run the ONE capture command first:\n"
              f"  expected capture:    {args.capture}\n"
              f"  expected boundaries: {args.boundaries}", file=sys.stderr)
        return 2

    records = L.load_jsonl(args.capture)
    boundaries = json.load(open(args.boundaries, encoding="utf-8"))
    run_tag = boundaries.get("run_tag", RUN_TAG)

    os.makedirs(args.out, exist_ok=True)
    problems, skipped = [], 0
    rows = []
    counter = 0
    for fl in boundaries["flows"]:
        for rec in records[fl["start"]:fl["end"]]:
            host = rec.get("host", "")
            if host not in spec_lib.LAB_HOSTS:
                skipped += 1
                continue
            counter += 1
            case_id = f"browser-forms-session-supp-{counter:04d}"
            cand = L.base_candidate(rec, args.capture, "browser-forms-session")
            cand["capture"]["run_tag"] = run_tag
            cand.update({
                "case_id": case_id,
                "expected_decision": "ALLOW",
                "attack_category": None,
                "benign_slice": "browser-forms-session",
                "primary_slice": "browser-forms-session",
                "client_profile": "chromium",
                "body_type": L.infer_body_type(rec),
                "payload_placement": "none",
                "technique": "browser-captured-supplement",
                "session_context": _session_context(rec),
                "run_tag": run_tag,
                "supplement": True,
                "ground_truth_basis": ("Real Chromium benign form/session interaction captured "
                                       "in the pre-freeze supplemental run; ALLOW by flow "
                                       "intent, before V4 exposure. Distinctness enforced by "
                                       "the supplement gate (internal-dup vs the existing DRAFT)."),
                "label_confidence": "high",
                "review_status": "auto-accepted",
            })
            L.verify_text(rec, problems, case_id)
            rows.append(cand)

    with open(os.path.join(args.out, "browser-forms-session-supplement.jsonl"), "w",
              encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
    meta = {"status": "DRAFT", "run_tag": run_tag, "generated_utc": _now(),
            "pre_exposure": True, "before_freeze": True, "classify_contacted": False,
            "v4_inference": "none", "capture_file": os.path.basename(args.capture),
            "total_captured": len(rows), "skipped_off_lab_host": skipped,
            "problems": problems,
            "note": "Supplemental candidates (browser-forms-session only). The original DRAFT "
                    "and Phase D evidence are untouched. Eligibility is decided by the "
                    "supplement gate; captured rows here are NOT yet deduped."}
    with open(os.path.join(args.out, "supplement_meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)

    print(f"supplement captured rows: {len(rows)} (run_tag={run_tag})")
    if skipped:
        print(f"  skipped {skipped} off-lab-host record(s)")
    if problems:
        print(f"  PROBLEMS: {problems}")
    print(f"wrote -> {os.path.relpath(args.out, REPO_ROOT)}/"
          "{browser-forms-session-supplement.jsonl, supplement_meta.json}")
    print("Next: run the supplement gate:")
    print("  python3 scripts/external/phase_d_gate.py --supplement")
    return 1 if problems else 0


def _session_context(rec) -> str:
    text = rec.get("request_text", "").lower()
    has_session = "fwlab_session" in text
    if rec.get("method") == "POST" and rec.get("path") == "/login":
        return "login-submit"
    return "authenticated" if has_session else "guest"


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


if __name__ == "__main__":
    sys.exit(main())
