"""External Test v1 — pre-freeze SUPPLEMENTAL capture for browser-forms-session only.

WHY THIS EXISTS (recorded in the boundaries file as provenance):
    Phase D found browser-forms-session had 37 < 40 eligible cases after the internal-duplicate
    gate, because the original flow re-navigated to bare /search and /cart and produced
    byte-identical GET requests. This is a pre-exposure methodological correction, NOT
    post-result tuning: it runs before V4 exposure, before freeze, with no knowledge of any V4
    prediction. It adds genuinely distinct benign form/session interactions and nothing else.

Same already-validated pre-exposure path as Phase C: Playwright/Chromium -> capture-proxy ->
lab-app. No control plane, no firewall data plane, no /classify, no model.

It writes to a SEPARATE capture file so the Phase C DRAFT and Phase D evidence are preserved
untouched. Correlation stays offset-based (no marker in any request under test).

Run (single command; lab-app + capture-proxy must already be up):
    python3 run_forms_supplement.py --proxy http://capture-proxy:8081 \
        --shop http://shop.fwlab.test:9100 \
        --capture-file /logs/capture/extv1-browser-forms-supplement.jsonl \
        --boundaries /logs/capture/boundaries_supplement.json
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import drive_traffic     # noqa: E402
from run_capture import check_proxy, count_lines, wait_for_stable  # noqa: E402

RUN_TAG = "pre-freeze-supplement-browser-forms-session"
REASON = ("Phase D found browser-forms-session eligible=37 < 40 after the internal-duplicate "
          "gate (byte-identical repeated GET /search and GET /cart). Pre-freeze, pre-exposure "
          "supplemental capture of genuinely distinct benign form/session interactions.")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--proxy", default="http://capture-proxy:8081")
    ap.add_argument("--shop", default="http://shop.fwlab.test:9100")
    ap.add_argument("--capture-file",
                    default="/logs/capture/extv1-browser-forms-supplement.jsonl")
    ap.add_argument("--boundaries", default="/logs/capture/boundaries_supplement.json")
    ap.add_argument("--settle", type=float, default=2.0)
    args = ap.parse_args(argv)

    check_proxy(args.proxy)

    start = wait_for_stable(args.capture_file, 0.2)
    drive_traffic.browser_forms_supplement(args.shop, args.proxy)
    end = wait_for_stable(args.capture_file, args.settle)

    boundaries = {
        "schema": "external-v1-capture-boundaries/1",
        "kind": "supplement",
        "run_tag": RUN_TAG,
        "reason": REASON,
        "pre_exposure": True, "before_freeze": True,
        "control_plane_started": False, "firewall_data_plane_started": False,
        "classify_contacted": False, "v4_inference": "none",
        "capture_file": args.capture_file,
        "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "flows": [{"flow": "browser-forms-session", "kind": "browser",
                   "group": "browser-forms-session", "run_tag": RUN_TAG,
                   "start": start, "end": end, "count": end - start, "expected": None,
                   "count_matches_expected": True}],
    }
    os.makedirs(os.path.dirname(args.boundaries) or ".", exist_ok=True)
    with open(args.boundaries, "w", encoding="utf-8") as f:
        json.dump(boundaries, f, indent=2, ensure_ascii=False)

    print(f"\nsupplemental capture done: {end - start} record(s) this run "
          f"(includes navigation GETs used to reach forms; the supplement gate keeps only "
          f"genuinely new distinct requests)")
    print(f"capture   -> {args.capture_file}")
    print(f"boundaries-> {args.boundaries}")
    print("status: DRAFT | pre-exposure | /classify never | V4 inference none")
    return 0


if __name__ == "__main__":
    sys.exit(main())
