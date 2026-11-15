#!/usr/bin/env python3
"""Preregister v3 after the owner-approved D76 C-S7 amendment."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
V2 = HERE.parent / "final-run-2026-10-25-v2"


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def save(path: Path, value: dict) -> str:
    path.write_text(json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
                    encoding="utf-8")
    return sha(path)


def main() -> None:
    # Copy fixed generator and split inputs byte-for-byte: D76 changes only the
    # interpretation of a later quality gate, not the sampling procedure.
    for name in ("generator-config.json", "split-config.json"):
        (HERE / name).write_bytes((V2 / name).read_bytes())
    prereg = load(V2 / "preregistration.json")
    prereg["version"] = "v5-dataset-v3"
    prereg["owner_decisions"].append("D76")
    prereg["correction"] = {
        "reason": "D76 amendment after C-S7 rejected v2; no model output viewed",
        "rejected_v2_manifest_sha256": sha(V2.parents[3] / "datasets/v5_sources/final_source_2026-10-25-v2/manifest.json"),
        "rejected_v2_cs7_sha256": sha(V2 / "cs7-counts.json"),
        "owner_ruling": "D76",
    }
    prereg["ratified"]["acceptance_thresholds"]["C-S7"] = {
        "warn_element_share_gt": "0.01", "block_element_share_gt": "0.03",
        "TRAIN": "BLOCK_ABOVE_0.03",
        "VALIDATION": "WARN_ONLY_REPORT_EXCESS",
        "INTERNAL_TEST": "WARN_ONLY_REPORT_EXCESS",
        "owner_ruling": "D76",
    }
    prereg["limitations"].append("D76: C-S7 concentration in protected small splits is reported as WARN only.")
    prereg_sha = save(HERE / "preregistration.json", prereg)
    auth = load(V2 / "build-authorization.json")
    auth["preregistration_sha256"] = prereg_sha
    auth["owner_decision"] = "D74+D75+D76; new v3 build after rejected v2 C-S7"
    auth_sha = save(HERE / "build-authorization.json", auth)
    print(json.dumps({"preregistration_sha256": prereg_sha,
                      "build_authorization_sha256": auth_sha}, sort_keys=True))


if __name__ == "__main__":
    main()
