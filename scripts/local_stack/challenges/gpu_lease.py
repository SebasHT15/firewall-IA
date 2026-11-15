"""Temporary owner-authorized GPU hand-off for real V5.1 lab measurements."""
from contextlib import contextmanager
import json
from pathlib import Path
import secrets
import time

from scripts.model2.real_guard_probe import STATUS, gpu_busy


@contextmanager
def temporary_handoff(enabled, evidence_dir):
    if not enabled:
        yield
        return
    evidence_dir = Path(evidence_dir)
    before = json.loads(STATUS.read_text())
    if (before.get("state") != "AVAILABLE" or before.get("owner") not in (None, "none")
            or gpu_busy()):
        raise RuntimeError("GPU is unavailable for the owner-authorized V5.1 lab run")
    token = secrets.token_hex(12)
    evidence_dir.mkdir(parents=True, exist_ok=True)
    (evidence_dir / "GPU_STATUS.before.json").write_text(json.dumps(before, indent=2) + "\n")
    STATUS.write_text(json.dumps({"owner": None, "state": "AVAILABLE_FOR_CLAUDE",
                                  "handoff_id": token, "UTC": time.time(),
                                  "note": "Owner-authorized temporary V5.1 lab measurement"}, indent=2) + "\n")
    try:
        yield
    finally:
        current = json.loads(STATUS.read_text())
        if current.get("handoff_id") == token:
            STATUS.write_text(json.dumps({"owner": None, "state": "AVAILABLE", "UTC": time.time(),
                                          "note": "Temporary V5.1 lab measurement ended; GPU released"},
                                         indent=2) + "\n")
        (evidence_dir / "GPU_STATUS.after.json").write_text(STATUS.read_text())
