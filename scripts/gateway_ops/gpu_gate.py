"""
The shared GPU belongs to whoever `GPU_STATUS.json` says. Read before any model is loaded; a script
that would load one refuses to start without the hand-off. Standard library only.
"""
import json

STATUS_FILE = ("/home/sebas/Documents/Codex/2026-10-26/ta/outputs/Coordinacion_modelos_arquitectura/"
               "GPU_STATUS.json")
HANDED_OVER = ("AVAILABLE_FOR_CLAUDE", "IN_USE_BY_CLAUDE")


def read_status(path=STATUS_FILE):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def refusal(path=STATUS_FILE):
    """Why a model must not be loaded now, or None when the GPU was handed over."""
    try:
        status = read_status(path)
    except (OSError, ValueError) as exc:
        return f"GPU status unreadable ({type(exc).__name__})"
    state = status.get("state") if isinstance(status, dict) else None
    if state not in HANDED_OVER:
        return f"GPU state is {state!r}: wait for an explicit hand-off"
    return None
