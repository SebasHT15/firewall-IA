"""
firewall-IA — WIRE-EVIDENCE LAB ADDON (issue #68, §8). A dedicated mitmproxy addon script used ONLY
by scripts/wire_evidence/harness.py.

It constructs the REAL `data_plane.FirewallGateway` (so the real request hook, the real fail-closed
logic and the real canonical observer run), but points the classifier at the local lab stub and the
observer at the local lab worker, taken from environment variables set by the harness. This lets the
lab exercise the production gateway + observer code WITHOUT editing the shared data_plane/data_plane.py
or config.yaml: both files are imported, never modified.

Everything here is OBSERVE-ONLY and loopback-only, exactly like the committed gateway: V4 (the stub)
is the only decision, the canonical observer only logs a "CANONICAL OBS" line, and the Fast Path stays
ineligible. No production pin, receive limit or zstd window is changed.
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_PLANE_DIR = os.path.join(os.path.dirname(os.path.dirname(HERE)), "data_plane")
for p in (DATA_PLANE_DIR,):
    if p not in sys.path:
        sys.path.insert(0, p)

import logging  # noqa: E402

import data_plane as dp  # noqa: E402  (imported, never modified)

_eff_log = logging.getLogger("firewall.wire_lab.effective_options")


class EffectiveOptions:
    """Logs the EFFECTIVE mitmproxy options read from the running instance, so the runner records
    requested-vs-effective accurately instead of guessing. Observe-only; no traffic effect."""

    _KEYS = ("mode", "validate_inbound_headers", "http2", "connection_strategy",
             "stream_large_bodies", "body_size_limit")

    def running(self):
        from mitmproxy import ctx
        for k in self._KEYS:
            try:
                val = getattr(ctx.options, k)
            except Exception as exc:  # noqa: BLE001
                val = f"<unreadable:{type(exc).__name__}>"
            _eff_log.info("LAB EFFECTIVE OPTION %s=%r", k, val)


def _build():
    classifier_url = os.environ["WIRE_LAB_CLASSIFIER_URL"]
    timeout = float(os.environ.get("WIRE_LAB_TIMEOUT", "3.0"))
    observer = None
    if os.environ.get("WIRE_LAB_OBSERVER") == "1":
        cfg = dp.CanonicalObserverConfig(
            python=os.environ["WIRE_LAB_OBSERVER_PY"],
            timeout_seconds=float(os.environ.get("WIRE_LAB_OBS_TIMEOUT", "0.5")),
            startup_timeout_seconds=float(os.environ.get("WIRE_LAB_OBS_STARTUP", "10")),
            restart_backoff_seconds=1.0,
            max_consecutive_failures=3,
            max_decoded_body=int(os.environ.get("WIRE_LAB_MAX_DECODED_BODY", str(1 << 20))),
        )
        observer = dp.build_canonical_observer(cfg)
    # Track B (v2): when WIRE_LAB_FRAMING=1, construct the REAL gateway with the shadow FRAMING
    # observer ON. mitmproxy then drives the gateway's own configure() hook (sampling the EFFECTIVE
    # profile and establishing the relevant-profile generation baseline) and a FRAMING OBS line is
    # logged beside each CANONICAL OBS line. If framing is on but there is NO canonical observer, the
    # gateway logs FRAMING OBS UNAVAILABLE (NO_CANONICAL_OBSERVER) and starts no worker — by design.
    framing = os.environ.get("WIRE_LAB_FRAMING") == "1"
    return dp.FirewallGateway(classifier_url, timeout, canonical_observer=observer,
                              framing_observer=framing)


addons = [EffectiveOptions(), _build()]
