"""External Test v1 — CAPTURE-ONLY mitmproxy addon.

Records every request that passes through it, in the exact classifier representation the
firewall data plane would send to /classify, and FORWARDS EVERYTHING. It never classifies,
never blocks and never contacts the control plane.

WHY THIS EXISTS
    External v1 ground truth must be assigned before V4 sees anything (D37). So the DRAFT
    capture runs real clients against the lab application with the FIREWALL data plane and
    the control plane absent from the path. This passive proxy sits there instead.

WHY A PROXY AND NOT THE APPLICATION
    Capturing at the destination would record what a WSGI server parsed, not the text V4
    is given. Capturing here, through the same mitmproxy version, with the SAME renderer,
    means the frozen text is exactly what the firewall would later hand to the model.

RENDERER IDENTITY — the point of the whole file
    `render_request` is IMPORTED from the production data plane, never copied. There is
    one implementation of the D1 representation, and a test asserts object identity, the
    same way test_model asserts it shares inference_core's parser. A copy here could drift
    and would silently invalidate every frozen case.

    Importing data_plane also constructs its FirewallGateway addon as a module-level side
    effect. That object is never registered: mitmproxy only loads the `addons` list of the
    script passed with -s, which below contains the capture addon alone. Nothing in this
    process enforces anything.

RUN (inside the data-plane image, which already has mitmproxy):
    mitmdump -s /opt/external/capture_addon.py --listen-host 0.0.0.0 -p 8081

    CAPTURE_OUT   JSONL output path (default /logs/capture/capture.jsonl)
    CAPTURE_TAG   free-text label recorded on every record (e.g. the flow name)
"""

import datetime
import hashlib
import json
import os
import sys
import threading

# /app/data_plane is where the data-plane image puts the production addon.
for _candidate in ("/app/data_plane",
                   os.path.join(os.path.dirname(os.path.dirname(
                       os.path.dirname(os.path.abspath(__file__)))), "data_plane")):
    if os.path.isdir(_candidate) and _candidate not in sys.path:
        sys.path.insert(0, _candidate)

import data_plane  # noqa: E402  — production module, imported for its renderer

render_request = data_plane.render_request     # THE one implementation (D1)

OUT_PATH = os.environ.get("CAPTURE_OUT", "/logs/capture/capture.jsonl")
TAG = os.environ.get("CAPTURE_TAG", "")


class CaptureAddon:
    """Append one JSONL record per request, then let it through untouched."""

    def __init__(self, out_path: str = OUT_PATH, tag: str = TAG) -> None:
        self.out_path = out_path
        self.tag = tag
        self.seq = 0
        self.lock = threading.Lock()
        os.makedirs(os.path.dirname(self.out_path) or ".", exist_ok=True)

    def running(self) -> None:
        print(f"capture proxy ready: out={self.out_path} tag={self.tag!r} "
              f"policy=CAPTURE-ONLY (no classification, no enforcement)", flush=True)

    def request(self, flow) -> None:
        # No try/except that swallows: a capture failure must be loud. Unlike the
        # firewall addon there is nothing to fail closed about here — this proxy makes
        # no security decision, and a request it forwards is not a request V4 allowed.
        text = render_request(flow.request)
        with self.lock:
            self.seq += 1
            seq = self.seq
        record = {
            "seq": seq,
            "tag": self.tag,
            "captured_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "flow_id": flow.id,
            "method": flow.request.method,
            "host": flow.request.pretty_host,
            "port": flow.request.port,
            "path": flow.request.path,
            "http_version": flow.request.http_version,
            "request_text": text,
            "request_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            "request_bytes": len(text.encode("utf-8")),
            "body_bytes": len(flow.request.raw_content or b""),
        }
        line = json.dumps(record, ensure_ascii=False)
        with self.lock:
            with open(self.out_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
                f.flush()


addons = [CaptureAddon()]
