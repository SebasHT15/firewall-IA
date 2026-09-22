"""External Test v1 — Phase C authoring library (DRAFT only, NO model in the path).

This module is the single source of truth for what the DRAFT drivers SEND. It does not
capture, does not label a frozen case, and never contacts /classify. Its three consumers
all import from here so they can never disagree:

    drive_traffic.py / drive_attacks.py   send the specs with REAL clients
    preview_specs.py                       render an authoring preview, count, pre-check
    label_candidates.py                    join a capture back to its spec after capture

WHAT A SPEC IS, AND WHAT IT IS NOT
    A `Spec` describes the request a real client is asked to MAKE: method, target, the
    handful of headers we deliberately set (a body's Content-Type, an unseen-structure
    header), and the body. It is authoring intent.

    The FROZEN candidate's `request_text` is NEVER taken from a Spec. It is the text the
    capture proxy renders from what the real client actually put on the wire — real
    User-Agent, real Accept, real framing. Capture then owns the bytes; nothing here is
    hand-edited into a case. `render_preview()` exists only so a human and the offline
    tests can read and count the authored intent; it is labelled a preview everywhere it
    is written out.

INDEPENDENCE
    App-specific authoring reduces reuse risk but does NOT establish independence
    (protocol section 4.4). The authoritative independence gate is Phase D (section 7) and
    is NOT run here. `precheck_independence()` is a courtesy screen so obvious collisions
    are caught during authoring instead of at the Phase D gate; it is explicitly not that
    gate.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field, asdict
from typing import Optional

# ── Lab-network facts (compose.yaml) ────────────────────────────────────────
SHOP_HOST = "shop.fwlab.test"          # storefront alias
API_HOST = "api.fwlab.test"            # API alias
LAB_PORT = 9100                        # lab-app listen port
LAB_HOSTS = {SHOP_HOST, API_HOST}

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

# The five pre-declared benign slices and five malicious categories (protocol 4.3/4.4).
BENIGN_SLICES = ["browser-navigation", "browser-forms-session",
                 "api-json", "api-query", "unseen-structure"]
ATTACK_CATEGORIES = ["sqli", "cmdi", "xss", "path-traversal", "ssrf"]

ATTACK_CATEGORY_LABEL = {
    "sqli": "SQL injection",
    "cmdi": "Command injection",
    "xss": "Cross-site scripting",
    "path-traversal": "Path traversal",
    "ssrf": "Server-side request forgery",
}


@dataclass
class Spec:
    """One authored request. See module docstring: intent, not frozen bytes."""
    group: str                     # slice name (ALLOW) or attack category key (BLOCK)
    expected_decision: str         # "ALLOW" | "BLOCK"
    client: str                    # "curl" | "httpx" | "chromium" | "mixed"
    method: str
    host: str                      # MUST be a lab alias — every request stays in-lab
    path: str                      # origin-form target, query included
    technique: str                 # sub-technique / structural axis label
    description: str               # human-readable intent
    ground_truth_basis: str        # why this label, assigned before exposure
    payload_placement: str = "none"   # query|form|json|path|header|cookie|none
    payload: str = ""              # the security-relevant / notable string (decoded)
    body: Optional[str] = None
    body_type: str = "none"        # none|form|json|multipart|text|xml|csv
    headers: list = field(default_factory=list)   # EXTRA headers we set explicitly
    label_confidence: str = "high"                 # high|medium|review
    review_status: str = "auto-accepted"           # auto-accepted|needs-review
    port: int = LAB_PORT

    # ── derived ──
    @property
    def attack_category(self) -> Optional[str]:
        return self.group if self.expected_decision == "BLOCK" else None

    @property
    def benign_slice(self) -> Optional[str]:
        return self.group if self.expected_decision == "ALLOW" else None

    @property
    def route_family(self) -> str:
        p = self.path.split("?", 1)[0]
        parts = [seg for seg in p.split("/") if seg]
        if not parts:
            return "/"
        if parts[0] == "api":
            return "api/" + (parts[1] if len(parts) > 1 else "")
        return parts[0]

    @property
    def host_type(self) -> str:
        return "api-alias" if self.host == API_HOST else "shop-alias"

    def signature(self) -> str:
        """The authored, distinguishing part of the request, for dedup and the independence
        pre-check. Includes the method, target, the headers we deliberately set (for the
        header/cookie placements and the unseen-header slice these ARE the distinguishing
        feature) and the body. Client DEFAULT headers are not here — they carry no payload
        and are identical across a client's requests."""
        base = f"{self.method} {self.path}"
        for name, value in self.headers:
            base += f"\n{name}: {value}"
        if self.body:
            base += "\n\n" + self.body
        return base

    def render_preview(self) -> str:
        """AUTHORING PREVIEW ONLY — not the frozen classifier representation.

        Mirrors data_plane.render_request()'s layout (LF, origin-form, blank line before a
        body) so wire.assert_canonical() can validate it, but it contains only the headers
        we set. The real client adds Host, User-Agent, Accept, etc.; capture records those.
        """
        lines = [f"{self.method} {self.path} HTTP/1.1",
                 f"Host: {self.host}:{self.port}"]
        for name, value in self.headers:
            lines.append(f"{name}: {value}")
        text = "\n".join(lines)
        if self.body is not None:
            text += "\n\n" + self.body
        return text

    def to_record(self, case_id: str) -> dict:
        d = {
            "case_id": case_id,
            "expected_decision": self.expected_decision,
            "attack_category": self.attack_category,
            "benign_slice": self.benign_slice,
            "client_profile": self.client,
            "host": self.host,
            "host_type": self.host_type,
            "port": self.port,
            "method": self.method,
            "route": self.path.split("?", 1)[0],
            "route_family": self.route_family,
            "path": self.path,
            "body_type": self.body_type,
            "payload_placement": self.payload_placement,
            "payload_decoded": self.payload,
            "technique": self.technique,
            "description": self.description,
            "ground_truth_basis": self.ground_truth_basis,
            "label_confidence": self.label_confidence,
            "review_status": self.review_status,
            "extra_headers": self.headers,
            "preview_text": self.render_preview(),
            "preview_note": ("AUTHORING PREVIEW — the frozen request_text is the CAPTURED "
                             "text from the real client through the capture proxy, never "
                             "this string; capture fills request_text/request_sha256."),
            "request_text": None,
            "request_sha256": None,
            "capture_status": "pending-capture",
        }
        return d


def assign_case_ids(specs: list[Spec]) -> list[tuple[str, Spec]]:
    """Deterministic, stable case ids: <group>-NNNN in authored order."""
    out, counters = [], {}
    for s in specs:
        n = counters.get(s.group, 0) + 1
        counters[s.group] = n
        out.append((f"{s.group}-{n:04d}", s))
    return out


# ── Independence PRE-CHECK (courtesy only; the Phase D gate is authoritative) ─
def _canonical_key(payload: str) -> str:
    """Reuse the project's canonical_key so the pre-check speaks the gate's language.

    Falls back to a minimal local normaliser if the dataset module cannot be imported
    (e.g. its heavy deps are absent), so the pre-check still runs offline. The fallback is
    only a convenience; Phase D uses parse_dataset_v4.canonical_key() authoritatively.
    """
    try:
        import sys
        ds = os.path.join(REPO_ROOT, "scripts", "dataset")
        if ds not in sys.path:
            sys.path.insert(0, ds)
        from parse_dataset_v4 import canonical_key  # type: ignore
        return canonical_key(payload)
    except Exception:
        import re
        from urllib.parse import unquote_plus
        s = payload
        for _ in range(3):
            nxt = unquote_plus(s)
            if nxt == s:
                break
            s = nxt
        s = re.sub(r"/\*.*?\*/", "", s)
        s = re.sub(r"\s+", " ", s).replace("${IFS}", " ").strip().lower()
        return s


def load_forbidden_canonical() -> dict:
    """Canonical-key corpora of the sources External v1 must not reuse.

    Returns {source_name: set_of_canonical_texts}. Read-only; used only to SCREEN authored
    specs. Nothing here is copied into a case.
    """
    corpora: dict[str, set] = {}

    # 4. real-http-fp-v1 diagnostic texts
    diag = os.path.join(REPO_ROOT, "reports", "diagnostics", "real-http-fp-v1", "cases.jsonl")
    diag_keys = set()
    if os.path.exists(diag):
        with open(diag, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    rec = json.loads(line)
                    if rec.get("text"):
                        diag_keys.add(_canonical_key(rec["text"]))
    corpora["real-http-fp-v1"] = diag_keys

    # 5. smoke fixtures (the two URLs baked into the smoke client)
    corpora["smoke-fixtures"] = {
        _canonical_key("/index.html"),
        _canonical_key("/products.html?id=1' OR '1'='1"),
        _canonical_key("1' OR '1'='1"),
    }
    return corpora


def load_v4_canonical_texts(limit: Optional[int] = None) -> list[str]:
    """Canonical form of every V4 fine-tuning row's `input`. Big; loaded lazily by the
    substring screen. Read-only, never copied into a case."""
    out = []
    for fn in ("train.jsonl", "eval.jsonl"):
        p = os.path.join(REPO_ROOT, "datasets", "v4_clean", fn)
        if not os.path.exists(p):
            continue
        with open(p, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                rec = json.loads(line)
                out.append(_canonical_key(rec.get("input", "")))
                if limit and len(out) >= limit:
                    return out
    return out


def precheck_independence(specs: list[Spec], check_v4: bool = True) -> dict:
    """Courtesy screen — NOT the Phase D independence gate (protocol section 7).

    Flags, per spec: internal canonical duplicates, and canonical collisions with the
    diagnostic set, the smoke fixtures, and (optionally) the V4 corpus. Returns a report;
    an empty `collisions` list means the authored pool is clean going into Phase D, which
    is where the authoritative, blocking gate runs.
    """
    forbidden = load_forbidden_canonical()
    v4 = load_v4_canonical_texts() if check_v4 else []

    seen: dict[str, str] = {}
    collisions = []
    for case_id, spec in assign_case_ids(specs):
        sig_key = _canonical_key(spec.signature())
        pay_key = _canonical_key(spec.payload) if spec.payload else ""

        if sig_key in seen:
            collisions.append({"case_id": case_id, "kind": "internal-duplicate",
                               "against": seen[sig_key]})
        else:
            seen[sig_key] = case_id

        for src, keys in forbidden.items():
            if sig_key in keys or (pay_key and pay_key in keys):
                collisions.append({"case_id": case_id, "kind": f"{src}-collision"})

        if v4 and pay_key and len(pay_key) >= 8:
            for row in v4:
                if pay_key in row:
                    collisions.append({"case_id": case_id, "kind": "v4-canonical-substring",
                                       "payload": spec.payload})
                    break

    return {
        "n_specs": len(specs),
        "v4_rows_screened": len(v4),
        "collisions": collisions,
        "clean": not collisions,
        "note": ("Courtesy authoring screen only. The authoritative, blocking independence "
                 "gate (exact + canonical + duplicate + diagnostic + smoke reuse + "
                 "near-duplicate + CSIC) is Phase D, protocol section 7, and was NOT run."),
    }


def spec_to_dict(spec: Spec) -> dict:
    return asdict(spec)
