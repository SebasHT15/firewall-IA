#!/usr/bin/env python3
"""V5 stage 4 — the shared client encoder and rendering through `canonicalize()` (issue #74).

Spec V5-DATA-SPEC-r3 (FROZEN, D62): §4.1 (one client encoder for both classes), §5 (the model text is
exactly what `canonical_request.canonicalize` returns: imported, never re-implemented, I1), §6
(ENC-1 encode plain payloads exactly once, insert pre-encoded payloads verbatim; ENC-2 one encoder
set: `%20` / `+`, reserved characters literal or encoded where legal, uppercase hex, JSON compact or
spaced; ENC-3 held-out forms only when native; ENC-6 uppercase hex for pre-encoded payloads when the
decode check confirms an identical value).

A rendered row keeps the character span of every leaf in the canonical text, so pair integrity can
be verified on the text itself (exactly one contiguous difference, inside the attacked leaf).

Held-out-form detection reuses the stage-2 detector (`build_v5_attack_pool.native_forms`), so the
ENC-3 gate and the stage-2 `native_forms` field are one definition.

Nothing here labels, draws values or assigns splits.
"""
from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass, field
from urllib.parse import unquote, unquote_plus

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))
for p in (HERE, os.path.join(REPO_ROOT, "data_plane")):
    if p not in sys.path:
        sys.path.insert(0, p)

import canonical_request as cr  # noqa: E402  (stage 1: the ONE canonicalize, I1)
from build_v5_attack_pool import PCT_RE, hex_case_profile, native_forms  # noqa: E402  (stage 2 detectors)

canonicalize = cr.canonicalize          # re-exported object: a test asserts identity with cr.canonicalize (I1)
parse_canonical = cr.parse_canonical

PLAIN, PRE_ENCODED = "plain", "pre_encoded"
# Signals the generator may produce: diagnostic encoding signals carried natively by a source payload
# (P11, D63). Every other signal means a row outside the §2.2 training distribution: a generator bug.
ALLOWED_SIGNALS = frozenset({"S-ENC-MULTI", "S-ENC-U", "S-ENC-NUL", "S-UTF8-OVERLONG"})
HELD_OUT_FORMS = ("double_encoding", "unicode_escape", "html_entity", "ifs", "mixed_case_hex")

_UNRESERVED = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
# Characters that may stay literal in a value of each context when the profile keeps reserved
# characters literal (RFC 3986 §3.3 pchar / §3.4 query, minus what is structural in the carrier:
# `&` `=` `+` `#` in query/form values, `/` `?` `#` in a path segment).
_LITERAL_OK = {
    "query": frozenset("!$'()*,;:@/?"),
    "form": frozenset("!$'()*,;:@/?"),
    "segment": frozenset("!$&'()*+,;=:@"),
    "tail": frozenset("!$&'()*+,;=:@"),
}
# Characters a PRE-ENCODED payload may carry verbatim in each context (its native bytes): anything
# else would change the request structure or be rejected (R5), so such a payload is not placeable.
_VERBATIM_OK = {
    "query": _UNRESERVED | frozenset("!$'()*+,;=:@/?%"),
    "form": _UNRESERVED | frozenset("!$'()*+,;=:@/?%"),
    "segment": _UNRESERVED | frozenset("!$&'()*+,;=:@%"),
    "tail": _UNRESERVED | frozenset("!$&'()*+,;=:@/%"),
}
_PCT_ANY = re.compile(r"%(?![0-9A-Fa-f]{2})")


class RenderError(ValueError):
    """A leaf cannot be rendered in its context (never silently repaired)."""


class GeneratorBug(AssertionError):
    """A rendered row violates the canonical contract the generator must satisfy (A-G2, I3, §2.2)."""


# ───────────────────────────── encoder profile (ENC-2) ─────────────────────────────
@dataclass(frozen=True)
class EncoderProfile:
    space: str = "%20"            # query / form values: "%20" or "+"; paths always "%20"
    reserved: str = "literal"     # "literal" | "encoded": legal reserved characters in values
    json_style: str = "compact"   # "compact" | "spaced"
    charset: bool = False         # Content-Type carries "; charset=utf-8"

    def __post_init__(self):
        if self.space not in ("%20", "+") or self.reserved not in ("literal", "encoded") \
                or self.json_style not in ("compact", "spaced") or not isinstance(self.charset, bool):
            raise ValueError(f"invalid encoder profile {self!r}")

    @property
    def profile_id(self) -> str:
        return (f"sp{'20' if self.space == '%20' else 'plus'}.{self.reserved[:3]}."
                f"{self.json_style}.{'cs' if self.charset else 'nocs'}")


PROFILES = tuple(EncoderProfile(s, r, j, c) for s in ("%20", "+") for r in ("literal", "encoded")
                 for j in ("compact", "spaced") for c in (False, True))


def _pct(b: int) -> str:
    return f"%{b:02X}"                          # uppercase hex (ENC-2)


def encode_plain(text: str, ctx: str, profile: EncoderProfile) -> str:
    """Encode a plain value exactly once for a URL context (query | form | segment | tail)."""
    if ctx not in _LITERAL_OK:
        raise RenderError(f"unknown URL context {ctx!r}")
    literal = _LITERAL_OK[ctx] if profile.reserved == "literal" else frozenset()
    out = []
    for ch in text:
        if ch in _UNRESERVED or ch in literal or (ctx == "tail" and ch == "/"):
            out.append(ch)
        elif ch == " ":
            out.append(profile.space if ctx in ("query", "form") else "%20")
        else:
            out.extend(_pct(b) for b in ch.encode("utf-8"))
    enc = "".join(out)
    decode = unquote_plus if ctx in ("query", "form") else unquote
    if decode(enc, errors="strict") != text:     # ENC-1: one decode returns the logical value
        raise GeneratorBug(f"ENC-1: decode(encode({text[:40]!r})) differs")
    return enc


def normalize_hex(wire: str) -> tuple:
    """ENC-6: uppercase every %xx triplet, only when one decode gives the identical value."""
    norm = PCT_RE.sub(lambda m: m.group(0).upper(), wire)
    if norm == wire:
        return wire, False
    try:
        same = unquote(norm, errors="strict") == unquote(wire, errors="strict")
    except UnicodeDecodeError:
        same = unquote(norm, encoding="latin-1") == unquote(wire, encoding="latin-1")
    return (norm, True) if same else (wire, False)


def verbatim_ok(wire: str, ctx: str) -> bool:
    """A pre-encoded payload is placeable verbatim in a URL context only if every character is legal
    there and every `%` starts a valid triplet (otherwise its bytes would change the structure)."""
    return all(ch in _VERBATIM_OK[ctx] for ch in wire) and not _PCT_ANY.search(wire)


# ───────────────────────────── leaves ─────────────────────────────
@dataclass(frozen=True)
class Part:
    """A piece of a string leaf: benign text (always plain) or the payload (plain / pre-encoded)."""
    text: str
    form: str = PLAIN             # plain | pre_encoded
    payload: bool = False

    def __post_init__(self):
        if self.form not in (PLAIN, PRE_ENCODED) or not isinstance(self.text, str):
            raise ValueError("invalid leaf part")


@dataclass(frozen=True)
class Leaf:
    """A slot value. Strings are a tuple of Parts (prefix / suffix / embedded twins keep the benign
    text as plain parts around the payload). Scalars are typed (int, float, bool)."""
    kind: str                     # "string" | "int" | "number" | "bool"
    parts: tuple = ()
    scalar: object = None

    @staticmethod
    def string(*parts: Part) -> "Leaf":
        return Leaf("string", tuple(parts))

    @property
    def logical(self) -> str:
        """The value an application would see after one transport decode of each part."""
        if self.kind != "string":
            return scalar_text(self)
        return "".join(unquote(p.text) if p.form == PRE_ENCODED else p.text for p in self.parts)

    @property
    def raw(self) -> str:
        """The leaf as inserted: plain text plus verbatim pre-encoded wire."""
        if self.kind != "string":
            return scalar_text(self)
        return "".join(p.text for p in self.parts)

    @property
    def has_payload(self) -> bool:
        return any(p.payload for p in self.parts)


def scalar_text(leaf: Leaf) -> str:
    if leaf.kind == "bool":
        return "true" if leaf.scalar else "false"
    if leaf.kind == "int":
        return str(int(leaf.scalar))
    if leaf.kind == "number":
        return json.dumps(float(leaf.scalar))
    raise RenderError(f"not a scalar leaf: {leaf.kind}")


def encode_leaf_url(leaf: Leaf, ctx: str, profile: EncoderProfile) -> str:
    if leaf.kind != "string":
        return scalar_text(leaf)                  # digits, '.', 'true' / 'false': nothing to encode
    out = []
    for p in leaf.parts:
        if p.form == PLAIN:
            out.append(encode_plain(p.text, ctx, profile))
        else:
            wire, _ = normalize_hex(p.text)
            if not verbatim_ok(wire, ctx):
                raise RenderError(f"pre-encoded payload not placeable verbatim in {ctx}")
            out.append(wire)                       # ENC-1: inserted verbatim, never re-encoded
    return "".join(out)


def leaf_json_value(leaf: Leaf):
    if leaf.kind == "string":
        return "".join(normalize_hex(p.text)[0] if p.form == PRE_ENCODED else p.text for p in leaf.parts)
    if leaf.kind == "int":
        return int(leaf.scalar)
    if leaf.kind == "number":
        return float(leaf.scalar)
    if leaf.kind == "bool":
        return bool(leaf.scalar)
    raise RenderError(f"unknown leaf kind {leaf.kind}")


def leaf_text_value(leaf: Leaf) -> str:
    if leaf.kind != "string":
        raise RenderError("a text/plain body holds a string leaf")
    return "".join(normalize_hex(p.text)[0] if p.form == PRE_ENCODED else p.text for p in leaf.parts)


def _json_scalar(v) -> str:
    return json.dumps(v, ensure_ascii=False)       # never \uXXXX for non-ASCII (ENC-3)


# ───────────────────────────── rendering ─────────────────────────────
@dataclass(frozen=True)
class Rendered:
    method: str
    target: str
    content_type: str | None
    body: str
    spans: dict                   # slot_id -> ("target" | "body", start, end) in target / body
    parts: cr.RequestParts = field(compare=False, default=None)

    def text_spans(self, text: str) -> dict:
        """Leaf spans in the canonical text (asserted against the text)."""
        head = f"{self.method} "
        body_off = None
        if self.body:
            body_off = text.index("\n\n") + 2 if self.content_type is None else \
                len(f"{self.method} {self.target} HTTP/1.1\nContent-Type: {self.content_type}\n\n")
        out = {}
        for sid, (where, a, b) in self.spans.items():
            off = len(head) if where == "target" else body_off
            src = self.target if where == "target" else self.body
            if text[off + a:off + b] != src[a:b]:
                raise GeneratorBug(f"span of {sid} does not match the canonical text")
            out[sid] = (off + a, off + b)
        return out


def content_type(template, profile: EncoderProfile) -> str | None:
    if template.media_type is None:
        return None
    return template.media_type + ("; charset=utf-8" if profile.charset else "")


def render(template, names: dict, leaves: dict, profile: EncoderProfile) -> Rendered:
    """Template + field names (site key -> name) + leaves (slot_id -> Leaf) + profile -> request parts.
    Field names are inserted as is ([a-z0-9_], lexicon-validated); values go through the encoder."""
    spans = {}
    target, pos = "", 0
    for seg in template.path:
        target += "/"
        if isinstance(seg, str):
            target += seg
        else:
            ctx = "tail" if seg.value_type == "path_file" else "segment"
            enc = encode_leaf_url(leaves[seg.slot_id], ctx, profile)
            if not enc:
                raise RenderError(f"empty path segment for {seg.slot_id}")
            spans[seg.slot_id] = ("target", len(target), len(target) + len(enc))
            target += enc
    body = ""
    if template.carrier in ("query", "form"):
        items, s = [], ""
        for i, sl in enumerate(template.fields):
            name = names[sl.key_path]
            enc = encode_leaf_url(leaves[sl.slot_id], template.carrier, profile)
            pre = ("&" if i else "") + name + "="
            items.append((sl.slot_id, len(s) + len(pre), enc))
            s += pre + enc
        if template.carrier == "query":
            base = len(target) + 1
            for sid, a, enc in items:
                spans[sid] = ("target", base + a, base + a + len(enc))
            target += "?" + s
        else:
            for sid, a, enc in items:
                spans[sid] = ("body", a, a + len(enc))
            body = s
    elif template.carrier == "json":
        body = _render_json(template.body, names, leaves, profile, spans)
    elif template.carrier == "text":
        sl = template.fields[0]
        body = leaf_text_value(leaves[sl.slot_id])
        if not body:
            raise RenderError("empty text/plain body")
        spans[sl.slot_id] = ("body", 0, len(body))
    ct = content_type(template, profile)
    headers = ((b"Content-Type", ct.encode("latin-1")),) if ct else ()
    try:
        tb = target.encode("ascii")
    except UnicodeEncodeError:
        raise GeneratorBug("non-ASCII in the target: the encoder must percent-encode it") from None
    parts = cr.RequestParts(method=template.method.encode("ascii"), target=tb, http_version="HTTP/1.1",
                            headers=headers, body=body.encode("utf-8"))
    return Rendered(template.method, target, ct, body, spans, parts)


def _render_json(root, names, leaves, profile, spans) -> str:
    item_sep, key_sep = (",", ":") if profile.json_style == "compact" else (", ", ": ")
    out = []

    def emit(s):
        out.append(s)

    def length():
        return sum(len(x) for x in out)

    def walk(n):
        if n.kind == "leaf":
            v = _json_scalar(leaf_json_value(leaves[n.slot.slot_id]))
            start = length()
            emit(v)
            spans[n.slot.slot_id] = ("body", start, start + len(v))
            return
        if n.kind == "object":
            emit("{")
            for i, c in enumerate(n.children):
                if i:
                    emit(item_sep)
                emit(_json_scalar(names[c.key_path]) + key_sep)
                walk(c)
            emit("}")
        else:
            emit("[")
            for i, c in enumerate(n.children):
                if i:
                    emit(item_sep)
                walk(c)
            emit("]")
    walk(root)
    return "".join(out)


def json_reference(root, names, leaves, profile) -> str:
    """The same body through `json.dumps` (a test asserts byte equality with `_render_json`)."""
    def build(n):
        if n.kind == "leaf":
            return leaf_json_value(leaves[n.slot.slot_id])
        if n.kind == "object":
            return {names[c.key_path]: build(c) for c in n.children}
        return [build(c) for c in n.children]
    seps = (",", ":") if profile.json_style == "compact" else (", ", ": ")
    return json.dumps(build(root), ensure_ascii=False, separators=seps)


# ───────────────────────────── canonical text + contract checks ─────────────────────────────
@dataclass(frozen=True)
class CanonicalRow:
    outcome: str                  # ACCEPT | REJECT
    text: str | None
    reject: str | None
    reason: str | None
    signals: tuple
    size: str
    leaf_spans: dict              # slot_id -> (start, end) in text (ACCEPT only)


def to_canonical(rendered: Rendered, limits: cr.Limits) -> CanonicalRow:
    """canonicalize() the rendered parts; check what the generator must guarantee:
    ACCEPT or R8 only; signals within ALLOWED_SIGNALS; A-G2 (JSON parses); A-G3 (only Content-Type);
    I3 idempotence through the reference parser. R8 is the OVER_LIMIT exclusion (never truncated)."""
    res = canonicalize(rendered.parts, limits)
    if res.outcome == cr.REJECT and res.reject == "R8":
        return CanonicalRow(res.outcome, None, "R8", res.reason, res.signals, res.size, {})
    if res.outcome != cr.ACCEPT:
        raise GeneratorBug(f"canonicalize returned {res.outcome} {res.reject} {res.reason}")
    bad = sorted(set(res.signals) - ALLOWED_SIGNALS)
    if bad:
        raise GeneratorBug(f"signals outside the training distribution: {bad}")
    text = res.text
    again = canonicalize(parse_canonical(text), limits)
    if again.text != text:
        raise GeneratorBug("I3: canonicalize(parse(text)) != text")
    lines = text.split("\n")
    if rendered.content_type is not None and lines[1] != f"Content-Type: {rendered.content_type}":
        raise GeneratorBug("A-G3: Content-Type line missing or altered")
    if rendered.content_type is None and len(lines) > 1 and lines[1] != "":
        raise GeneratorBug("A-G3: a header line other than Content-Type")
    if rendered.content_type and rendered.content_type.startswith("application/json"):
        json.loads(rendered.body)                     # A-G2 (raises on failure)
    return CanonicalRow(res.outcome, text, None, None, res.signals, res.size, rendered.text_spans(text))


# ───────────────────────────── encoding features (ENC-3 / ENC-4) ─────────────────────────────
def held_out_forms(text: str) -> list:
    """D15 held-out forms present in a text (stage-2 detector) plus row-level mixed hex case."""
    found = set(native_forms(text))
    prof = hex_case_profile(text)
    if prof in ("mixed_across_tokens", "lower", "mixed_within_token"):
        found.add("mixed_case_hex")                 # the generator emits uppercase hex only (ENC-2/6)
    return sorted(found)


def encoding_features(text: str) -> dict:
    """ENC-4 features of one row (class-difference audit input)."""
    trip = PCT_RE.findall(text)
    return {"pct_triplets": len(trip), "pct25": text.count("%25"),
            "plus": text.count("+"), "pct20": text.count("%20"),
            "lower_hex": sum(1 for t in trip if any(c.islower() for c in t[1:])),
            "double_encoding": bool(re.search(r"%25[0-9A-Fa-f]{2}", text))}
