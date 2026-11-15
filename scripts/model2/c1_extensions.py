"""Bounded, offline C1 facts from an already canonicalized request.

These facts are diagnostic evidence, not approved Model 2 inputs or decisions.
The parser does not revalidate wire framing or authorize data use. It never
serializes request values in its output.
"""

from dataclasses import dataclass
import hashlib
import json
import re
from urllib.parse import unquote_to_bytes, urlsplit

from .contracts import REPRESENTATION, invalid_features, rf
import canonical_request as cr

SCHEMA = "c1-extension-evidence/proposal-v2"
MAX_TEXT_BYTES = 65536  # Offline work bound; not a production B or R8 limit.
MAX_VALUES = 256
MAX_VALUE_CHARS = 2048

_PERCENT_BAD = re.compile(r"%(?![0-9a-fA-F]{2})")
_INTEGER = re.compile(r"[+-]?[0-9]+\Z")
_DECIMAL = re.compile(r"[+-]?(?:[0-9]+\.[0-9]+|[0-9]+\.|\.[0-9]+)\Z")
_SCIENTIFIC = re.compile(r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)[eE][+-]?[0-9]+\Z")
_LEXEMES = {
    "select": re.compile(r"(?<![A-Za-z0-9_])select(?![A-Za-z0-9_])", re.I | re.ASCII),
    "union": re.compile(r"(?<![A-Za-z0-9_])union(?![A-Za-z0-9_])", re.I | re.ASCII),
    "script": re.compile(r"(?<![A-Za-z0-9_])script(?![A-Za-z0-9_])", re.I | re.ASCII),
}


@dataclass(frozen=True)
class ValueFacts:
    count: int = 0
    empty: int = 0
    null: int = 0
    boolean: int = 0
    integer: int = 0
    decimal: int = 0
    scientific: int = 0
    url_http: int = 0
    url_https: int = 0
    text: int = 0
    lex_select: int = 0
    lex_union: int = 0
    lex_script: int = 0


@dataclass(frozen=True)
class JsonScalarTypes:
    string: int = 0
    number: int = 0
    boolean: int = 0
    null: int = 0


@dataclass(frozen=True)
class C1ExtensionEvidence:
    schema: str
    representation: str
    canonical_outcome: str
    status: str                 # COMPLETE | PARTIAL | UNAVAILABLE
    baseline: rf.RequestFeatures | None
    raw: ValueFacts | None
    decoded_once: ValueFacts | None
    value_sources: tuple[str, ...]
    facts_missing: tuple[str, ...]
    view_conflicts: int | None
    canonical_signals: tuple[str, ...]
    canonical_size: str
    learned_input_admitted: bool = False
    json_types: JsonScalarTypes | None = None
    coverage_scope: str = "bounded_query_form_json_scalars_only"


def _url_type(value):
    # A URL fact needs an absolute HTTP(S) URI with a hostname. No DNS/network I/O.
    # urlsplit alone silently removes control characters and accepts bad ports.
    if (not re.match(r"https?://", value, re.I | re.ASCII)
            or any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in value)):
        return None
    try:
        parsed = urlsplit(value)
        parsed.port  # Force the parser's malformed/out-of-range port check.
        if parsed.scheme.lower() in ("http", "https") and parsed.hostname:
            return "url_" + parsed.scheme.lower()
    except ValueError:
        pass
    return None


def _kind(value):
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if value == "":
        return "empty"
    if value.lower() in ("true", "false"):
        return "boolean"
    if _INTEGER.fullmatch(value):
        return "integer"
    if _DECIMAL.fullmatch(value):
        return "decimal"
    if _SCIENTIFIC.fullmatch(value):
        return "scientific"
    return _url_type(value) or "text"


def _facts(values):
    totals = {name: 0 for name in ValueFacts.__dataclass_fields__}
    for value in values:
        totals["count"] += 1
        totals[_kind(value)] += 1
        if isinstance(value, str):
            for name, pattern in _LEXEMES.items():
                totals["lex_" + name] += len(pattern.findall(value))
    return ValueFacts(**totals)


def _decode(value, *, plus_as_space):
    if _PERCENT_BAD.search(value):
        return None
    if plus_as_space:
        value = value.replace("+", " ")
    try:
        return unquote_to_bytes(value).decode("utf-8", "strict")
    except UnicodeDecodeError:
        return None


def _pairs(text):
    return [part.partition("=")[2] for part in text.split("&") if part]


class _JsonNumber(str):
    """Preserve JSON numeric type without conversion, overflow or digit limits."""


def _json_scalars(body):
    # Pair wrapper preserves duplicate object members. Numeric lexemes remain
    # strings for shape facts, while native JSON type counts stay separate.
    try:
        root = json.loads(body, object_pairs_hook=lambda pairs: ("object", pairs),
                          parse_int=_JsonNumber, parse_float=_JsonNumber,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, RecursionError):
        return None
    values, stack = [], [root]
    types = {name: 0 for name in JsonScalarTypes.__dataclass_fields__}
    while stack:
        node = stack.pop()
        if isinstance(node, tuple) and len(node) == 2 and node[0] == "object":
            stack.extend(value for _, value in node[1])
        elif isinstance(node, list):
            stack.extend(node)
        elif node is None or isinstance(node, (bool, str)):
            kind = ("null" if node is None else "boolean" if isinstance(node, bool)
                    else "number" if isinstance(node, _JsonNumber) else "string")
            types[kind] += 1
            values.append(str(node) if isinstance(node, _JsonNumber) else node)
    return values, JsonScalarTypes(**types)


def extract_extension(result):
    """Return bounded evidence only; a missing/partial view is never zero evidence."""
    if type(result) is not cr.CanonicalResult:
        raise TypeError("canonical result required")
    if result.outcome not in (cr.ACCEPT, cr.REJECT, cr.UNSUPPORTED):
        raise ValueError("unknown canonical outcome")
    if not isinstance(result.signals, tuple) or any(s not in cr.ALL_SIGNALS for s in result.signals):
        raise ValueError("unknown canonical signal")
    if result.size not in (cr.SIZE_UNCHECKED, cr.SIZE_WITHIN,
                           cr.SIZE_OVER, cr.SIZE_NEEDS_EXACT_COUNT):
        raise ValueError("unknown canonical size")
    base = dict(schema=SCHEMA, representation=REPRESENTATION,
                canonical_outcome=result.outcome, canonical_signals=result.signals,
                canonical_size=result.size)
    if result.outcome != cr.ACCEPT or result.text is None:
        return C1ExtensionEvidence(**base, status="UNAVAILABLE", baseline=None,
                                   raw=None, decoded_once=None, value_sources=(),
                                   facts_missing=("canonical_accept",), view_conflicts=None)
    if type(result.text) is not str:
        raise TypeError("canonical text required")
    # Check character bound before encoding/hashing potentially huge input.
    if len(result.text) > MAX_TEXT_BYTES or len(result.text.encode("utf-8")) > MAX_TEXT_BYTES:
        return C1ExtensionEvidence(**base, status="UNAVAILABLE", baseline=None,
                                   raw=None, decoded_once=None, value_sources=(),
                                   facts_missing=("text_over_offline_bound",), view_conflicts=None)
    if (not isinstance(result.audit, dict)
            or result.audit.get("contract") != cr.CONTRACT_ID
            or result.audit.get("text_sha256") != hashlib.sha256(result.text.encode("utf-8")).hexdigest()):
        raise ValueError("canonical text integrity mismatch")
    parts = cr.parse_canonical(result.text)
    features = rf.extract_features(result.text)
    if invalid_features(features):
        raise ValueError("invalid baseline C1 features")
    target, body = parts.target.decode("utf-8"), parts.body.decode("utf-8")

    raw, decoded, sources, missing = [], [], [], []
    json_types = None
    if "?" in target:
        raw.extend(_pairs(target.partition("?")[2]))
        sources.append("query")
    if body:
        if features.body_format == "form":
            raw.extend(_pairs(body))
            sources.append("form")
        elif features.body_format == "json":
            parsed = _json_scalars(body)
            if parsed is None:
                missing.append("json_parse")
            else:
                values, json_types = parsed
                raw.extend(values)
                sources.append("json_scalar")
        else:
            missing.append("body_values_unsupported")
    if len(raw) > MAX_VALUES or any(len(value) > MAX_VALUE_CHARS
                                    for value in raw if isinstance(value, str)):
        return C1ExtensionEvidence(**base, status="UNAVAILABLE", baseline=features,
                                   raw=None, decoded_once=None, value_sources=tuple(sources),
                                   facts_missing=("values_over_offline_bound",), view_conflicts=None)
    # JSON strings are already semantic values. Query decodes percent only; form
    # additionally maps + to space. A malformed triplet/UTF-8 leaves the whole
    # decoded view unavailable instead of silently replacing bytes.
    q = len(_pairs(target.partition("?")[2])) if "?" in target else 0
    f = len(_pairs(body)) if body and features.body_format == "form" else 0
    for i, value in enumerate(raw):
        encoded_value = i < q + f
        decoded_value = (_decode(value, plus_as_space=q <= i < q + f)
                         if encoded_value else value)
        if encoded_value and decoded_value is None:
            missing.append("decoded_view_invalid")
            decoded = []
            break
        decoded.append(decoded_value)
    decoded_facts = _facts(decoded) if "decoded_view_invalid" not in missing else None
    return C1ExtensionEvidence(**base, status="PARTIAL" if missing else "COMPLETE",
                               baseline=features, raw=_facts(raw), decoded_once=decoded_facts,
                               value_sources=tuple(sources), facts_missing=tuple(sorted(set(missing))),
                               json_types=json_types,
                               view_conflicts=(sum(a != b for a, b in zip(raw, decoded))
                                               if decoded_facts is not None else None))
