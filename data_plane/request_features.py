"""
firewall-IA — request feature extraction (Hybrid Architecture Phase 1, Issue #49).

Describes one HTTP request as a fixed set of features. It DESCRIBES; it does not
decide. There is no ALLOW, no BLOCK, no score and no threshold anywhere in this
module, and nothing in the request path reads its output: in Phase 1 the data
plane only logs it (shadow mode, D43). V4 remains the only decision.

INPUT is the D1 representation: the raw HTTP text `data_plane.render_request()`
produces, `/classify` receives and the V4 dataset stores.

    METHOD /path?query HTTP/1.1
    Name: value                   <- one line per header
                                  <- blank line, only when there is a body
    body

Working on that text, not on mitmproxy objects, makes a feature computed live in
the gateway and one computed offline over a dataset the same function of the
same string.

EXCLUDED (D44): `Host` and `User-Agent`. Both were label shortcuts (F1, D1). The
only header read is `Content-Type`. Character and syntax features are computed
over the request "surface" = path + query + body, never over headers. Counts are
taken on the text as received: nothing is percent-decoded or normalized.

Standard library only, so it imports in the data plane environment and in the
ML environment alike. Deterministic: no randomness, no clock, no dependence on
hash seeds, on interpreter settings or on the caller's stack depth.
"""

import json
import math
import re
import string
from collections import Counter
from dataclasses import dataclass

# Bump when a feature is added, removed or redefined, so features recorded under
# different definitions are never mixed. v1 was the pre-review definition, seen
# only in reports/hybrid/phase1-feature-extraction-v1/.
FEATURE_SCHEMA_VERSION = "request-features/v2"

FORM_MEDIA_TYPE = "application/x-www-form-urlencoded"

# JSON nested deeper than this is reported as json_invalid. Python's parser gives
# up at a depth that depends on the caller's stack (measured 9,897-9,997 on
# Python 3.12), so without a cap far below it the same body could be "json" in
# one process and "json_invalid" in another.
MAX_JSON_DEPTH = 1000

_ALNUM = frozenset(string.ascii_letters + string.digits)
_SYMBOLS = frozenset(string.punctuation)  # the 32 ASCII punctuation characters
_PERCENT_ENCODED = re.compile(r"%[0-9A-Fa-f]{2}")
_CHAR_RUN = re.compile(r"(.)\1+", re.DOTALL)  # runs of 2+ identical characters


@dataclass(frozen=True)
class RequestFeatures:
    """The description of one request. Every field is defined in
    docs/technical_reference.md ("Request feature extraction")."""

    # Request general
    method: str
    path_length: int
    query_length: int
    body_length: int
    has_body: bool
    content_type: str               # media type only, lowercase; "" when absent
    body_format: str                # "none" | "form" | "json" | "json_invalid" | "other"
    query_param_count: int
    body_param_count: int           # form pairs or JSON object members; 0 when not parsed
    total_param_count: int
    repeated_param_name_count: int  # names occurring more than once (query + form body)

    # Characters and structure, over path + query + body
    alnum_ratio: float
    symbol_count: int               # ASCII punctuation characters
    symbol_ratio: float
    non_ascii_count: int
    percent_encoded_count: int      # %XX triplets
    percent_encoded_ratio: float    # share of characters inside %XX triplets
    has_percent_encoding: bool
    longest_char_run: int
    entropy_bits_per_char: float
    path_depth: int                 # non-empty path segments
    json_depth: int                 # container nesting of a parsed JSON body; else 0

    # Syntactic signal counts, over path + query + body, not decoded
    single_quote_count: int
    double_quote_count: int
    parenthesis_count: int
    semicolon_count: int
    slash_count: int
    backslash_count: int
    angle_bracket_count: int
    pipe_count: int
    ampersand_count: int
    equals_count: int
    percent_count: int
    brace_count: int

    schema_version: str = FEATURE_SCHEMA_VERSION


def extract_features(request_text: str) -> RequestFeatures:
    """Describe one request given as D1 text. Total over strings: an empty or
    malformed text yields features (missing parts count as empty), never an
    exception. A non-string is a caller bug and raises TypeError."""
    if not isinstance(request_text, str):
        raise TypeError(f"request_text must be str, got {type(request_text).__name__}")

    head, _, body = request_text.partition("\n\n")
    request_line, *header_lines = head.split("\n")
    method, _, rest = request_line.partition(" ")
    # METHOD TARGET VERSION; the version is the last token when there is one.
    target = rest.rpartition(" ")[0] if " " in rest else rest
    path, _, query = target.partition("?")
    content_type = _content_type(header_lines)

    query_names = _param_names(query)
    body_names: list[str] = []
    body_param_count = json_depth = 0
    if not body:
        body_format = "none"
    elif content_type == FORM_MEDIA_TYPE:
        body_format = "form"
        body_names = _param_names(body)
        body_param_count = len(body_names)
    elif content_type == "application/json" or content_type.endswith("+json"):
        body_format, body_param_count, json_depth = _json_body(body)
    else:
        body_format = "other"

    parts = (path, query, body)
    surface = "".join(parts)
    n = len(surface)
    chars = Counter(surface)
    alnum = sum(c for ch, c in chars.items() if ch in _ALNUM)
    symbols = sum(c for ch, c in chars.items() if ch in _SYMBOLS)
    non_ascii = sum(c for ch, c in chars.items() if ord(ch) > 127)
    # Patterns are matched part by part: path, query and body are not adjacent
    # in the request, so a %XX triplet or a character run must not be formed
    # across their boundaries. (Character counts are additive and need no care.)
    encoded = sum(len(_PERCENT_ENCODED.findall(part)) for part in parts)
    longest_run = max(_longest_run(part) for part in parts)

    return RequestFeatures(
        method=method,
        path_length=len(path),
        query_length=len(query),
        body_length=len(body),
        has_body=bool(body),
        content_type=content_type,
        body_format=body_format,
        query_param_count=len(query_names),
        body_param_count=body_param_count,
        total_param_count=len(query_names) + body_param_count,
        repeated_param_name_count=sum(
            1 for c in Counter(query_names + body_names).values() if c > 1),
        alnum_ratio=_ratio(alnum, n),
        symbol_count=symbols,
        symbol_ratio=_ratio(symbols, n),
        non_ascii_count=non_ascii,
        percent_encoded_count=encoded,
        percent_encoded_ratio=_ratio(3 * encoded, n),
        has_percent_encoding=encoded > 0,
        longest_char_run=longest_run,
        entropy_bits_per_char=_entropy(chars.values(), n),
        path_depth=sum(1 for segment in path.split("/") if segment),
        json_depth=json_depth,
        single_quote_count=chars["'"],
        double_quote_count=chars['"'],
        parenthesis_count=chars["("] + chars[")"],
        semicolon_count=chars[";"],
        slash_count=chars["/"],
        backslash_count=chars["\\"],
        angle_bracket_count=chars["<"] + chars[">"],
        pipe_count=chars["|"],
        ampersand_count=chars["&"],
        equals_count=chars["="],
        percent_count=chars["%"],
        brace_count=chars["{"] + chars["}"],
    )


def _content_type(header_lines: list[str]) -> str:
    """Media type of the first Content-Type header, lowercase, parameters
    dropped. This is the ONLY header this module reads (D44)."""
    for line in header_lines:
        name, _, value = line.partition(":")
        if name.strip().lower() == "content-type":
            return value.split(";", 1)[0].strip().lower()
    return ""


def _param_names(encoded: str) -> list[str]:
    """Parameter names of an `a=1&b=2` string, raw (not decoded). Empty
    segments (`a=1&&b=2`) are not parameters; `flag` without `=` is one."""
    return [segment.partition("=")[0] for segment in encoded.split("&") if segment]


def _longest_run(text: str) -> int:
    """Length of the longest run of one repeated character."""
    return max((m.end() - m.start() for m in _CHAR_RUN.finditer(text)),
               default=1 if text else 0)


def _json_body(body: str) -> tuple[str, int, int]:
    """(body_format, object members, nesting depth) of a JSON-typed body.

    Objects are kept as written (`object_pairs_hook=tuple`), so a duplicate key
    is still a member, as a repeated form parameter is. Integers stay strings
    (`parse_int=str`): their values are never used, and the interpreter's
    int-digit limit must not decide whether a body is JSON. See MAX_JSON_DEPTH.
    """
    try:
        parsed = json.loads(body, object_pairs_hook=tuple, parse_int=str)
    except (ValueError, RecursionError):
        return "json_invalid", 0, 0
    members, depth = _json_shape(parsed)
    if depth > MAX_JSON_DEPTH:
        return "json_invalid", 0, 0
    return "json", members, depth


def _json_shape(value) -> tuple[int, int]:
    """(object members at any depth, maximum container nesting) of a value
    parsed by `_json_body`, where an object is a tuple of (name, value) pairs.
    Iterative, so walking a deep value cannot exhaust the interpreter stack."""
    members = depth = 0
    stack = [(value, 1)]
    while stack:
        node, level = stack.pop()
        if isinstance(node, tuple):
            members += len(node)
            depth = max(depth, level)
            stack.extend((child, level + 1) for _, child in node)
        elif isinstance(node, list):
            depth = max(depth, level)
            stack.extend((child, level + 1) for child in node)
    return members, depth


def _ratio(part: int, whole: int) -> float:
    return part / whole if whole else 0.0


def _entropy(counts, total: int) -> float:
    """Shannon entropy of the character distribution, in bits per character."""
    if not total:
        return 0.0
    # max() turns the -0.0 of a single repeated character into 0.0.
    return max(0.0, -sum((c / total) * math.log2(c / total) for c in counts))
