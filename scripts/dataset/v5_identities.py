#!/usr/bin/env python3
"""V5 stage 3 — dataset identities and grouping (V5-DATA-SPEC-r3 §4.6, FROZEN by D62; issue #72).

Stdlib only, plus the D16 `canonical_key` (imported from `parse_dataset_v4`, never re-implemented)
and the stage-2 `value_entry_id` (imported from `v5_pools_common`, never re-implemented).

Identities (spec §4.6):
  template_id        sha256 of the structural skeleton; field names are not part of the input type
  struct_cluster_id  declared by the template author; declared merges resolve to the
                     lexicographically smallest member id; near-duplicate templates (Jaccard >= 0.60)
                     in different clusters are reported, never split
  payload_family_id  canonical_key + digits -> 0, hosts / IPs / e-mails -> H, character runs > 3 -> 3,
                     whitespace removed. Explicit merges happen before ranking (merged id = smallest
                     member id). One identity across categories; stratum category = the
                     lexicographically first category it occurs in
  value_entry_id     sha256(pool_id NUL NFC(element)) — stage 2, reused
  pair_id            a benign row and its twins; derived from the row coordinates of step 4

Where the frozen text is silent this module states its interpretation next to the code; every one
is listed in reports/v5/dataset-identities-split/README.md §3 for the owner's ratification.
Nothing here assigns a split (that is `v5_split.py`), renders a request or labels anything.
"""
from __future__ import annotations

import hashlib
import json
import random
import re
import sys
import os
import unicodedata
from collections import defaultdict
from dataclasses import dataclass
from typing import Iterable, Mapping, Sequence

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import v5_pools_common as C  # noqa: E402  (value_entry_id, nfc: stage 2, reused)
from parse_dataset_v4 import canonical_key  # noqa: E402  (D16 identity: imported, never edited)

SALT = "v5-split-v1"                      # spec §4.6, frozen; also restated and checked in the config
PFID_RULES_VERSION = "pfid-rules/v3"     # D-5 (digit runs), D-6 (§4.3 redirect forms); v3: D-6 residual, integer host after `http:`
NEAR_DUP_THRESHOLD = (3, 5)               # Jaccard >= 0.60, compared as exact integers: 5·|A∩B| >= 3·|A∪B|
NEAR_DUP_N = 4                            # owner ruling D-1
NEAR_DUP_REPRESENTATION = "set of contiguous 4-grams of Unicode code points of each pre-merge family key/v2"
value_entry_id = C.value_entry_id         # re-exported: one implementation only


class IdentityError(ValueError):
    """Invalid identity input: duplicate, conflict, unknown reference or malformed id."""


# ───────────────────────────── hashing convention (NUL-joined, D54) ─────────────────────────────
def nul_sha256(*parts: str) -> str:
    """sha256 over UTF-8 of the NUL-joined parts. Only the LAST part may contain NUL; any earlier
    part containing it would make two different tuples hash the same input, so it is refused."""
    for i, p in enumerate(parts):
        if not isinstance(p, str):
            raise IdentityError(f"hash part {i} is {type(p).__name__}, not str")
        if i < len(parts) - 1 and "\0" in p:
            raise IdentityError(f"hash part {i} contains NUL (only the last part may)")
    return hashlib.sha256("\0".join(parts).encode("utf-8")).hexdigest()


def canonical_json(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


# ───────────────────────────── payload_family_id ─────────────────────────────
# Rules applied, in the order the spec lists them, to the D16 canonical_key (already lowercase, so
# the marker "H" cannot collide with payload text). Interpretations (report §3):
#   I-1 (owner ruling D-5) "digits -> 0": every maximal run of one or more ASCII digits becomes one "0".
#   I-2 (owner ruling D-6) "hosts" = e-mail addresses, IP literals (IPv6 bracketed / with "::" or 7
#       colons; IPv4 as four dotted parts in decimal, octal or 0x-hex) anywhere, and, in URL-authority
#       position, a dotted reg-name, `localhost` or a single all-digit / 0x-hex label (integer IPv4),
#       with a trailing dot and non-ASCII labels allowed. URL-authority position is a separator run of
#       two or more `/` or `\` in any mix (`//h`, `\\h` RFC 3986 §3.2.2; `/\h`, `\/\/h` §4.3
#       POL-REDIRECT-DIFF), with CR / LF / TAB inside the run (after canonical_key, a space), IN URL
#       CONTEXT only (start of the value, after `=`, a quote, a backtick or a space, or after a scheme of
#       2+ characters), so `..//boot.ini`, `..\/boot.ini`, `c:\\php.ini` and `alert(1)//x.y` keep their
#       names; `http:h` / `https:h` with no slash (dotted name, localhost, or an integer / 0x-hex IPv4 such
#       as `http:3627734734` / `http:0xd83ad6ce`: §4.3 POL-REDIRECT-DIFF `https:h` with a POL-URL-OBFUSCATED
#       dword host; owner ruling D-6 residual, round 3); an integer / 0x host after the userinfo `@`
#       of a URL (§4.3 POL-URL-OBFUSCATED, "userinfo @ confusion"). A bare dotted word is NOT a host
#       (`php.ini`, `document.cookie`); look-alike slashes (U+3031, U+FF0F, …) are not §4.3 forms.
#   I-3 (ratified) "character runs > 3 -> 3" means a single character repeated 4+ times becomes 3 copies.
_DIGIT_RUN = re.compile(r"[0-9]+")
_EMAIL = re.compile(r"[a-z0-9._%+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)+")
_IPV6_BRACKET = re.compile(r"\[[0-9a-f.]*:[0-9a-f.]*:[0-9a-f:.]*\]")
_IPV6_BARE = re.compile(r"(?<![0-9a-z:.])[0-9a-f:.]+(?![0-9a-z:.])")
_IPV4_PART = r"(?:0x[0-9a-f]+|[0-9]+)"
_IPV4 = re.compile(rf"(?<![0-9a-z.]){_IPV4_PART}(?:\.{_IPV4_PART}){{3}}(?![0-9a-z])(?!\.[0-9a-z])")
_HOST = r"(?:localhost|0x[0-9a-f]+|[0-9]+|[\w~-]+(?:\.[\w~-]+)+)\.?(?![\w~.-])"
# A separator run (`//`, `\\`, `/\`, `\/\/`, with CR / LF / TAB inside) introduces a host only in URL
# context: at the start of the value, after `=`, a quote, a backtick or a space, or right after a scheme
# of two or more characters (`http:`, `gopher:`; a drive letter `c:` is not a scheme). Elsewhere it is a
# path or a comment (`..//boot.ini`, `c:\\php.ini`, `alert(1)//document.cookie`) and is left alone.
_SEP_HOST = re.compile(r"(?P<pre>(?:[/\\] *){2,})" + _HOST)
_URL_BOUNDARY = frozenset("=\"'` ")
_SCHEME_TAIL = re.compile(r"(?:^|[^a-z0-9+.-])[a-z][a-z0-9+.-]+:$")
# `http:h` / `https:h` takes the same host forms as the authority position. Digits are already one `0`
# (D-5), so `http:80` and `http:3627734734` are one key: both are a host for a WHATWG parser (0.0.0.80).
_PLAIN_SCHEME_HOST = re.compile(r"(?P<pre>(?<![\w])https?:)" + _HOST)
_USERINFO_INT_HOST = re.compile(r"(?P<pre>(?:https?:|//)[^\s@/]*@)(?:0x[0-9a-f]+|[0-9]+)(?![\w.])")
_RUN = re.compile(r"(.)\1{3,}", re.DOTALL)
_WS = re.compile(r"\s+")


_AUTH_HOST_V1 = re.compile(r"(?:(?<=//)|(?<=\\\\))" + _HOST)       # superseded v1 rule (census diagnostics)


def _literals(s: str) -> str:
    s = _EMAIL.sub("H", s)
    s = _IPV6_BRACKET.sub("H", s)
    s = _IPV6_BARE.sub(_bare_ipv6, s)
    return _IPV4.sub("H", s)


def _mask_hosts_v1(s: str) -> str:
    return _AUTH_HOST_V1.sub("H", _literals(s))


def _url_context(left: str) -> bool:
    return left == "" or left[-1] in _URL_BOUNDARY or bool(_SCHEME_TAIL.search(left))


def _sep_host(m: re.Match) -> str:
    return m.group("pre") + "H" if _url_context(m.string[:m.start()]) else m.group(0)


def _bare_ipv6(m: re.Match) -> str:
    s = m.group(0)
    if ("::" in s or s.count(":") == 7) and re.search(r"[0-9a-f]", s):
        return "H"
    return s


def _mask_hosts(s: str) -> str:
    s = _SEP_HOST.sub(_sep_host, _literals(s))
    s = _PLAIN_SCHEME_HOST.sub(lambda m: m.group("pre") + "H", s)
    return _USERINFO_INT_HOST.sub(lambda m: m.group("pre") + "H", s)


def _family_key(payload: str, per_digit: bool = False, redirect_forms: bool = True) -> str:
    """`per_digit` / `redirect_forms=False` reproduce the superseded v1 rules; census diagnostics only."""
    s = canonical_key(payload)
    s = re.sub(r"[0-9]", "0", s) if per_digit else _DIGIT_RUN.sub("0", s)
    s = _mask_hosts(s) if redirect_forms else _mask_hosts_v1(s)
    s = _RUN.sub(lambda m: m.group(1) * 3, s)
    return _WS.sub("", s)


def family_key(payload: str) -> str:
    """The family key under the current rules, possibly empty. Stage 2 reads it for its identity
    admissibility steps (owner rulings D-4 and round 3); `payload_family_id` refuses empty keys."""
    return _family_key(payload)


def payload_family_id(payload: str) -> str:
    """The family key itself is the id (the spec defines no hash for it). Empty keys and keys that
    are not encodable as UTF-8 (lone surrogates) are refused."""
    if not isinstance(payload, str):
        raise IdentityError("payload must be str")
    key = _family_key(payload)
    if not key:
        raise IdentityError(f"payload {payload[:40]!r} has an empty family key")
    _check_utf8(key)
    return key


def _check_utf8(key: str) -> None:
    try:
        key.encode("utf-8")
    except UnicodeEncodeError:
        raise IdentityError(f"family key {key[:40]!r} is not valid UTF-8 (lone surrogate)") from None


@dataclass(frozen=True)
class Family:
    payload_family_id: str
    categories: tuple            # sorted, unique; stratum = categories[0]
    native_forms: tuple          # sorted union of the members' stage-2 `native_forms` (ENC-5)
    members: tuple               # sorted record ids
    merged_from: tuple           # sorted pre-merge family ids (just the id itself when unmerged)

    @property
    def stratum_category(self) -> str:
        return self.categories[0]

    @property
    def has_native_held_out_form(self) -> bool:
        return bool(self.native_forms)


class UnionFind:
    def __init__(self, items: Iterable[str] = ()):
        self.parent = {x: x for x in items}

    def find(self, x: str) -> str:
        root = x
        while self.parent[root] != root:
            root = self.parent[root]
        while self.parent[x] != root:
            self.parent[x], x = root, self.parent[x]
        return root

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:                       # the smaller id becomes the root: root == min(component)
            lo, hi = (ra, rb) if ra < rb else (rb, ra)
            self.parent[hi] = lo

    def components(self) -> dict:
        out = defaultdict(list)
        for x in self.parent:
            out[self.find(x)].append(x)
        return {k: sorted(v) for k, v in out.items()}


def _resolve_merges(ids: Iterable[str], merges: Sequence[Sequence[str]], what: str) -> UnionFind:
    uf = UnionFind(sorted(set(ids)))
    for g, group in enumerate(merges):
        if not isinstance(group, (list, tuple)) or not all(isinstance(x, str) for x in group):
            raise IdentityError(f"{what} merge #{g} must be a list of id strings")
        group = list(group)
        if len(set(group)) < 2 or len(set(group)) != len(group):
            raise IdentityError(f"{what} merge #{g} needs at least two distinct ids and no repeats")
        for x in group:
            if x not in uf.parent:
                raise IdentityError(f"{what} merge #{g} names unknown id {x[:60]!r}")
        for x in group[1:]:
            uf.union(group[0], x)
    return uf


def build_families(records: Iterable[Mapping], merges: Sequence[Sequence[str]] = ()) -> dict:
    """Group stage-2 attack records (status ACCEPTED) into payload families.

    Each record needs `record_id`, `payload_wire`, `canonical_key`, `dedup_scope` (the stage-2
    category: V4 category, traversal + inclusion merged by D49) and `native_forms`. The stored
    `canonical_key` must equal `canonical_key(payload_wire)` (provenance integrity). Declared merges
    are applied before anything is ranked; the merged id is the smallest member id.
    Returns {payload_family_id: Family}."""
    by_pfid = defaultdict(list)
    seen, empty = set(), []
    for r in records:
        rid = r.get("record_id")
        if not rid or rid in seen:
            raise IdentityError(f"missing or duplicate record_id {rid!r}")
        seen.add(rid)
        if r.get("status") != C.ACCEPTED:
            raise IdentityError(f"record {rid} has status {r.get('status')!r}; only ACCEPTED records form families")
        wire = r.get("payload_wire")
        if not isinstance(wire, str):
            raise IdentityError(f"record {rid} has no payload_wire")
        if r.get("canonical_key") != canonical_key(wire):
            raise IdentityError(f"record {rid}: stored canonical_key differs from canonical_key(payload_wire)")
        cat = r.get("dedup_scope")
        if not isinstance(cat, str) or not cat:
            raise IdentityError(f"record {rid} has no category (dedup_scope)")
        key = _family_key(wire)
        if not key:
            empty.append(rid)
            continue
        _check_utf8(key)
        by_pfid[key].append(r)
    if empty:
        raise IdentityError(f"{len(empty)} record(s) have an empty family key (empty canonical_key); "
                            f"no family can be defined for them: {sorted(empty)}")
    uf = _resolve_merges(by_pfid, merges, "family")
    families = {}
    for root, ids in uf.components().items():
        rs = [r for i in ids for r in by_pfid[i]]
        families[root] = Family(
            payload_family_id=root,
            categories=tuple(sorted({r["dedup_scope"] for r in rs})),
            native_forms=tuple(sorted({f for r in rs for f in (r.get("native_forms") or [])})),
            members=tuple(sorted(r["record_id"] for r in rs)),
            merged_from=tuple(ids))
    return families


# ───────────────────────────── template_id ─────────────────────────────
# I-4 The frozen text says "structural skeleton, field names excluded". The skeleton follows the
#     pre-freeze proposal (G §2.1): method, carrier, media type, path skeleton (literal segments and
#     type tokens) and the ordered (positional key path, value type) slots. Field names are not a
#     member of the type, so they cannot reach the hash.
_KEY_STEP_ARRAY = "[]"


@dataclass(frozen=True)
class TemplateSkeleton:
    method: str
    carrier: str
    media_type: str | None
    path: tuple            # segments, e.g. ("api", "{int}")
    slots: tuple           # ((key path of ints / "[]"), value type), in order

    def as_obj(self) -> dict:
        if not self.method or not self.carrier:
            raise IdentityError("template skeleton needs method and carrier")
        slots = []
        for kp, vt in self.slots:
            kp = tuple(kp)
            if not kp or not all((isinstance(k, int) and not isinstance(k, bool) and k >= 0)
                                 or k == _KEY_STEP_ARRAY for k in kp):
                raise IdentityError(f"slot key path {kp!r} must be positions (int >= 0) or '[]' — never names")
            if not isinstance(vt, str) or not vt:
                raise IdentityError("slot value type must be a non-empty string")
            slots.append([list(kp), vt])
        if not all(isinstance(s, str) and s for s in self.path):
            raise IdentityError("path segments must be non-empty strings")
        return {"method": self.method, "carrier": self.carrier, "media_type": self.media_type,
                "path": list(self.path), "slots": slots}


def template_id(skeleton: TemplateSkeleton) -> str:
    return nul_sha256("template", canonical_json(skeleton.as_obj()))


def template_tokens(skeleton: TemplateSkeleton) -> frozenset:
    """Token set used by the Jaccard near-duplicate audit of templates (I-5)."""
    o = skeleton.as_obj()
    toks = {f"m:{o['method']}", f"c:{o['carrier']}", f"t:{o['media_type']}"}
    toks |= {f"p{i}:{seg}" for i, seg in enumerate(o["path"])}
    toks |= {f"s:{'.'.join(map(str, kp))}:{vt}" for kp, vt in o["slots"]}
    return frozenset(toks)


# ───────────────────────────── struct_cluster_id ─────────────────────────────
@dataclass(frozen=True)
class TemplateDecl:
    template_id: str
    struct_cluster_id: str          # as declared by the template author
    carrier_stratum: str
    tokens: frozenset = frozenset()


@dataclass(frozen=True)
class ClusterTable:
    template_cluster: dict          # template_id -> resolved struct_cluster_id
    cluster_stratum: dict           # resolved struct_cluster_id -> carrier stratum
    cluster_members: dict           # resolved id -> sorted declared ids merged into it
    near_duplicates: tuple          # ((template_a, template_b, inter, union), ...) across clusters


def resolve_clusters(decls: Iterable[TemplateDecl], merges: Sequence[Sequence[str]] = ()) -> ClusterTable:
    """Apply declared cluster merges (merged id = smallest member id) and audit templates.

    Refused: a template declared twice; a merge naming an unknown cluster; a resolved cluster whose
    templates span two carrier strata (it would be ranked twice and could be fragmented).
    Reported, not resolved: undeclared near-duplicate templates (Jaccard >= 0.60) in different
    resolved clusters. The split refuses to run while any exists; the fix is a declared merge."""
    decls = list(decls)
    seen = {}
    for d in decls:
        if d.template_id in seen:
            raise IdentityError(f"template {d.template_id[:16]} declared more than once")
        if not d.struct_cluster_id or not d.carrier_stratum:
            raise IdentityError(f"template {d.template_id[:16]} lacks cluster or stratum")
        if not d.tokens:
            raise IdentityError(f"template {d.template_id[:16]} has no audit tokens; the near-duplicate "
                                "audit cannot be skipped")
        seen[d.template_id] = d
    uf = _resolve_merges({d.struct_cluster_id for d in decls}, merges, "cluster")
    template_cluster = {d.template_id: uf.find(d.struct_cluster_id) for d in decls}
    cluster_stratum = {}
    for d in decls:
        c = template_cluster[d.template_id]
        if cluster_stratum.setdefault(c, d.carrier_stratum) != d.carrier_stratum:
            raise IdentityError(f"cluster {c!r} spans strata {cluster_stratum[c]!r} and {d.carrier_stratum!r}")
    members = {k: v for k, v in uf.components().items() if k in cluster_stratum}
    tok = {d.template_id: d.tokens for d in decls}
    near = [(a, b, i, u) for a, b, i, u in near_duplicate_pairs(tok)
            if template_cluster[a] != template_cluster[b]]
    return ClusterTable(template_cluster, cluster_stratum, members, tuple(near))


# ───────────────────────────── pair_id and the per-row RNG (step 4) ─────────────────────────────
# I-6 The spec defines a pair (a benign row and its twins, generated inside one split) and the
#     per-row RNG string, not a pair hash. pair_id hashes the same coordinates. Coordinates may not
#     contain "|", which would make two different coordinate tuples produce one RNG string.
def _row_coordinates(split: str, cluster: str, quota: str, i: int) -> tuple:
    for name, v in (("split", split), ("cluster", cluster), ("quota", quota)):
        if not isinstance(v, str) or not v or "|" in v or "\0" in v:
            raise IdentityError(f"{name} {v!r} must be a non-empty string without '|' or NUL")
    if not isinstance(i, int) or isinstance(i, bool) or i < 0:
        raise IdentityError("row index must be an int >= 0")
    return split, cluster, quota, str(i)


def row_seed(split: str, cluster: str, quota: str, i: int) -> str:
    s, c, q, n = _row_coordinates(split, cluster, quota, i)
    return f"{SALT}|{s}|{c}|{q}|{n}"


def row_rng(split: str, cluster: str, quota: str, i: int) -> random.Random:
    """Spec §4.6 step 4: Random(f"{SALT}|{split}|{cluster}|{quota}|{i}"). str seeds are hashed by
    SHA-512 inside `random` (version 2), so the stream does not depend on PYTHONHASHSEED."""
    return random.Random(row_seed(split, cluster, quota, i))


def pair_id(split: str, cluster: str, quota: str, i: int) -> str:
    return nul_sha256(SALT, "pair", *_row_coordinates(split, cluster, quota, i))


# ───────────────────────────── near-duplicates (SPL-9, template audit) ─────────────────────────────
# I-5 (owner ruling D-1, after a structural audit of the stage-2 pool and before any real split): the
#     frozen text fixes Jaccard >= 0.60, not the representation. Representation: the SET (not
#     multiset) of contiguous n-grams, n = 4, of Unicode code points (Python str slices; not UTF-8
#     bytes) of each pre-merge family key. Two families are near-duplicates when any pair of their
#     pre-merge keys is. A key shorter than 4 code points has NO n-gram: it is reported as
#     UNOBSERVABLE, never padded, never compared with a smaller n, never silently passed. Whether and
#     how such keys are compared is an open owner decision (report §R3). The superseded v1 word
#     representation ([a-z0-9]{3,} of canonical_key) left 413 families with no representation.
def payload_shingles(family_key: str) -> frozenset:
    n = NEAR_DUP_N
    return frozenset(family_key[i:i + n] for i in range(len(family_key) - n + 1))


def is_unobservable(family_key: str) -> bool:
    return len(family_key) < NEAR_DUP_N


def is_near_duplicate(inter: int, union: int) -> bool:
    num, den = NEAR_DUP_THRESHOLD
    return union > 0 and den * inter >= num * union


def near_duplicate_pairs(tokens: Mapping[str, frozenset], partition: Mapping[str, str] | None = None) -> list:
    """Every pair (a < b) with Jaccard >= 0.60, exactly (an inverted index finds every pair that
    shares a token; pairs sharing none have Jaccard 0). With `partition`, only pairs whose members
    are in different partitions are returned. Items with an empty token set are skipped."""
    index = defaultdict(list)
    for k in sorted(tokens):
        for t in tokens[k]:
            index[t].append(k)
    out = []
    for a in sorted(tokens):
        A = tokens[a]
        if not A:
            continue
        cands = {b for t in A for b in index[t] if b > a}
        for b in sorted(cands):
            if partition is not None and partition[a] == partition[b]:
                continue
            B = tokens[b]
            inter = len(A & B)
            union = len(A) + len(B) - inter
            if is_near_duplicate(inter, union):
                out.append((a, b, inter, union))
    return out


def family_near_duplicate_pairs(families: Mapping[str, "Family"], partition: Mapping[str, str] | None = None) -> list:
    """Sorted unique (family_a, family_b) pairs, a < b, with a pre-merge key pair at Jaccard >= 0.60.
    With `partition` (family id -> partition), only pairs in different partitions. Unobservable keys
    (shorter than n) take part in no pair; `unobservable_keys` lists them."""
    owner, shingles = {}, {}
    for fid, f in families.items():
        for k in f.merged_from:
            if k in owner and owner[k] != fid:
                raise IdentityError(f"family key in two families: {k[:40]!r}")
            owner[k], shingles[k] = fid, payload_shingles(k)
    key_part = None if partition is None else {k: partition[owner[k]] for k in owner}
    pairs = {tuple(sorted((owner[a], owner[b]))) for a, b, *_ in near_duplicate_pairs(shingles, key_part)
             if owner[a] != owner[b]}
    return sorted(pairs)


def unobservable_keys(families: Mapping[str, "Family"]) -> list:
    return sorted(k for f in families.values() for k in f.merged_from if is_unobservable(k))


def propose_merges(pairs: Iterable[tuple]) -> list:
    """Union-find components of near-duplicate pairs: a PROPOSAL for the declared merge list. The
    split never merges by itself; adopting a proposal is an explicit, recorded configuration change."""
    uf = UnionFind()
    for a, b, *_ in pairs:
        uf.parent.setdefault(a, a)
        uf.parent.setdefault(b, b)
        uf.union(a, b)
    return sorted(uf.components().values())


# ───────────────────────────── value equivalence and pre-split deduplication (owner ruling D-3) ─────────────────────────────
# I-15 Value equivalence = NFC + str.casefold(). Not `canonical_key`: that D16 payload identity
#      URL-decodes (`+` -> space: "O+" ~ "O", "Disney+" ~ "Disney") and lower()s without folding ß.
#      No whitespace collapse: on the stage-2 pools it adds no group (measured), and spaces can be
#      significant. `value_entry_id` keeps its frozen formula; only WHICH entries enter the split
#      changes. Representative of a group: first by the configured pool precedence, then the smallest
#      value_entry_id (content-defined; never the file order). The rule is applied to EVERY group
#      (owner ruling, stage 3 round 3, policy B: the round-2 hold is removed). Where a reviewer recorded
#      that the members differ in meaning (`semantic_notes`: `wasps` insect vs `WASPs` acronym), the
#      excluded member gets VALUE_POLICY_REASON and the note: it is excluded by the equivalence policy
#      that keeps equivalent values out of two splits, never because it is a synonym of the kept one.
VALUE_EQUIVALENCE = "nfc_casefold/v1"
VALUE_DUPLICATE_REASON = "value_equivalent_duplicate"
VALUE_POLICY_REASON = "value_equivalence_policy:split_contamination_guard"


def value_equivalence_key(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


def dedup_value_pools(pools: Mapping[str, Iterable[Mapping]], precedence: Sequence[str],
                      semantic_notes: Mapping[str, str] | None = None) -> dict:
    """pools: pool_id -> stage-2 records (`value`, `value_entry_id`, `source_ref`). `semantic_notes`:
    equivalence key -> reviewer note for a group whose members differ in meaning. Returns
    {"kept": {pool_id: [records]}, "excluded": [ledger rows], "groups": n, "semantic_notes_applied": [keys]}.
    Every input record is either kept or in the ledger with its representative's provenance."""
    rank = {p: i for i, p in enumerate(precedence)}
    missing = sorted(set(pools) - set(rank))
    if missing or len(rank) != len(precedence):
        raise IdentityError(f"value pool precedence must list each pool once; missing {missing}")
    notes = dict(semantic_notes or {})
    if not all(isinstance(k, str) and k and isinstance(v, str) and v.strip() for k, v in notes.items()):
        raise IdentityError("semantic notes must map an equivalence key to a non-empty note")
    groups = defaultdict(list)
    for pool in sorted(pools):
        seen = set()
        for r in pools[pool]:
            v = r.get("value")
            if not isinstance(v, str) or not v:
                raise IdentityError(f"{pool}: record without a value")
            vid = value_entry_id(pool, v)
            if r.get("value_entry_id") != vid:
                raise IdentityError(f"{pool}: value_entry_id does not match the frozen formula for {v[:30]!r}")
            if vid in seen:
                raise IdentityError(f"{pool}: duplicate value_entry_id")
            seen.add(vid)
            groups[value_equivalence_key(v)].append((rank[pool], vid, pool, r))
    unknown = sorted(k for k in notes if len(groups.get(k, ())) < 2)
    if unknown:
        raise IdentityError(f"semantic notes name keys that are not an equivalence group of 2+ values: {unknown}")
    kept, excluded = defaultdict(list), []
    for key in sorted(groups):
        members = sorted(groups[key], key=lambda m: (m[0], m[1]))
        _, rep_id, rep_pool, rep = members[0]
        kept[rep_pool].append(rep)
        for _, vid, p, r in members[1:]:
            row = {"pool_id": p, "value": r["value"], "value_entry_id": vid,
                   "source_ref": r.get("source_ref"), "exclusion_reason": VALUE_DUPLICATE_REASON,
                   "equivalence": VALUE_EQUIVALENCE,
                   "representative": {"pool_id": rep_pool, "value": rep["value"],
                                      "value_entry_id": rep_id, "source_ref": rep.get("source_ref")}}
            if key in notes:          # not a synonym: excluded by the split-contamination policy only
                row.update(exclusion_reason=VALUE_POLICY_REASON, synonym=False, semantic_difference=notes[key])
            excluded.append(row)
    kept = {p: sorted(kept.get(p, []), key=lambda r: r["value_entry_id"]) for p in sorted(pools)}
    excluded.sort(key=lambda e: (e["pool_id"], e["value_entry_id"]))
    return {"kept": kept, "excluded": excluded, "semantic_notes_applied": sorted(notes),
            "groups": sum(1 for g in groups.values() if len(g) > 1), "equivalence": VALUE_EQUIVALENCE}
