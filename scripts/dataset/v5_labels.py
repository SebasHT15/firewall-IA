#!/usr/bin/env python3
"""V5 stage 4 — labelling policy, value classes and label invariants M-1…M-10 (issue #74).

Spec V5-DATA-SPEC-r3 §4.3 / §4.5 (classes, contexts, precedence FROZEN by D62; decisions D59):

* A label is a function of provenance (benign generator value vs attack-pool leaf), of the value's
  structure and of explicit policies. The label functions take NO field name (M-8): the only
  name-derived input is the slot ROLE (`navigation` | `data`), computed separately by `slot_role`
  from the PROPOSED navigation-role lexicon, and it may only decide inclusion.
* `label_status` ∈ VERIFIED / POLICY_DEFINED / EXCLUDED; `exclusion_reason` in the D59 vocabulary,
  one per row, first match in the frozen order; `policy_id` resolves in the versioned policy table.
* Attack-pool items are never ALLOW (M-6). SSRF / open-redirect BLOCK labels come only from a
  `POL-*` BLOCK class and are POLICY_DEFINED. No attack leaf is labelled at all without an attack
  label basis: VERIFIED needs the post-filter audit (§7, §11.3), which does not exist, so the only
  basis this code accepts today is a synthetic fixture whose every record says so.

The concrete lists (hosts, networks, schemes, navigation names) are read from the policy table,
whose status is PROPOSED; this module never declares them approved.
"""
from __future__ import annotations

import hashlib
import inspect
import ipaddress
import json
import os
import re
import sys
from collections import Counter
from dataclasses import dataclass, field

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))
for p in (HERE, os.path.join(REPO_ROOT, "control_plane")):
    if p not in sys.path:
        sys.path.insert(0, p)

import v5_row_contract as RC
import v5_catalog as K  # noqa: E402
import v5_output_contract as OC  # noqa: E402  (ALLOW string and V4/D47 BLOCK strings: read only)

POLICY_SCHEMA = "v5-policy-table/v1"
DEFAULT_POLICY_TABLE = os.path.join(HERE, "v5_policy", "policy_table_v1.json")

VERIFIED, POLICY_DEFINED, EXCLUDED = "VERIFIED", "POLICY_DEFINED", "EXCLUDED"
LABEL_STATUSES = (VERIFIED, POLICY_DEFINED, EXCLUDED)
ALLOW, BLOCK = "ALLOW", "BLOCK"
AMBIGUOUS, INSUFFICIENT_CONTEXT, ORACLE_REJECT = "AMBIGUOUS", "INSUFFICIENT_CONTEXT", "ORACLE_REJECT"
AUDIT_REJECT, OUT_OF_SCOPE, OVER_LIMIT = "AUDIT_REJECT", "OUT_OF_SCOPE", "OVER_LIMIT"
EXCLUSION_REASONS = (AMBIGUOUS, INSUFFICIENT_CONTEXT, ORACLE_REJECT, AUDIT_REJECT, OUT_OF_SCOPE, OVER_LIMIT)
CTX_LOOPBACK, CTX_PRIVATE, CTX_OPEN_REDIRECT = "ctx_loopback", "ctx_private", "ctx_open_redirect"
CTX_ATTACK_UNCLASSIFIED, QUOTED_SYNTAX = "ctx_attack_unclassified", "quoted_syntax"
SLICE_REASONS = (AMBIGUOUS, INSUFFICIENT_CONTEXT)        # M-4: only these exist as rows (slice files)
RULE_BENIGN, RULE_ATTACK = "BENIGN_ORACLE_PASS", "ATTACK_POOL_LEAF"
NAVIGATION, DATA = "navigation", "data"

# §4.3 "one reason per row", frozen order. OUT_OF_SCOPE appears twice: category first, deferred family 6th.
_EXCLUSION_ORDER = {(OUT_OF_SCOPE, "category"): 1, (AUDIT_REJECT, None): 2, (ORACLE_REJECT, None): 3,
                    (INSUFFICIENT_CONTEXT, CTX_LOOPBACK): 4.1, (INSUFFICIENT_CONTEXT, CTX_PRIVATE): 4.1,
                    (INSUFFICIENT_CONTEXT, CTX_OPEN_REDIRECT): 4.1, (INSUFFICIENT_CONTEXT, CTX_ATTACK_UNCLASSIFIED): 4.2,
                    (AMBIGUOUS, QUOTED_SYNTAX): 5, (OUT_OF_SCOPE, "deferred_family"): 6, (OVER_LIMIT, None): 7}

# M-7: BLOCK reason strings are the V4/D47 vocabulary (`v5_output_contract`, read only).
ALLOW_OUTPUT = OC.ALLOW_OUTPUT
BLOCK_REASONS = frozenset(s[len("BLOCK | "):] for s in OC.VOCABULARY_ALT_A if s.startswith("BLOCK | "))
CATEGORY_REASON = {                                        # policy rows: reason of the policy's category
    K.SSRF: "Server-side request forgery attack detected.",
    K.REDIRECT: "Open redirect payload detected.",
    K.XSS: "Cross-site scripting payload detected.",
}


class LabelError(ValueError):
    """Inputs the labelling policy cannot label (programming or configuration error)."""


class LabelBlocked(RuntimeError):
    """An attack leaf cannot be labelled because its basis (post-filter audit) does not exist."""


class BenignPoolViolation(AssertionError):
    """A benign generator value falls in a BLOCK class or outside the reserved stand-ins: a pool bug."""


# ───────────────────────────── policy table ─────────────────────────────
@dataclass(frozen=True)
class PolicyTable:
    obj: dict
    sha256: str
    policies: dict
    precedence: tuple
    lists: dict

    @property
    def block_policies(self) -> frozenset:
        return frozenset(k for k, v in self.policies.items() if v["label"] == BLOCK)

    def networks(self, key):
        return tuple(ipaddress.ip_network(n) for n in self.lists[key])


FROZEN_PRECEDENCE = ("POL-URL-META", "POL-URL-SCHEME", "POL-URL-OBFUSCATED", "POL-REDIRECT-DIFF",
                     "INSUFFICIENT_CONTEXT", "POL-URL-PUBLIC", "POL-ADDR-DATA")
FROZEN_LABELS = {"POL-URL-META": BLOCK, "POL-URL-SCHEME": BLOCK, "POL-URL-OBFUSCATED": BLOCK,
                 "POL-REDIRECT-DIFF": BLOCK, "POL-URL-PUBLIC": ALLOW, "POL-ADDR-DATA": ALLOW}
FROZEN_CATEGORY = {"POL-URL-META": K.SSRF, "POL-URL-SCHEME": K.SSRF, "POL-URL-OBFUSCATED": K.SSRF,
                   "POL-REDIRECT-DIFF": K.REDIRECT, "POL-URL-PUBLIC": None, "POL-ADDR-DATA": None}
LIST_KEYS = ("meta_hosts", "meta_networks", "allowed_schemes", "loopback_hosts", "loopback_suffixes",
             "loopback_networks", "private_networks", "internal_suffixes", "public_host_suffixes",
             "navigation_role_names")


def load_policy_table(path: str = DEFAULT_POLICY_TABLE) -> PolicyTable:
    with open(path, "rb") as fh:
        data = fh.read()
    return parse_policy_table(json.loads(data), hashlib.sha256(data).hexdigest())


def parse_policy_table(obj: dict, sha256: str | None = None) -> PolicyTable:
    """Classes, labels, categories and precedence must equal the frozen §4.3 text; lists are validated
    for shape only (they are PROPOSED)."""
    if not isinstance(obj, dict) or obj.get("schema") != POLICY_SCHEMA:
        raise LabelError(f"policy table schema must be {POLICY_SCHEMA!r}")
    if tuple(obj.get("precedence", ())) != FROZEN_PRECEDENCE:
        raise LabelError("policy precedence differs from the frozen §4.3 order")
    pols = {}
    for p in obj.get("policies", ()):
        pid = p.get("policy_id")
        if pid in pols:
            raise LabelError(f"policy {pid} declared twice")
        if p.get("label") != FROZEN_LABELS.get(pid) or p.get("attack_category") != FROZEN_CATEGORY.get(pid):
            raise LabelError(f"policy {pid}: label / attack_category differ from the frozen table")
        if not p.get("rule") or not p.get("assumed_context"):
            raise LabelError(f"policy {pid}: rule and assumed_context are required (D59)")
        pols[pid] = p
    if set(pols) != set(FROZEN_LABELS):
        raise LabelError(f"policy ids {sorted(pols)} differ from the frozen set")
    lists = obj.get("lists", {})
    if set(lists) != set(LIST_KEYS):
        raise LabelError(f"policy lists must be exactly {LIST_KEYS}")
    for k in LIST_KEYS:
        if not isinstance(lists[k], list) or not lists[k] or not all(isinstance(x, str) and x for x in lists[k]):
            raise LabelError(f"policy list {k} must be a non-empty list of strings")
    for k in ("meta_networks", "loopback_networks", "private_networks"):
        for n in lists[k]:
            ipaddress.ip_network(n)                    # raises on a malformed network
    if [s.lower() for s in lists["allowed_schemes"]] != ["http", "https"]:
        raise LabelError("allowed_schemes is fixed by the frozen text: http, https")
    if sha256 is None:
        sha256 = hashlib.sha256(json.dumps(obj, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    return PolicyTable(obj, sha256, pols, FROZEN_PRECEDENCE, {k: tuple(v) for k, v in lists.items()})


def slot_role(field_name: str | None, table: PolicyTable) -> str:
    """The only name-derived input: decides inclusion only (§4.3). Unnamed slots are data."""
    return NAVIGATION if field_name in table.lists["navigation_role_names"] else DATA


# ───────────────────────────── URL value classes (deterministic, §4.3) ─────────────────────────────
_SCHEME = re.compile(r"([A-Za-z][A-Za-z0-9+.\-]+):")        # >= 2 characters: `c:` is a drive letter
_SEP_RUN = re.compile(r"(?:/|\\|%2[fF]|%5[cC])+")
_REDIRECT_START = re.compile(r"(?:/[/\\]|\\[/\\]|/%2[fF]|%2[fF]%2[fF]|\\/\\/)")
_HOSTNAME = re.compile(r"(?=.{1,253}\.?$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\.?\Z", re.I)


@dataclass(frozen=True)
class UrlClass:
    kind: str                 # POLICY | EXCLUDE | RELATIVE | PUBLIC_UNRESERVED
    policy_id: str | None = None
    slice: str | None = None
    detail: str = ""
    scheme: str | None = None


def parse_ipv4_numeric(host: str):
    """WHATWG-style IPv4 parse: 1–4 dot parts, each decimal, 0-octal or 0x-hex. Returns
    (IPv4Address, canonical: bool) or None when the host is not a numeric IPv4."""
    parts = host.split(".")
    if parts and parts[-1] == "":
        parts = parts[:-1]
    if not 1 <= len(parts) <= 4:
        return None
    nums = []
    for p in parts:
        if re.fullmatch(r"0[xX][0-9A-Fa-f]*", p):
            nums.append(int(p[2:] or "0", 16))
        elif re.fullmatch(r"0[0-7]+", p):
            nums.append(int(p, 8))
        elif re.fullmatch(r"[0-9]+", p):
            if len(p) > 1 and p[0] == "0":
                return None                          # 08 / 09: not octal, not a valid IPv4 part
            nums.append(int(p))
        else:
            return None
    if any(n > 255 for n in nums[:-1]) or nums[-1] >= 256 ** (5 - len(nums)):
        return None
    value = 0
    for n in nums[:-1]:
        value = value * 256 + n
    value = value * 256 ** (5 - len(nums)) + nums[-1]
    ip = ipaddress.IPv4Address(value)
    return ip, host.rstrip(".") == str(ip) and host == host.rstrip(".")


def _host_info(host: str):
    """(ip or None, obfuscated: bool, mapped_v4 or None)."""
    if host.startswith("[") and host.endswith("]"):
        try:
            ip6 = ipaddress.IPv6Address(host[1:-1].split("%")[0])
        except ValueError:
            return None, False, None
        return ip6, ip6.ipv4_mapped is not None, ip6.ipv4_mapped
    v4 = parse_ipv4_numeric(host)
    if v4 is not None:
        return v4[0], not v4[1], None
    return None, False, None


def _in(ip, nets) -> bool:
    return ip is not None and any(ip.version == n.version and ip in n for n in nets)


def _suffix(host: str, suffixes) -> bool:
    h = host.rstrip(".").lower()
    return any(h == s or h.endswith("." + s) for s in suffixes)


def classify_url(value: str, role: str, table: PolicyTable) -> UrlClass:
    """Value class of a URL-slot value, first match in the frozen precedence. `role` decides only the
    `ctx_open_redirect` exclusion (inclusion), never a BLOCK class."""
    if role not in (NAVIGATION, DATA):
        raise LabelError(f"unknown role {role!r}")
    v = value.strip(" ")
    ctl = any(c in value for c in "\r\n\t")
    m = _SCHEME.match(v)
    scheme = m.group(1).lower() if m else None
    rest = v[m.end():] if m else v
    authority = None
    form = "relative"
    if scheme is not None and scheme not in ("http", "https"):
        form = "scheme"
        sep = _SEP_RUN.match(rest)
        authority = rest[sep.end():] if sep else None
    elif scheme is not None:
        if rest.startswith("//"):
            form, authority = "absolute", rest[2:]
        else:
            form = "scheme_no_slashes"                  # https:h, http:\\h, https:/h
            sep = _SEP_RUN.match(rest)
            authority = rest[sep.end():] if sep else rest
    elif _REDIRECT_START.match(v):
        form = "scheme_relative"
        authority = v[_SEP_RUN.match(v).end():]
    userinfo, host = False, None
    if authority is not None:
        auth = re.split(r"[/?#\\]", authority, maxsplit=1)[0]
        if "@" in auth:
            userinfo, auth = True, auth.rsplit("@", 1)[1]
        if auth.startswith("["):
            host = auth[:auth.find("]") + 1] if "]" in auth else auth
        else:
            host = re.sub(r":[0-9]*\Z", "", auth)
        host = host.lower()
    ip, obfuscated, mapped = _host_info(host) if host else (None, False, None)
    L = table.lists
    meta_nets = table.networks("meta_networks")
    if host and (host.rstrip(".") in L["meta_hosts"] or _in(ip, meta_nets) or _in(mapped, meta_nets)):
        return UrlClass("POLICY", "POL-URL-META", detail=f"host {host}", scheme=scheme)
    if form == "scheme":
        return UrlClass("POLICY", "POL-URL-SCHEME", detail=f"scheme {scheme}", scheme=scheme)
    if host and (obfuscated or userinfo):
        return UrlClass("POLICY", "POL-URL-OBFUSCATED", detail="userinfo" if userinfo else f"host {host}", scheme=scheme)
    if ctl or form in ("scheme_relative", "scheme_no_slashes"):
        return UrlClass("POLICY", "POL-REDIRECT-DIFF", detail="control character" if ctl else form, scheme=scheme)
    if form == "relative":
        return UrlClass("RELATIVE", detail="relative reference")
    if not host:
        return UrlClass("EXCLUDE", slice=CTX_ATTACK_UNCLASSIFIED, detail="absolute URL without host", scheme=scheme)
    if _in(ip, table.networks("loopback_networks")) or _in(mapped, table.networks("loopback_networks")) \
            or host.rstrip(".") in L["loopback_hosts"] or _suffix(host, L["loopback_suffixes"]):
        return UrlClass("EXCLUDE", slice=CTX_LOOPBACK, detail=f"host {host}", scheme=scheme)
    if _in(ip, table.networks("private_networks")) or _suffix(host, L["internal_suffixes"]) \
            or (ip is None and "." not in host.rstrip(".")):
        return UrlClass("EXCLUDE", slice=CTX_PRIVATE, detail=f"host {host}", scheme=scheme)
    if role == NAVIGATION:
        return UrlClass("EXCLUDE", slice=CTX_OPEN_REDIRECT, detail="absolute external URL in a navigation role",
                        scheme=scheme)
    if ip is None and _suffix(host, L["public_host_suffixes"]):
        return UrlClass("POLICY", "POL-URL-PUBLIC", detail=f"host {host}", scheme=scheme)
    return UrlClass("PUBLIC_UNRESERVED", detail=f"host {host} is not a reserved stand-in", scheme=scheme)


def is_addr_data(value: str) -> bool:
    """POL-ADDR-DATA value class: an IP address or a hostname (dotted labels, alphabetic TLD)."""
    v = value.strip()
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        pass
    return bool(_HOSTNAME.match(v))


# ───────────────────────────── leaf and row labels ─────────────────────────────
@dataclass(frozen=True)
class LeafLabel:
    label: str | None             # ALLOW | BLOCK | None (excluded)
    status: str                   # VERIFIED | POLICY_DEFINED | EXCLUDED
    rule: str | None = None       # BENIGN_ORACLE_PASS | ATTACK_POOL_LEAF | policy id
    policy_id: str | None = None
    exclusion: str | None = None
    exclusion_kind: str | None = None   # category | deferred_family | slice name
    slice: str | None = None
    attack_category: str | None = None
    reason: str | None = None
    detail: str = ""
    label_status_basis: str | None = None


@dataclass(frozen=True)
class AttackBasis:
    """What licenses labelling attack leaves. `post_filter_audit` needs a passed audit per category
    (spec §7) — not available, so it refuses. `fixture_synthetic` accepts only records that declare
    `synthetic: true` (never a real payload)."""
    mode: str
    categories_passed: frozenset = frozenset()
    audit_type: str | None = None
    row_contract: str | None = None

    def check(self, record: dict, category: str) -> None:
        if self.mode == "fixture_synthetic":
            if record.get("synthetic") is not True:
                raise LabelBlocked(f"record {record.get('record_id')} is not synthetic; a fixture basis cannot label it")
            return
        if self.mode == "post_filter_audit":
            if category not in self.categories_passed:
                raise LabelBlocked(f"{category}: post-filter audit not passed (spec §7); no attack leaf can be labelled")
            return
        raise LabelBlocked(f"unknown attack label basis {self.mode!r}")


NO_BASIS = AttackBasis("post_filter_audit", frozenset())   # today's real state: nothing passed


def label_benign_leaf(slot_type: str, logical: str, role: str, oracle_reason: str | None,
                      table: PolicyTable) -> LeafLabel:
    """A benign generator value in an attackable slot."""
    if slot_type not in K.ATTACK_SLOT_TYPES:
        raise LabelError(f"{slot_type} is not an attackable slot type")
    if oracle_reason is not None:
        return LeafLabel(None, EXCLUDED, exclusion=ORACLE_REJECT, detail=oracle_reason)
    if slot_type == "url":
        uc = classify_url(logical, role, table)
        if uc.kind == "RELATIVE":
            return LeafLabel(ALLOW, VERIFIED, RULE_BENIGN, detail="relative URL")
        if uc.kind == "POLICY" and uc.policy_id == "POL-URL-PUBLIC":
            return LeafLabel(ALLOW, POLICY_DEFINED, uc.policy_id, uc.policy_id, detail=uc.detail)
        if uc.kind == "EXCLUDE":
            return LeafLabel(None, EXCLUDED, exclusion=INSUFFICIENT_CONTEXT, exclusion_kind=uc.slice,
                             slice=uc.slice, detail=uc.detail)
        raise BenignPoolViolation(f"benign URL {logical[:60]!r} is {uc.kind} {uc.policy_id}: benign URL pools "
                                  "hold only relative URLs and reserved public stand-ins")
    if slot_type == "path_file":
        if re.search(r"(?:^|[/\\])\.\.(?:[/\\]|$)", logical):
            raise BenignPoolViolation(f"benign path {logical[:60]!r} contains '..' (spec §2.1)")
        return LeafLabel(ALLOW, VERIFIED, RULE_BENIGN)
    if is_addr_data(logical):
        return LeafLabel(ALLOW, POLICY_DEFINED, "POL-ADDR-DATA", "POL-ADDR-DATA", detail="address as data")
    return LeafLabel(ALLOW, VERIFIED, RULE_BENIGN)


def label_attack_leaf(record: dict, category: str, slot_type: str, logical: str, role: str,
                      table: PolicyTable, basis: AttackBasis, trained_categories) -> LeafLabel:
    """An attack-pool payload placed in a compatible slot. Never ALLOW (M-6)."""
    if category not in K.SLOT_COMPATIBILITY.get(slot_type, ()):
        raise LabelError(f"{category} is not compatible with slot type {slot_type} (§4.2)")
    if category not in trained_categories:
        return LeafLabel(None, EXCLUDED, exclusion=OUT_OF_SCOPE, exclusion_kind="category",
                         detail=f"{category} outside the configured V5 ML scope")
    if record.get("status") != "ACCEPTED" or record.get("audit_verdict") == "INCORRECT":
        return LeafLabel(None, EXCLUDED, exclusion=AUDIT_REJECT, detail="rejected by deny-list, filters or audit")
    basis.check(record, category)
    if category in K.POLICY_CATEGORIES:
        uc = classify_url(logical, role, table)
        if uc.kind == "POLICY" and uc.policy_id in table.block_policies:
            cat = table.policies[uc.policy_id]["attack_category"]
            cat = table.policies[uc.policy_id].get("attack_category_by_scheme", {}).get(uc.scheme, cat)
            return LeafLabel(BLOCK, POLICY_DEFINED, uc.policy_id, uc.policy_id, attack_category=cat,
                             reason=CATEGORY_REASON[cat], detail=uc.detail)
        if uc.kind == "EXCLUDE" and uc.slice != CTX_ATTACK_UNCLASSIFIED:
            return LeafLabel(None, EXCLUDED, exclusion=INSUFFICIENT_CONTEXT, exclusion_kind=uc.slice,
                             slice=uc.slice, detail=uc.detail)
        return LeafLabel(None, EXCLUDED, exclusion=INSUFFICIENT_CONTEXT, exclusion_kind=CTX_ATTACK_UNCLASSIFIED,
                         slice=CTX_ATTACK_UNCLASSIFIED, detail=f"value class {uc.kind} is not a BLOCK class")
    reason = record.get("reason_string")
    if reason not in BLOCK_REASONS:
        raise LabelError(f"record {record.get('record_id')}: reason {reason!r} is not a V4/D47 string (M-7)")
    if basis.audit_type == 'ai_audited':
        if basis.row_contract != RC.SCHEMA:
            raise LabelBlocked('AI attack references require the explicit training-reference contract')
        return LeafLabel(BLOCK,RC.TRAINING_REFERENCE,RULE_ATTACK,attack_category=category,
                         reason=reason,label_status_basis='ai_audit')
    return LeafLabel(BLOCK, VERIFIED, RULE_ATTACK, attack_category=category, reason=reason)


def exclusion_rank(leaf: LeafLabel) -> float:
    key = (leaf.exclusion, leaf.exclusion_kind if leaf.exclusion in (OUT_OF_SCOPE, INSUFFICIENT_CONTEXT, AMBIGUOUS)
           else None)
    if key not in _EXCLUSION_ORDER:
        raise LabelError(f"exclusion {key} has no place in the frozen order")
    return _EXCLUSION_ORDER[key]


def combine(leaves: list, table: PolicyTable) -> LeafLabel:
    """One row label from its leaf labels: the first exclusion in the frozen order; else the attack
    leaf's BLOCK; else ALLOW, POLICY_DEFINED by the first policy in precedence if any leaf needs one."""
    if not leaves:
        raise LabelError("a row has at least one attackable leaf")
    excl = [x for x in leaves if x.status == EXCLUDED]
    if excl:
        return min(excl, key=lambda x: (exclusion_rank(x), x.detail))
    blocks = [x for x in leaves if x.label == BLOCK]
    if len(blocks) > 1:
        raise LabelError("a row has exactly one attack leaf")
    if blocks:
        return blocks[0]
    pol = [x for x in leaves if x.status == POLICY_DEFINED]
    if pol:
        return min(pol, key=lambda x: table.precedence.index(x.policy_id))
    return leaves[0]


def output_string(row_label: LeafLabel) -> str | None:
    if row_label.label == ALLOW:
        return ALLOW_OUTPUT
    if row_label.label == BLOCK:
        return f"BLOCK | {row_label.reason}"
    return None


# ───────────────────────────── M-1 … M-10 on generated row metadata ─────────────────────────────
def check_m_invariants(rows: list, table: PolicyTable, split_rows: bool, *, row_contract=None) -> dict:
    """rows: row metadata dicts. `split_rows`: the rows are a TRAIN / VALIDATION / INTERNAL TEST file
    (M-4: no EXCLUDED row) rather than a slice file (only AMBIGUOUS / INSUFFICIENT_CONTEXT)."""
    bad = Counter()
    for r in rows:
        st, ex, pid = r.get("label_status"), r.get("exclusion_reason"), r.get("policy_id")
        if st not in LABEL_STATUSES and not RC.is_reference(r,contract=row_contract):
            bad["M-1"] += 1
        if (ex is not None) != (st == EXCLUDED) or (ex is not None and ex not in EXCLUSION_REASONS):
            bad["M-2"] += 1
        if (pid is not None) != (st == POLICY_DEFINED) or (pid is not None and pid not in table.policies):
            bad["M-3"] += 1
        if split_rows and st == EXCLUDED:
            bad["M-4"] += 1
        if not split_rows and (st != EXCLUDED or ex not in SLICE_REASONS):
            bad["M-4"] += 1
        if r.get("label") == BLOCK:
            if not r.get("attack_category") or not r.get("payload_family_id") or \
                    r.get("label_rule") not in ({RULE_ATTACK} | table.block_policies):
                bad["M-5"] += 1
            if r.get("output") != f"BLOCK | {r.get('reason_string')}" or r.get("reason_string") not in BLOCK_REASONS:
                bad["M-7"] += 1
            if pid in ("POL-URL-META", "POL-URL-OBFUSCATED") and r.get("attack_category") != K.SSRF:
                bad["M-7"] += 1
            if pid == "POL-REDIRECT-DIFF" and r.get("attack_category") != K.REDIRECT:
                bad["M-7"] += 1
            if pid == "POL-URL-SCHEME" and r.get("attack_category") not in (K.SSRF, K.XSS):
                bad["M-7"] += 1
        if r.get("label") == ALLOW:
            if r.get("payload_family_id") is not None:
                bad["M-5"] += 1
            if r.get("payload_record_id") is not None:
                bad["M-6"] += 1
            if r.get("output") != ALLOW_OUTPUT:
                bad["M-7"] += 1
        if r.get("label") is None and st != EXCLUDED:
            bad["M-1"] += 1
    m8 = check_m8_signature()
    out = {k: {"ok": bad.get(k, 0) == 0, "violations": bad.get(k, 0)} for k in
           ("M-1", "M-2", "M-3", "M-4", "M-5", "M-6", "M-7")}
    out["M-8"] = m8
    out["policy_table_sha256"] = table.sha256
    out["rows"] = len(rows)
    out["ok"] = all(v["ok"] for k, v in out.items() if k.startswith("M-"))
    return out


def check_m8_signature() -> dict:
    """M-8 (static part): no label function takes a field name. The behavioural part (renaming fields
    within a role gives identical labels) is a unit test and a generator gate."""
    funcs = (label_benign_leaf, label_attack_leaf, classify_url, combine, is_addr_data)
    params = {f.__name__: list(inspect.signature(f).parameters) for f in funcs}
    offenders = {n: [p for p in ps if "name" in p or p == "field"] for n, ps in params.items()}
    offenders = {n: ps for n, ps in offenders.items() if ps}
    return {"ok": not offenders, "offenders": offenders, "violations": len(offenders)}


def m9_counts(rows: list) -> list:
    """M-9: rows per (split, category, class, label_status, exclusion_reason, policy_id)."""
    c = Counter((r.get("split"), r.get("attack_category") or r.get("twin_category") or "—",
                 r.get("label") or "—", r.get("label_status"), r.get("exclusion_reason") or "—",
                 r.get("policy_id") or "—") for r in rows)
    keys = ("split", "category", "class", "label_status", "exclusion_reason", "policy_id")
    return [dict(zip(keys, k), rows=n) for k, n in sorted(c.items())]
