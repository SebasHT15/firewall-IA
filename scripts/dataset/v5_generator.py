#!/usr/bin/env python3
"""V5 stage 4 — constructive pair generator (V5-DATA-SPEC-r3 §4.1–§4.6, §5, §6; issue #74).

Builds, from a stage-3 `SplitAssignment` (never redefined here), benign rows and their attack twins:

  * per split, only that split's partition is drawn from (`SplitAssignment.partition`, §4.6 step 4);
  * per pair, `row_rng(split, cluster, quota, i)` is the only randomness and `pair_id(...)` its id
    (stage 3, D64); quota = the twin's category slug; i = attempt index;
  * the twin keeps the template, method, carrier, Content-Type, encoder profile, field names and every
    non-attacked leaf; exactly one leaf differs (§4.2); `placement_mode` is recorded;
  * attack twins are drawn from the length bin nearest to the benign value they replace (§4.1);
  * every row is labelled by `v5_labels` (no field-name input, M-8), checked by the benign oracle,
    rendered by the shared encoder and `canonicalize()` (I1–I3), and an over-budget row is
    EXCLUDED `OVER_LIMIT` (R8), never truncated (§5.5);
  * a pair is emitted to its split only when both rows are included. Excluded rows go to slice files
    (AMBIGUOUS / INSUFFICIENT_CONTEXT, M-4) or to the counts; an included sibling of an excluded row is
    withheld and counted (balance by pairs, no row trimming);
  * a pair that would carry a non-native held-out form (ENC-3) is abandoned and counted.

After generation the build gates run: M-1…M-8, C-M2 pair integrity, ENC-1 / ENC-3 / ENC-7, the
stage-3 SPL-3…SPL-9 gates on the generated rows, plus reported (PROPOSED-threshold) diagnostics:
class balance, carrier symmetry, ENC-4 encoding features, over-limit shares, cluster shares.

Fixture builds are synthetic. Real builds require the D72-ratified #80 contract,
committed authorization, admitted category evidence and effective preconditions.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, replace

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import v5_row_contract as RC
import v5_pilot_authorization as PA
import v5_audit_evidence as AE
import v5_component_binding as CB
import v5_catalog as K  # noqa: E402
import v5_identities as I  # noqa: E402
import v5_labels as L  # noqa: E402
import v5_oracle as O  # noqa: E402
import v5_pools_common as C  # noqa: E402
import v5_rebalance as V9  # noqa: E402
import v5_render as R  # noqa: E402
import v5_split as S  # noqa: E402
import v5_split_checks as SC  # noqa: E402

GEN_CONFIG_SCHEMA = "v5-generator-config/v1"
ROW_META_SCHEMA = "v5-row-meta/v1"
MANIFEST_SCHEMA = "v5-generator-manifest/v1"
GENERATOR_VERSION = "v5-generator/0.1"
PLACEMENT_MODES = ("replace", "prefix", "suffix", "embedded")
VALUE_STATUSES = ("PROPOSED", "PENDING", "FIXTURE", "RATIFIED")
COUNTERS = ("utf8_bytes_upper_bound", "tokenizer")
CODE_FILES = ("v5_pilot_authorization.py", "v5_rebalance.py", "v5_row_contract.py", "v5_audit_evidence.py", "v5_catalog.py", "v5_render.py", "v5_labels.py", "v5_oracle.py", "v5_generator.py",
              "v5_fixture.py", "v5_identities.py", "v5_split.py", "v5_split_checks.py", "v5_pools_common.py")
DATA_FILES = (os.path.join("v5_templates", "catalog_v1.json"), os.path.join("v5_templates", "field_names_v1.json"),
              os.path.join("v5_policy", "policy_table_v1.json"), os.path.join("v5_policy", "oracle_signatures_v1.json"))
SPLIT_FILE, SLICE_FILE = "rows.{split}.jsonl", "slices.{split}.jsonl"
StopBuild = S.StopBuild


class GeneratorConfigError(ValueError):
    pass


# ───────────────────────────── generator configuration ─────────────────────────────
GEN_KEYS = {"schema", "mode", "quota", "placement_shares", "length_bins", "encoder_profiles", "oracle",
            "token_budget", "trained_categories", "attack_label_basis", "twins_per_pair", "i9"}


def _status(block, name):
    if not isinstance(block, dict) or block.get("status") not in VALUE_STATUSES:
        raise GeneratorConfigError(f"{name}.status must be one of {VALUE_STATUSES}")
    return block["status"]


def _pos_int(v, name, minimum=1):
    if isinstance(v, bool) or not isinstance(v, int) or v < minimum:
        raise GeneratorConfigError(f"{name} must be an int >= {minimum}")
    return v


def validate_gen_config(cfg: dict) -> dict:
    """Shapes and statuses. PROPOSED / PENDING values are configuration with their status carried
    into the manifest; a real build accepts only RATIFIED values (and is refused today anyway)."""
    if not isinstance(cfg, dict) or set(cfg) != GEN_KEYS:
        raise GeneratorConfigError(f"generator config keys must be exactly {sorted(GEN_KEYS)}")
    if cfg["schema"] != GEN_CONFIG_SCHEMA:
        raise GeneratorConfigError(f"schema must be {GEN_CONFIG_SCHEMA!r}")
    if cfg["mode"] not in ("fixture", "real"):
        raise GeneratorConfigError("mode must be 'fixture' or 'real'")
    statuses = {}
    q = cfg["quota"]
    statuses["quota"] = _status(q, "quota")
    _pos_int(q.get("pairs_per_cluster_category"), "quota.pairs_per_cluster_category")
    _pos_int(q.get("max_attempts_factor"), "quota.max_attempts_factor")
    if set(q) != {"pairs_per_cluster_category", "max_attempts_factor", "status"}:
        raise GeneratorConfigError("quota keys: pairs_per_cluster_category, max_attempts_factor, status")
    ps = cfg["placement_shares"]
    statuses["placement_shares"] = _status(ps, "placement_shares")
    if set(ps) != set(PLACEMENT_MODES) | {"status"}:
        raise GeneratorConfigError(f"placement_shares needs integer weights for {PLACEMENT_MODES}")
    for m in PLACEMENT_MODES:
        _pos_int(ps[m], f"placement_shares.{m}", minimum=0)
    if ps["replace"] < 1:
        raise GeneratorConfigError("placement_shares.replace must be >= 1 (URL / path slots are replace-only)")
    lb = cfg["length_bins"]
    statuses["length_bins"] = _status(lb, "length_bins")
    edges = lb.get("edges")
    if not isinstance(edges, list) or not edges or not all(isinstance(e, int) and not isinstance(e, bool) and e > 0
                                                           for e in edges) or edges != sorted(set(edges)):
        raise GeneratorConfigError("length_bins.edges must be strictly increasing positive ints")
    ep = cfg["encoder_profiles"]
    statuses["encoder_profiles"] = _status(ep, "encoder_profiles")
    if ep.get("weights") != "uniform" or set(ep) != {"weights", "status"}:
        raise GeneratorConfigError("encoder_profiles.weights must be 'uniform' (the only implemented draw)")
    oc = cfg["oracle"]
    statuses["oracle"] = _status(oc, "oracle")
    O.OracleConfig(oc.get("L"), oc["status"])           # refuses L <= 4
    tb = cfg["token_budget"]
    statuses["token_budget"] = _status(tb, "token_budget")
    _pos_int(tb.get("B"), "token_budget.B")
    if tb.get("counter") not in COUNTERS:
        raise GeneratorConfigError(f"token_budget.counter must be one of {COUNTERS}")
    tc = cfg["trained_categories"]
    statuses["trained_categories"] = _status(tc, "trained_categories")
    cats = tc.get("categories")
    allowed = set().union(*K.SLOT_COMPATIBILITY.values())
    if not isinstance(cats, list) or not cats or len(set(cats)) != len(cats) or not set(cats) <= allowed:
        raise GeneratorConfigError(f"trained_categories.categories must be a non-empty subset of {sorted(allowed)}")
    if len({slug(c) for c in cats}) != len(cats):           # the slug is a row_rng / pair_id coordinate (quota)
        raise GeneratorConfigError("trained_categories.categories have colliding slugs; they must be slug-distinct")
    if cfg["attack_label_basis"] not in ("fixture_synthetic", "post_filter_audit"):
        raise GeneratorConfigError("attack_label_basis must be 'fixture_synthetic' or 'post_filter_audit'")
    if cfg["twins_per_pair"] != 1:
        raise GeneratorConfigError("twins_per_pair: only 1 is implemented")
    if cfg["mode"] == "fixture" and cfg["attack_label_basis"] != "fixture_synthetic":
        raise GeneratorConfigError("a fixture build labels synthetic records only (attack_label_basis fixture_synthetic)")
    try:
        V9.validate_i9_config(cfg["i9"])                 # I-9 step-5 rebalancing (spec §4.6; thresholds PROPOSED)
    except V9.RebalanceConfigError as e:
        raise GeneratorConfigError(str(e)) from None
    statuses["i9"] = cfg["i9"]["status"]
    out = json.loads(json.dumps(cfg, sort_keys=True))
    out["_statuses"] = statuses
    return out


def config_sha256(cfg: dict) -> str:
    return hashlib.sha256(I.canonical_json({k: v for k, v in cfg.items() if k != "_statuses"}).encode()).hexdigest()


# ───────────────────────────── real-build preconditions (D64) ─────────────────────────────
# Audit category outcome that admits a category's records (mirror of v5_train_data.OUTCOME_PASS / #80).
OUTCOME_PASS = "PASS_AI_AUDITED"
# D72 ratifies this REAL_BUILD schema definition; a complete committed record
# bound to actual evidence/preregistration is still required for every build.
PROPOSED_REAL_BUILD_AUTH_SCHEMA = "v5-real-build-authorization/v1-PROPOSED"
REAL_BUILD_AUTH_SCHEMA = PROPOSED_REAL_BUILD_AUTH_SCHEMA  # D72; records remain separately required


def _record_category(r: dict):
    """The audit category of a stage-2 attack record, from the first present of the known keys. The R3
    outcomes use the original categories (`path_file_access` unites traversal/file inclusion)."""
    for k in ("attack_category", "category", "dedup_scope"):
        v = r.get(k)
        if isinstance(v, str) and v:
            return v
    return None


def _check_real_build_authorization(auth, preregistration_sha256) -> list:
    """EFFECTIVE validator for the owner's real-build authorization (replaces the old unconditional refusal).
    `auth` is the parsed committed authorization record (a dict), supplied by the real-build caller — never
    invented here. Refused by default until the owner ratifies a schema (REAL_BUILD_AUTH_SCHEMA)."""
    code, d = "REAL_SPLIT_NOT_AUTHORIZED", []
    if REAL_BUILD_AUTH_SCHEMA is None:
        d.append({"code": code, "detail": "no ratified real-build authorization schema exists; a real split/build/"
                  "freeze/training is refused until the owner ratifies one (holds even if a record is supplied)"})
    if not isinstance(auth, dict):
        return d + [{"code": code, "detail": "a real build requires an owner authorization record (none supplied)"}]
    if REAL_BUILD_AUTH_SCHEMA is not None and auth.get("schema") != REAL_BUILD_AUTH_SCHEMA:
        d.append({"code": code, "detail": f"schema {auth.get('schema')!r} != {REAL_BUILD_AUTH_SCHEMA!r}"})
    if auth.get("scope") != "REAL_BUILD":
        d.append({"code": code, "detail": f"scope {auth.get('scope')!r}; must be 'REAL_BUILD'"})
    if preregistration_sha256 and auth.get("preregistration_sha256") != preregistration_sha256:
        d.append({"code": code, "detail": "authorization is not bound to this preregistration (preregistration_sha256)"})
    for k in ("authorized_by", "date", "owner_decision"):
        if not str(auth.get(k, "")).strip():
            d.append({"code": code, "detail": f"field {k!r} is empty"})
    return d


def real_build_preconditions(gen_cfg: dict, records, pools: dict, preregistration_sha256: str | None = None, *,
                             build_authorization=None, category_outcomes=None,
                             build_purpose="REAL_BUILD", split_cfg=None) -> list:
    """Every unmet condition for a real build, as EFFECTIVE validators bound to concrete artifacts/decisions —
    never an unconditional refusal, never a boolean that skips controls. A real build is permitted only when
    this returns empty. Nothing here invents the authorization, the preregistration or the audit outcomes:
    the caller supplies them and they are validated.

    Attack-record eligibility (replaces the old 'VERIFIED for every attack', which is impossible under an
    ai_audit provenance that never confers VERIFIED): a record is eligible when its CATEGORY passed the
    post-filter audit (`category_outcomes[category] == PASS_AI_AUDITED`). A category that did not pass makes
    its records ineligible — they are not forced to VERIFIED and none is silently admitted. With no outcomes
    supplied, eligibility cannot be established and the build is refused."""
    unmet = []
    if gen_cfg.get('mode') != 'real':
        unmet.append({'code':'REAL_BUILD_MODE_REQUIRED','detail':'REAL_BUILD authorization cannot turn a fixture world into real data'})
    if gen_cfg.get('attack_label_basis') != 'post_filter_audit':
        unmet.append({'code':'REAL_BUILD_BASIS_REQUIRED','detail':'real attack rows require post_filter_audit basis'})
    # (A) owner authorization — EFFECTIVE check bound to a committed record (was an unconditional refusal).
    if build_purpose == 'REAL_BUILD':
        unmet += _check_real_build_authorization(build_authorization, preregistration_sha256)
    elif build_purpose == 'PILOT_BUILD':
        unmet += PA.check(build_authorization,generator_sha=config_sha256(gen_cfg),
                          split_sha=S.config_sha256(split_cfg) if split_cfg else None,
                          preregistration_sha=preregistration_sha256,generator_config=gen_cfg)
    else:
        unmet.append({'code':'BUILD_PURPOSE_UNKNOWN','detail':'unknown build purpose'})
    # (B) attack-record eligibility from the SEALED post-filter audit outcomes (was 'VERIFIED for all').
    outcomes = category_outcomes if isinstance(category_outcomes, dict) else None
    if outcomes is None:
        unmet.append({"code": "D64_B_POST_FILTER_AUDIT",
                      "detail": "no post-filter category outcomes supplied: attack-record eligibility cannot be established "
                                "(the sealed R3 category_outcomes must admit each record's category)"})
    else:
        not_admitted = {}
        for r in records:
            cat = _record_category(r)
            if outcomes.get(cat) != OUTCOME_PASS:
                not_admitted[cat] = outcomes.get(cat)
        for cat, got in sorted(not_admitted.items(), key=lambda kv: str(kv[0])):
            unmet.append({"code": "D64_B_POST_FILTER_AUDIT",
                          "detail": f"category {cat!r}: outcome {got!r}; only {OUTCOME_PASS!r} admits its records "
                                    "(rejected categories must not advance the build)"})
    if "names_family" not in pools:
        unmet.append({"code": "D64_C_NAMES_FAMILY",
                      "detail": "names_family is not among the loaded pools (#75): the pinned pool is built but not "
                                "configured/loaded here, or a configuration without it is not yet owner-approved"})
    if not preregistration_sha256:
        unmet.append({"code": "PREREGISTRATION_MISSING",
                      "detail": "L, signatures, placement shares, thresholds, B and the per-file cap are not ratified"})
    for k, st in sorted(gen_cfg.get("_statuses", {}).items()):
        allowed = ('PROPOSED','PENDING','RATIFIED') if build_purpose == 'PILOT_BUILD' else ('RATIFIED',)
        if st not in allowed:
            unmet.append({"code": "VALUE_NOT_RATIFIED", "detail": f"{k}: {st}"})
    # A real build must use the literal D62 §4.6 step-5 reading: WARN is the enforceable reduction
    # trigger. cap="block" would make only the BLOCK band reduce (D65 interpretation), which is not
    # authorized for a real build without an owner ruling — never let it slip through silently.
    i9 = gen_cfg.get("i9", {})
    if i9.get("enabled") and i9.get("cap") != "warn":
        unmet.append({"code": "I9_CAP_NOT_LITERAL",
                      "detail": f"i9.cap={i9.get('cap')!r}; a real build requires cap='warn' (D62: WARN and BLOCK "
                                "both trigger reduction). cap='block' needs a specific owner ruling / r4."})
    return unmet


# ───────────────────────────── the world (identities + their contents) ─────────────────────────────
@dataclass
class World:
    catalog: K.Catalog
    policy: L.PolicyTable
    assignment: S.SplitAssignment
    split_cfg: dict
    gen_cfg: dict
    pool_values: dict             # pool -> {value_entry_id: value}
    records: dict                 # record_id -> stage-2 attack record
    families: dict                # pfid -> v5_identities.Family
    oracle: O.BenignOracle
    basis: L.AttackBasis
    limits: object                # canonical_request.Limits
    count_tokens: object
    row_contract: str | None = None


def slug(category: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", category.lower()).strip("-")


def length_bin(n: int, edges) -> int:
    return sum(1 for e in edges if n >= e)


def ctx_of(slot: K.Slot) -> str:
    if slot.location == "path":
        return "tail" if slot.value_type == "path_file" else "segment"
    return slot.location                          # query | form | json | text


URL_CONTEXTS = ("query", "form", "segment", "tail")


class AttackIndex:
    """Per split: the member records of the split's families, by category, eligible per context."""

    def __init__(self, world: World, part: S.Partition):
        self.world, self.by_cat, self._cache = world, {}, {}
        for cat, pfids in part.families_by_category.items():
            recs = []
            for p in pfids:
                for rid in world.families[p].members:
                    r = world.records[rid]
                    if r["dedup_scope"] == cat:
                        recs.append((rid, p))
            self.by_cat[cat] = sorted(recs)

    def has(self, cat: str) -> bool:
        return bool(self.by_cat.get(cat))

    def binned(self, cat: str, ctx: str) -> dict:
        key = (cat, ctx)
        if key not in self._cache:
            edges = self.world.gen_cfg["length_bins"]["edges"]
            bins = defaultdict(list)
            for rid, p in self.by_cat.get(cat, ()):
                r = self.world.records[rid]
                if ctx in URL_CONTEXTS and r["payload_wire_form"] == R.PRE_ENCODED:
                    if not R.verbatim_ok(R.normalize_hex(r["payload_wire"])[0], ctx):
                        continue
                bins[length_bin(len(r["payload_logical"]), edges)].append((rid, p))
            self._cache[key] = dict(bins)
        return self._cache[key]


def _choice(rng, seq):
    return seq[rng.randrange(len(seq))]


def draw_names(template: K.Template, lexicon: dict, rng) -> dict:
    used = defaultdict(set)
    names = {}
    for key, lst, parent in template.name_sites():
        options = [n for n in lexicon[lst] if n not in used[parent]]
        n = _choice(rng, options)
        used[parent].add(n)
        names[key] = n
    return names


def draw_scalar(slot: K.Slot, rng) -> R.Leaf:
    if slot.value_type == "int":
        return R.Leaf("int", scalar=rng.randint(1, 9999))
    if slot.value_type == "number":
        return R.Leaf("number", scalar=rng.randint(0, 99999) / 100)
    if slot.value_type == "bool":
        return R.Leaf("bool", scalar=rng.randrange(2) == 1)
    if slot.value_type == "enum":
        return R.Leaf.string(R.Part(_choice(rng, slot.choices)))
    if slot.value_type == "token":
        return R.Leaf.string(R.Part(f"{rng.getrandbits(64):016x}"))
    raise K.CatalogError(f"not a scalar slot: {slot.value_type}")


def _modes(slot: K.Slot, benign_value: str, shares: dict) -> list:
    if slot.value_type not in ("free_string", "json_leaf"):
        return ["replace"]
    out = [m for m in PLACEMENT_MODES if shares[m] > 0]
    if len(benign_value) < 2:
        out = [m for m in out if m != "embedded"]
    return out


def _weighted(rng, modes, shares):
    total = sum(shares[m] for m in modes)
    x = rng.randrange(total)
    for m in modes:
        x -= shares[m]
        if x < 0:
            return m
    raise AssertionError("unreachable")


# ───────────────────────────── one pair ─────────────────────────────
def build_pair(world: World, split: str, part: S.Partition, index: AttackIndex, cluster: str,
               templates: list, category: str, i: int) -> dict:
    quota = slug(category)
    rng = I.row_rng(split, cluster, quota, i)
    pid = I.pair_id(split, cluster, quota, i)
    tpls = [t for t in templates if any(category in s.compatible_categories for s in t.attack_slots)]
    t = _choice(rng, tpls)
    profile = _choice(rng, R.PROFILES)
    names = draw_names(t, world.catalog.lexicon, rng)
    leaves, entries = {}, {}
    for s in t.slots:
        if s.attackable:
            pools = [p for p in s.pools if part.values_by_pool.get(p)]
            if not pools:
                raise StopBuild([{"code": "POOL_EMPTY_IN_SPLIT", "detail": f"{split}: no value of {list(s.pools)}"}])
            pool = _choice(rng, pools)
            vid = _choice(rng, part.values_by_pool[pool])
            value = world.pool_values[pool][vid]
            entries[s.slot_id] = (pool, vid, value)
            leaves[s.slot_id] = R.Leaf.string(R.Part(value))
        else:
            leaves[s.slot_id] = draw_scalar(s, rng)
    slot = _choice(rng, [s for s in t.attack_slots if category in s.compatible_categories])
    benign_value = entries[slot.slot_id][2]
    shares = world.gen_cfg["placement_shares"]
    mode = _weighted(rng, _modes(slot, benign_value, shares), shares)
    ctx = ctx_of(slot)
    bins = index.binned(category, ctx)
    if not bins:
        return {"status": "abandoned", "reason": "no_eligible_payload_for_context", "pair_id": pid}
    target = length_bin(len(benign_value), world.gen_cfg["length_bins"]["edges"])
    b = min(bins, key=lambda x: (abs(x - target), x))
    rid, pfid = _choice(rng, bins[b])
    rec = world.records[rid]
    form = rec["payload_wire_form"]
    part_p = R.Part(rec["payload_wire"] if form == R.PRE_ENCODED else rec["payload_logical"], form, True)
    if mode == "replace":
        twin_leaf = R.Leaf.string(part_p)
    elif mode == "prefix":
        twin_leaf = R.Leaf.string(part_p, R.Part(benign_value))
    elif mode == "suffix":
        twin_leaf = R.Leaf.string(R.Part(benign_value), part_p)
    else:
        k = rng.randint(1, len(benign_value) - 1)
        twin_leaf = R.Leaf.string(R.Part(benign_value[:k]), part_p, R.Part(benign_value[k:]))
    twin_leaves = dict(leaves)
    twin_leaves[slot.slot_id] = twin_leaf

    # labels: no field name reaches a label function; the role (inclusion only) is derived first (M-8)
    roles = {s.slot_id: (L.slot_role(names.get(s.key_path), world.policy) if s.names else L.DATA)
             for s in t.attack_slots}
    benign_leaf_labels = {}
    for s in t.attack_slots:
        value = entries[s.slot_id][2]
        benign_leaf_labels[s.slot_id] = L.label_benign_leaf(
            s.value_type, value, roles[s.slot_id], world.oracle.check(value, s.value_type), world.policy)
    attack_label = L.label_attack_leaf(rec, category, slot.value_type, twin_leaf.logical, roles[slot.slot_id],
                                       world.policy, world.basis, world.gen_cfg["trained_categories"]["categories"])
    labels = {"benign": L.combine(list(benign_leaf_labels.values()), world.policy),
              "twin": L.combine([v for k, v in benign_leaf_labels.items() if k != slot.slot_id] + [attack_label],
                                world.policy)}
    rendered = {"benign": R.render(t, names, leaves, profile), "twin": R.render(t, names, twin_leaves, profile)}
    common = {"schema": ROW_META_SCHEMA, "split": split, "pair_id": pid, "quota": quota, "attempt": i,
              "template_id": t.template_id, "template_name": t.name, "struct_cluster_id": cluster,
              "carrier": t.carrier, "method": t.method, "media_type": t.media_type,
              "encoder_profile": profile.profile_id, "field_names": [[list(k), v] for k, v in sorted(
                  names.items(), key=lambda kv: [str(x) for x in kv[0]])],
              "twin_category": category, "attacked_slot": slot.slot_id, "attacked_slot_type": slot.value_type,
              "attacked_slot_role": roles[slot.slot_id], "placement_mode": mode}
    rows = {}
    for role in ("benign", "twin"):
        lab = labels[role]
        can = R.to_canonical(rendered[role], world.limits)
        status, excl, kind, slc = lab.status, lab.exclusion, lab.exclusion_kind, lab.slice
        if can.outcome == "REJECT" and status != L.EXCLUDED:           # R8, evaluated last (§4.3, §5.5)
            status, excl, kind, slc = L.EXCLUDED, L.OVER_LIMIT, None, None
        label = None if status == L.EXCLUDED else lab.label
        ents = [(s.slot_id,) + entries[s.slot_id] for s in t.attack_slots
                if not (role == "twin" and s.slot_id == slot.slot_id and mode == "replace")]
        is_twin = role == "twin"
        meta = dict(common, pair_role=role, label=label,
                    output=L.output_string(lab) if label else None,
                    label_status=status, exclusion_reason=excl, exclusion_detail=(kind or lab.detail or None) if excl else None,
                    slice=slc if excl in L.SLICE_REASONS else None,
                    policy_id=lab.policy_id if status == L.POLICY_DEFINED else None,
                    label_rule=lab.rule if status != L.EXCLUDED else None,
                    attack_category=lab.attack_category if label == L.BLOCK else None,
                    reason_string=lab.reason if label == L.BLOCK else None,
                    payload_family_id=pfid if is_twin else None,
                    payload_record_id=rid if is_twin else None,
                    payload_source_file=rec.get("source_file") if is_twin else None,
                    payload_wire_form=form if is_twin else None,
                    payload_native_forms=list(rec.get("native_forms") or []) if is_twin else [],
                    hex_normalized=R.normalize_hex(rec["payload_wire"])[1] if is_twin and form == R.PRE_ENCODED else False,
                    value_entries=[[e[1], e[2]] for e in ents], values=[e[3] for e in ents],
                    value_slots=[e[0] for e in ents],
                    length_bin=length_bin(len(benign_value), world.gen_cfg["length_bins"]["edges"]),
                    payload_length_bin=b if is_twin else None,
                    signals=list(can.signals), canonical_outcome=can.outcome,
                    leaf_spans={k: list(v) for k, v in sorted(can.leaf_spans.items())})
        if world.row_contract == RC.SCHEMA and label == L.BLOCK:
            meta['label_status_basis'] = lab.label_status_basis or ('policy_defined' if status == L.POLICY_DEFINED else None)
        if can.text is not None:
            meta.update(text_sha256=hashlib.sha256(can.text.encode()).hexdigest(),
                        text_bytes=len(can.text.encode()), tokens=world.count_tokens(can.text),
                        held_out_forms=R.held_out_forms(can.text))
        else:
            meta.update(text_sha256=None, text_bytes=None, tokens=None, held_out_forms=[])
        rows[role] = (meta, can.text, rec["payload_wire"] if is_twin else None)
    # ENC-3: a non-native held-out form abandons the pair (never emitted, counted)
    for role, (meta, text, _) in rows.items():
        extra = sorted(set(meta["held_out_forms"]) - set(meta["payload_native_forms"]))
        if extra:
            return {"status": "abandoned", "reason": "enc3_non_native_held_out_form:" + ",".join(extra),
                    "pair_id": pid}
    included = [r for r in rows.values() if r[0]["label_status"] != L.EXCLUDED]
    complete = len(included) == 2
    for meta, text, _ in rows.values():
        if complete:
            meta["disposition"] = "split"
        elif meta["label_status"] == L.EXCLUDED:
            meta["disposition"] = "slice" if meta["exclusion_reason"] in L.SLICE_REASONS else "excluded_counted"
        else:
            meta["disposition"] = "withheld_sibling"
    return {"status": "complete" if complete else "incomplete", "pair_id": pid, "rows": rows, "template": t}


# ───────────────────────────── the build ─────────────────────────────
def plan_cells(world: World) -> tuple:
    """First pass (no rows): the per-split context and the base quota plan. Returns
    (ctx, cells): ctx[split] = (partition, AttackIndex, {cluster: [templates]}); cells maps
    (split, cluster, category) -> {"carrier", "pairs"} at the base quota (I-9 adjusts `pairs`)."""
    a, cfg = world.assignment, world.gen_cfg
    base = cfg["quota"]["pairs_per_cluster_category"]
    trained = cfg["trained_categories"]["categories"]
    ctx, cells = {}, {}
    for split in S.SPLITS:
        part = a.partition(split)
        index = AttackIndex(world, part)
        by_cluster = defaultdict(list)
        for tid in part.templates:
            by_cluster[a.template_cluster[tid]].append(world.catalog.by_id[tid])
        ctx[split] = (part, index, by_cluster)
        for cluster in part.clusters:
            tpls = sorted(by_cluster[cluster], key=lambda t: t.template_id)
            carrier = tpls[0].carrier                    # one carrier per cluster (cluster_table enforces it)
            cats = sorted(c for c in trained if index.has(c)
                          and any(c in s.compatible_categories for t in tpls for s in t.attack_slots))
            for cat in cats:
                cells[(split, cluster, cat)] = {"carrier": carrier, "pairs": base}
    return ctx, cells


def generate(world: World, plan: dict | None = None, ctx: dict | None = None) -> dict:
    """ONE generation pass over a quota plan (no I-9 here — the I-9 loop lives in `generate_balanced`).
    With no `plan`, the base plan from `plan_cells` is used. `row_rng` / `pair_id` are keyed by the
    attempt index, not the target, so a changed target keeps earlier rows byte-identical (R5)."""
    a, cfg = world.assignment, world.gen_cfg
    factor = cfg["quota"]["max_attempts_factor"]
    if ctx is None or plan is None:
        ctx, cells = plan_cells(world)
        if plan is None:
            plan = cells
    out = {"rows": [], "pairs": Counter(), "abandoned": Counter(), "shortfalls": [], "quota_cells": 0,
           "i9_report": {"enabled": False}}
    for split in S.SPLITS:
        part, index, by_cluster = ctx[split]
        for cluster in part.clusters:
            tpls = sorted(by_cluster[cluster], key=lambda t: t.template_id)
            cats = sorted(c for (s, cl, c) in plan if s == split and cl == cluster)
            for cat in cats:
                target = plan[(split, cluster, cat)]["pairs"]
                if target <= 0:
                    continue
                out["quota_cells"] += 1
                cap = target * factor
                done = i = 0
                while done < target and i < cap:
                    res = build_pair(world, split, part, index, cluster, tpls, cat, i)
                    i += 1
                    if res["status"] == "abandoned":
                        out["abandoned"][res["reason"]] += 1
                        continue
                    out["pairs"][res["status"]] += 1
                    done += res["status"] == "complete"
                    for role in ("benign", "twin"):
                        meta, text, payload = res["rows"][role]
                        out["rows"].append({"meta": meta, "text": text, "payload": payload})
                if done < target:
                    out["shortfalls"].append({"split": split, "cluster": cluster, "category": cat,
                                              "complete": done, "quota": target, "attempts": i})
    return out


# ───────────────────────────── I-9: realised-share rebalance + regenerate (§4.6 step 5) ─────────────────────────────
def realised_cells(gen: dict) -> dict:
    """ADMITTED complete pairs per (split, cluster, category) from a generation pass. Only rows whose
    disposition is `split` count: EXCLUDED rows and abandoned/withheld pairs are not valid dataset rows
    (owner decision, §4.6 step 5). Shape matches `v5_rebalance.rebalance` input."""
    by_pair = defaultdict(dict)
    for r in gen["rows"]:
        m = r["meta"]
        if m["disposition"] == "split":
            by_pair[m["pair_id"]][m["pair_role"]] = m
    cells = defaultdict(lambda: {"carrier": None, "pairs": 0})
    for pid, roles in by_pair.items():
        if set(roles) != {"benign", "twin"}:
            continue                                       # not a complete admitted pair
        m = roles["benign"]
        key = (m["split"], m["struct_cluster_id"], m["twin_category"])
        cells[key]["carrier"] = m["carrier"]
        cells[key]["pairs"] += 1
    return dict(cells)


def realised_share_report(gen: dict, cfg) -> dict:
    """Per split, the realised cluster share over ADMITTED rows, classified against the configured
    (PROPOSED) thresholds. Reports rows and shares; it does not itself stop — `generate_balanced` acts."""
    from fractions import Fraction
    i9 = cfg["i9"]
    warn, block = Fraction(i9["warn_share"]), Fraction(i9["block_share"])
    cap = i9["warn_share"] if i9["cap"] == "warn" else i9["block_share"]
    admitted = [r["meta"] for r in gen["rows"] if r["meta"]["disposition"] == "split"]
    per = defaultdict(Counter)
    for m in admitted:
        per[m["split"]][m["struct_cluster_id"]] += 1
    out, worst = {}, {}
    rulings = set(i9["owner_rulings"])
    for split in S.SPLITS:
        total = sum(per[split].values())
        clusters = {}
        over = []
        for cl, n in sorted(per[split].items()):
            share = Fraction(n, total) if total else Fraction(0)
            klass = V9.classify(share, warn, block)
            clusters[cl] = {"rows": n, "split_rows": total, "share": f"{float(share):.6f}",
                            "class": klass, "owner_ruled": cl in rulings}
            if cl not in rulings and ((i9["cap"] == "warn" and klass in ("WARN", "BLOCK"))
                                   or (i9["cap"] == "block" and klass == "BLOCK")):
                over.append(cl)
        out[split] = {"split_rows": total, "clusters": clusters, "over_cap": over}
        worst[split] = over
    return {"per_split": out, "over_cap_clusters": worst, "cap": i9["cap"], "cap_share": cap,
            "threshold_status": i9["status"]}


def generate_balanced(world: World) -> dict:
    """The I-9 driver (spec §4.6 step 5). Generate; measure the realised cluster share over ADMITTED
    rows; if a cluster exceeds the configured cap, rebalance the quota plan (reduce the over-cap cluster,
    redistribute within its carrier+split, identities and partitions intact) and REGENERATE; repeat.
    Stop (`StopBuild`) if redistribution is impossible, does not converge within `max_rounds`, or needs
    an owner ruling that is not recorded. When I-9 is disabled, this is a single `generate` pass.

    Every round's original quotas, adjusted quotas, realised rows, shares, attempts and outcome are
    recorded in the returned `i9_report`."""
    i9 = world.gen_cfg.get("i9")
    if not i9 or not i9["enabled"]:
        gen = generate(world)
        gen["i9_report"] = {"enabled": False}
        return gen
    ctx, base = plan_cells(world)
    plan = base
    max_rounds = i9["max_rounds"]
    rounds = []
    for r in range(max_rounds):
        gen = generate(world, plan=plan, ctx=ctx)
        realised = realised_cells(gen)
        shares = realised_share_report(gen, world.gen_cfg)
        over = any(shares["over_cap_clusters"].values())
        record = {"round": r,
                  "planned_pairs": {f"{s}|{c}|{cat}": v["pairs"] for (s, c, cat), v in sorted(plan.items())},
                  "realised_pairs": {f"{s}|{c}|{cat}": v["pairs"] for (s, c, cat), v in sorted(realised.items())},
                  "realised_shares": shares["per_split"], "attempts": dict(sorted(gen["pairs"].items())),
                  "abandoned": dict(sorted(gen["abandoned"].items())), "over_cap": shares["over_cap_clusters"]}
        if not over:
            record["outcome"] = "converged"
            rounds.append(record)
            gen["i9_report"] = {"enabled": True, "cap": i9["cap"], "cap_share": shares["cap_share"],
                                "threshold_status": i9["status"], "rounds": rounds,
                                "owner_rulings_applied": [
                                    {"split": split, "cluster": cl, "justification": i9["owner_rulings"][cl]}
                                    for split, split_report in sorted(shares["per_split"].items())
                                    for cl, entry in sorted(split_report["clusters"].items())
                                    if entry["owner_ruled"] and entry["class"] != "OK"],
                                "converged": True}
            return gen
        # rebalance the quota plan on the realised counts (may raise StopBuild: impossible / needs ruling)
        adjusted, rep = V9.rebalance(realised, i9)
        record["outcome"] = "rebalanced"
        record["rebalance"] = {"changed": rep["changed"], "owner_rulings_applied": rep["owner_rulings_applied"]}
        rounds.append(record)
        if not rep["changed"]:
            raise StopBuild([{"code": "I9_REALISED_NOT_CONVERGED",
                              "detail": f"round {r}: clusters still over cap after generation but rebalancing "
                                        "changed nothing (the realised shares cannot be reduced); stopping."}])
        # carry the adjusted counts as the next round's targets; cells realised at 0 keep a 0 target
        plan = {k: {"carrier": base[k]["carrier"], "pairs": adjusted.get(k, {}).get("pairs", 0)}
                for k in base}
        for k, v in adjusted.items():
            if k not in plan:
                plan[k] = {"carrier": v["carrier"], "pairs": v["pairs"]}
    raise StopBuild([{"code": "I9_REALISED_NON_CONVERGENCE",
                      "detail": f"realised cluster shares still exceed the cap after {max_rounds} rounds "
                                "of rebalance+regenerate; stopping (no silent acceptance)."}])


# ───────────────────────────── gates ─────────────────────────────
def _parse_pairs(body: str):
    return [kv.split("=", 1) for kv in body.split("&")] if body else []


def _flatten_json(v, path=()):
    if isinstance(v, dict):
        return [x for i, (k, c) in enumerate(v.items()) for x in _flatten_json(c, path + (("k", i, k),))]
    if isinstance(v, list):
        return [x for i, c in enumerate(v) for x in _flatten_json(c, path + (("a", i),))]
    return [(path, v)]


def verify_pair(b: dict, t: dict, tb: str, tt: str) -> list:
    """C-M2 pair integrity on the emitted text (independent of the renderer's own bookkeeping)."""
    errs = []
    for k in ("split", "pair_id", "template_id", "struct_cluster_id", "carrier", "method", "media_type",
              "encoder_profile", "field_names", "attacked_slot", "placement_mode", "twin_category"):
        if b[k] != t[k]:
            errs.append(f"{k} differs")
    lb, lt = tb.split("\n"), tt.split("\n")
    if lb[0].split(" ")[0] != lt[0].split(" ")[0] or lb[0].rsplit(" ", 1)[1] != lt[0].rsplit(" ", 1)[1]:
        errs.append("request-line method / version differ")
    if b["media_type"] and lb[1] != lt[1]:
        errs.append("Content-Type line differs")
    # exactly one contiguous difference, inside the attacked leaf in both texts
    p = 0
    while p < min(len(tb), len(tt)) and tb[p] == tt[p]:
        p += 1
    s = 0
    while s < min(len(tb), len(tt)) - p and tb[-1 - s] == tt[-1 - s]:
        s += 1
    sid = b["attacked_slot"]
    for name, text, spans in (("benign", tb, b["leaf_spans"]), ("twin", tt, t["leaf_spans"])):
        a0, a1 = spans[sid]
        if tb == tt or not (a0 <= p and len(text) - s <= a1):
            errs.append(f"{name}: difference outside the attacked leaf")
    for k in b["leaf_spans"]:
        if k != sid and tb[slice(*b["leaf_spans"][k])] != tt[slice(*t["leaf_spans"][k])]:
            errs.append(f"non-attacked leaf {k} differs")
    # structural parse: same keys in the same order; exactly one value differs
    carrier = b["carrier"]
    if carrier in ("query", "form"):
        qb = (lb[0].split(" ")[1].split("?", 1)[1] if carrier == "query" else tb.split("\n\n", 1)[1])
        qt = (lt[0].split(" ")[1].split("?", 1)[1] if carrier == "query" else tt.split("\n\n", 1)[1])
        pb, pt = _parse_pairs(qb), _parse_pairs(qt)
        if [x[0] for x in pb] != [x[0] for x in pt]:
            errs.append("parameter names / order differ")
        elif sum(x[1] != y[1] for x, y in zip(pb, pt)) != 1:
            errs.append("not exactly one parameter value differs")
    elif carrier == "json":
        fb = _flatten_json(json.loads(tb.split("\n\n", 1)[1]))
        ft = _flatten_json(json.loads(tt.split("\n\n", 1)[1]))
        if [x[0] for x in fb] != [x[0] for x in ft]:
            errs.append("JSON keys / shape differ")
        elif sum(x[1] != y[1] for x, y in zip(fb, ft)) != 1:
            errs.append("not exactly one JSON leaf differs")
    return errs


def gate_pairs(rows: list) -> dict:
    by = defaultdict(dict)
    for r in rows:
        if r["meta"]["disposition"] == "split":
            by[r["meta"]["pair_id"]][r["meta"]["pair_role"]] = r
    bad, examples = 0, []
    for pid in sorted(by):
        d = by[pid]
        if set(d) != {"benign", "twin"}:
            bad += 1
            examples.append({"pair_id": pid, "errors": ["pair not complete in its split"]})
            continue
        errs = verify_pair(d["benign"]["meta"], d["twin"]["meta"], d["benign"]["text"], d["twin"]["text"])
        if d["benign"]["meta"]["label"] != L.ALLOW or d["twin"]["meta"]["label"] != L.BLOCK:
            errs.append("a complete pair is ALLOW + BLOCK")
        if errs:
            bad += 1
            if len(examples) < 5:
                examples.append({"pair_id": pid, "errors": errs})
    return {"check": "C-M2", "ok": bad == 0, "pairs": len(by), "violations": bad, "examples": examples}


def gate_enc(rows: list) -> dict:
    """ENC-1 (twin leaf holds the payload encoded once / verbatim), ENC-3 (no non-native held-out
    form in any written row), ENC-6 (no lowercase hex triplet)."""
    enc1 = enc3 = 0
    for r in rows:
        m, text = r["meta"], r["text"]
        if m["disposition"] not in ("split", "slice") or text is None:
            continue
        if set(m["held_out_forms"]) - set(m["payload_native_forms"]):
            enc3 += 1
        if m["pair_role"] == "twin" and m["payload_wire_form"] == R.PRE_ENCODED:
            a0, a1 = m["leaf_spans"][m["attacked_slot"]]
            wire = R.normalize_hex(r["payload"])[0]
            if m["carrier"] == "json":
                wire = json.dumps(wire, ensure_ascii=False)[1:-1]
            if wire not in text[a0:a1]:
                enc1 += 1
    return {"check": "ENC-1/ENC-3/ENC-6", "ok": enc1 == 0 and enc3 == 0,
            "enc1_pre_encoded_not_verbatim": enc1, "enc3_non_native_held_out_rows": enc3}


def enc7_self_test(rows: list) -> dict:
    """ENC-7 mutation self-test: injecting `%2527` into a benign row must fire ENC-3 and ENC-4."""
    target = next((r for r in rows if r["meta"]["disposition"] == "split" and r["meta"]["pair_role"] == "benign"), None)
    if target is None:
        return {"check": "ENC-7", "ok": False, "detail": "no benign row to mutate"}
    text = target["text"]
    first = text.index("\n")
    mutated = text[:first].replace(" HTTP/1.1", "") + ("&" if "?" in text[:first] else "?") + "x=%2527 HTTP/1.1" + text[first:]
    fired3 = "double_encoding" in R.held_out_forms(mutated)
    fired4 = R.encoding_features(mutated)["pct25"] > R.encoding_features(text)["pct25"]
    return {"check": "ENC-7", "ok": fired3 and fired4, "enc3_fired": fired3, "enc4_feature_moved": fired4}


def diagnostics(rows: list, split_cfg: dict) -> dict:
    """Reported diagnostics with PROPOSED thresholds (never treated as approved)."""
    written = [r for r in rows if r["meta"]["disposition"] == "split"]
    bal = {}
    for split in S.SPLITS:
        c = Counter(r["meta"]["label"] for r in written if r["meta"]["split"] == split)
        tot = sum(c.values())
        bal[split] = {"ALLOW": c.get(L.ALLOW, 0), "BLOCK": c.get(L.BLOCK, 0),
                      "block_share": f"{c.get(L.BLOCK, 0) / tot:.4f}" if tot else None,
                      "band_PROPOSED": "[0.48, 0.52]"}
    carrier = defaultdict(Counter)
    for r in written:
        carrier[r["meta"]["carrier"]][r["meta"]["label"]] += 1
    feats = defaultdict(Counter)
    for r in written:
        f = R.encoding_features(r["text"])
        cls = r["meta"]["label"]
        feats[cls]["rows"] += 1
        for k, v in f.items():
            feats[cls][k + "_rows"] += bool(v)
    over = Counter((r["meta"]["twin_category"], r["meta"]["pair_role"]) for r in rows
                   if r["meta"]["exclusion_reason"] == L.OVER_LIMIT)
    gen = Counter((r["meta"]["twin_category"], r["meta"]["pair_role"]) for r in rows)
    shares = S.cluster_shares([{"split": r["meta"]["split"], "struct_cluster_id": r["meta"]["struct_cluster_id"]}
                               for r in written], split_cfg) if written else {}
    worst = {s: max((v["class"] for v in d.values()), key=["OK", "WARN", "BLOCK"].index) for s, d in shares.items()}
    lengths = defaultdict(Counter)
    for r in written:
        lengths[r["meta"]["label"]][r["meta"]["length_bin"]] += 1
    return {"class_balance_C-M3": bal,
            "carrier_symmetry_C-S6": {c: dict(sorted(v.items())) for c, v in sorted(carrier.items())},
            "encoding_features_ENC-4_rows_with_feature": {k: dict(sorted(v.items())) for k, v in sorted(feats.items())},
            "over_limit_by_category_role": [{"category": k[0], "role": k[1], "over_limit": over[k], "rows": gen[k]}
                                            for k in sorted(gen)],
            "length_bins_by_class": {k: dict(sorted(v.items())) for k, v in sorted(lengths.items())},
            "cluster_share_step5": {"worst_class_per_split": worst, "status": "PROPOSED thresholds",
                                    "rebalancing": "I-9 implemented in v5_rebalance (opt-in via gen_cfg.i9; thresholds PROPOSED)"},
            "placement_modes": dict(sorted(Counter(r["meta"]["placement_mode"] for r in written
                                                   if r["meta"]["pair_role"] == "twin").items())),
            "encoder_profiles": dict(sorted(Counter(r["meta"]["encoder_profile"] for r in written).items()))}


def gate_rows_for_spl(rows: list) -> list:
    out = []
    for r in rows:
        m = r["meta"]
        if m["disposition"] not in ("split", "slice"):
            continue
        out.append({"split": m["split"], "struct_cluster_id": m["struct_cluster_id"], "template_id": m["template_id"],
                    "pair_id": m["pair_id"], "payload_family_id": m["payload_family_id"],
                    "value_entries": [tuple(x) for x in m["value_entries"]], "values": m["values"],
                    "text": r["text"], "payload": r["payload"]})
    return out


def run_gates(world: World, gen: dict, pool_values_list: dict) -> dict:
    rows = gen["rows"]
    split_meta = [r["meta"] for r in rows if r["meta"]["disposition"] == "split"]
    slice_meta = [r["meta"] for r in rows if r["meta"]["disposition"] == "slice"]
    all_meta = [r["meta"] for r in rows]
    m_split = L.check_m_invariants(split_meta, world.policy, split_rows=True,row_contract=world.row_contract)
    m_slice = L.check_m_invariants(slice_meta, world.policy, split_rows=False,row_contract=world.row_contract)
    m_all = L.check_m_invariants(all_meta, world.policy, split_rows=True,row_contract=world.row_contract)
    m_all_ok = all(m_all[k]["ok"] for k in ("M-1", "M-2", "M-3", "M-5", "M-6", "M-7"))
    spl = SC.run_gates(world.assignment, gate_rows_for_spl(rows), pool_values_list,
                       list(world.records.values()))
    gates = {"M_split_files": m_split, "M_slice_files": m_slice,
             "M_all_generated_rows": {"ok": m_all_ok, **{k: m_all[k] for k in ("M-1", "M-2", "M-3", "M-5", "M-6", "M-7")}},
             "C-M2": gate_pairs(rows), "ENC": gate_enc(rows), "ENC-7": enc7_self_test(rows),
             "SPL": spl}
    gates["ok"] = all(g["ok"] for k, g in gates.items() if k != "SPL") and all(g["ok"] for g in spl.values())
    return gates


# ───────────────────────────── writing ─────────────────────────────
def _jsonl(objs) -> bytes:
    return "".join(I.canonical_json(o) + "\n" for o in objs).encode("utf-8")


def write_outputs(world: World, gen: dict, gates: dict, out_dir: str, extra: dict) -> dict:
    """Split files (`text`, `output`) with line-aligned `.meta.jsonl` sidecars; slice files; counts
    only for every other row (M-4); the stage-3 assignment; a deterministic manifest."""
    SC.guard_output(out_dir)
    os.makedirs(out_dir, exist_ok=True)
    artifacts = []

    def put(name, data):
        with open(os.path.join(out_dir, name), "wb") as fh:
            fh.write(data)
        artifacts.append({"path": name, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)})
    rows = gen["rows"]
    for split in S.SPLITS:
        for disp, pattern in (("split", SPLIT_FILE), ("slice", SLICE_FILE)):
            sel = [r for r in rows if r["meta"]["split"] == split and r["meta"]["disposition"] == disp]
            name = pattern.format(split=split)
            put(name, _jsonl({"text": r["text"], "output": r["meta"]["output"]} for r in sel))
            put(name.replace(".jsonl", ".meta.jsonl"), _jsonl(r["meta"] for r in sel))
    adir = os.path.join(out_dir, "assignment")
    hashes = S.write_assignment(world.assignment, adir)
    for n in ("assignment.jsonl", "manifest.json"):
        artifacts.append({"path": f"assignment/{n}", "sha256": C.sha256_file(os.path.join(adir, n)),
                          "bytes": os.path.getsize(os.path.join(adir, n))})
    manifest = build_manifest(world, gen, gates, artifacts, hashes, extra)
    mdata = (json.dumps(manifest, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode("utf-8")
    with open(os.path.join(out_dir, "manifest.json"), "wb") as fh:
        fh.write(mdata)
    return {"manifest_sha256": hashlib.sha256(mdata).hexdigest(), "artifacts": artifacts}


def build_manifest(world: World, gen: dict, gates: dict, artifacts: list, assignment_hashes: dict, extra: dict) -> dict:
    rows = gen["rows"]
    disp = Counter((r["meta"]["split"], r["meta"]["disposition"]) for r in rows)
    code = C.code_fingerprint([os.path.join(HERE, f) for f in CODE_FILES + DATA_FILES]
                              + [os.path.join(REPO_ROOT, "data_plane", "canonical_request.py")])
    gcfg = {k: v for k, v in world.gen_cfg.items() if k != "_statuses"}
    return {
        "schema": MANIFEST_SCHEMA, "spec": S.SPEC_ID, "generator_version": GENERATOR_VERSION,
        "status": ("FIXTURE — synthetic identities and payloads only; not a V5 dataset; no real split; "
                   "nothing here is VERIFIED in the sense of spec §7" if world.gen_cfg["mode"] == "fixture" else "REAL"),
        "generator_config": gcfg, "generator_config_sha256": config_sha256(world.gen_cfg),
        "value_statuses": world.gen_cfg["_statuses"],
        "split_config_sha256": S.config_sha256(world.split_cfg),
        "assignment": assignment_hashes,
        "catalog": {"sha256": world.catalog.sha256, "lexicon_sha256": world.catalog.lexicon_sha256,
                    "templates": len(world.catalog.templates)},
        "policy_table": {"sha256": world.policy.sha256, "lists_status": "PROPOSED"},
        "oracle": world.oracle.manifest(),
        "token_budget": {"B": world.gen_cfg["token_budget"]["B"], "counter": world.gen_cfg["token_budget"]["counter"],
                         "status": world.gen_cfg["token_budget"]["status"],
                         "max_decoded_body_generator_side": world.limits.max_decoded_body},
        "attack_label_basis": world.basis.mode,
        "i9_rebalance": gen.get("i9_report", {"enabled": False}),
        "counts": {"rows_generated": len(rows),
                   "by_split_disposition": {f"{s}|{d}": n for (s, d), n in sorted(disp.items())},
                   "pairs": dict(sorted(gen["pairs"].items())), "pairs_abandoned": dict(sorted(gen["abandoned"].items())),
                   "quota_cells": gen["quota_cells"], "quota_shortfalls": gen["shortfalls"],
                   "M-9": L.m9_counts([r["meta"] for r in rows])},
        "categories_not_trained": sorted(set().union(*K.SLOT_COMPATIBILITY.values())
                                         - set(world.gen_cfg["trained_categories"]["categories"])),
        "gates": gates, "diagnostics": diagnostics(rows, world.split_cfg),
        "code_fingerprint": code, "environment": C.environment(),
        "artifacts": sorted(artifacts, key=lambda a: a["path"]),
        "known_limitations": known_limitations(world), **extra,
    }


def known_limitations(world: World) -> list[str]:
    """Describe this build's actual scope; never label a source-backed build as a fixture."""
    notes = []
    if world.gen_cfg["mode"] == "fixture":
        notes.append("Synthetic fixture pools and attack records; no real-data claim.")
    else:
        notes.append("Attack labels are AI-audited training references, not independently VERIFIED labels.")
        for cat, row in sorted(world.assignment.evaluability.items()):
            if row["flag"] != S.EVALUABLE and cat in world.gen_cfg["trained_categories"]["categories"]:
                notes.append(f"{cat}: TRAIN-only / NOT_EVALUABLE under D60; no per-category held-out claim.")
    pending = sorted(k for k, status in world.gen_cfg.get("_statuses", {}).items() if status != "RATIFIED")
    if pending:
        notes.append(f"Configuration values not yet ratified: {', '.join(pending)}.")
    if not world.gen_cfg["i9"]["enabled"]:
        notes.append("I-9 realised cluster-share rebalancing disabled; shares are diagnostic only.")
    if world.gen_cfg["token_budget"]["counter"] == "utf8_bytes_upper_bound":
        notes.append("Token counts use the conservative UTF-8 byte upper bound, which can over-exclude rows.")
    notes.append("C-S1–C-S7 shortcut results are diagnostics unless separately checked under ratified thresholds.")
    return notes


def utf8_bytes_upper_bound(text: str) -> int:
    """<= 1 token per byte (§5.5 bound, PENDING re-verification on the V5 tokenizer)."""
    return len(text.encode("utf-8"))


def tokenizer_counter(tok, template):
    """Exact content tokens: len(encode_prompt(content)) - template_overhead (stage-1 additivity)."""
    sys.path.insert(0, os.path.join(REPO_ROOT, "control_plane"))
    import v5_tokenization as T
    overhead = T.template_overhead(tok, template)
    return lambda text: len(T.encode_prompt(tok, template, text)) - overhead


# ───────────────────────────── public authorized-build entry (#82) ─────────────────────────────
R3_EXCHANGE_SCHEMA = "v5-r3-category-outcomes-exchange/v1"
# Generator pools that still have no REAL builder (fixture stand-ins only); names_family IS built (#75).
REAL_POOLS_WITHOUT_BUILDER = ("passwords", "urls_public", "urls_relative", "rel_paths", "addr_data")


def _capture_json(path):
    """Read a JSON record's bytes ONCE: returns (sha256, obj, err). The same bytes are used to verify and to
    decide; a later check never re-reads the file."""
    if not path:
        return None, None, "not provided"
    try:
        C.assert_not_protected(path)
        with open(path, "rb") as fh:
            raw = fh.read()
    except (OSError, SystemExit) as e:
        return None, None, f"{path}: {type(e).__name__}"
    sha = hashlib.sha256(raw).hexdigest()
    try:
        return sha, json.loads(raw), None
    except ValueError as e:
        return sha, None, f"{path}: {e}"


def missing_real_pools(pools) -> list:
    """Pools the candidate config needs for a real build that have NO real builder yet (fixture stand-ins
    only). names_family is built (#75) and so is not listed when loaded."""
    return [p for p in REAL_POOLS_WITHOUT_BUILDER if p not in pools]


def authorized_build(world: World, *, authorization_path, audit_exchange_path, out_dir,
                     preregistration_sha256=None, category_selection=None, pool_values_list=None,
                     extra=None, build_purpose="REAL_BUILD") -> dict:
    """Public authorized-build entry — wires `real_build_preconditions` into a production flow (there was no
    production caller before, only tests). It:
      1. CAPTURES the owner authorization and the SEALED R3 audit exchange ONCE each (same bytes verify+decide);
      2. verifies pinned exchange/report/state/pool bytes and derives category outcomes from the report;
      3. requires EXPLICIT category selection equal to the effective world configuration; each must be
         admitted, i.e. PASS_AI_AUDITED — no rejected category advances the build);
      4. runs `real_build_preconditions` (authorization + eligibility + ratification + names_family + i9);
      5. ONLY if every precondition clears, GENERATES and PERSISTS (generate_balanced → run_gates → write_outputs).
    Refuse-by-default: while `REAL_BUILD_AUTH_SCHEMA` is None no real build proceeds, whatever is supplied.
    Returns {"status":"REFUSED","unmet":[...], …} (nothing written) or {"status":"BUILT", …}. It does NOT
    build real datasets while no schema is ratified; the positive control exercises the wiring on a SYNTHETIC
    world. Real pools still missing are reported in every result (`pools_without_real_builder`)."""
    unmet = []
    auth_sha, auth, auth_err = _capture_json(authorization_path)
    if auth_err:
        unmet.append({"code": "AUTHORIZATION_UNREADABLE", "detail": auth_err})
    elif not AE.is_committed(authorization_path):
        unmet.append({"code":"AUTHORIZATION_NOT_COMMITTED","detail":"build authorization must be committed and unchanged"})
    exch_sha, exch, exch_err = _capture_json(audit_exchange_path)
    outcomes = None
    evidence = None
    audit_components_meta = None
    if isinstance(auth, dict) and auth.get("components") is not None:
        # Component-evidence contract: each world attack record is admitted ONLY by the component that owns its
        # pool AND declares its category. No single pool, no combined PASS. `merged_outcomes` is category->status
        # with each category owned by exactly one component; it drives selection/preconditions/basis just like
        # the legacy single map, but every category traces to its own component's audit.
        rows = [{"meta": {"label": "BLOCK",
                          "attack_category": _record_category(r),
                          "payload_record_id": r.get("record_id"),
                          "payload_wire": r.get("payload_wire")}}
                for r in world.records.values()]
        try:
            resolved = CB.resolve_components(rows, auth["components"], committed_checker=AE.is_committed)
            unmet += [{"code": c, "detail": d} for c, d in resolved["diags"]]
            outcomes = resolved["merged_outcomes"]
            audit_components_meta = resolved["components_meta"]
        except (OSError, ValueError, TypeError) as e:
            unmet.append({"code": "AUDIT_COMPONENT_EVIDENCE", "detail": str(e)})
    elif exch_err:
        unmet.append({"code": "AUDIT_EXCHANGE_UNREADABLE", "detail": exch_err})
    elif not isinstance(auth, dict):
        unmet.append({"code":"AUDIT_EXCHANGE_UNBOUND", "detail":"authorization must pin audit evidence"})
    else:
        try:
            evidence = AE.verify(auth.get('audit_evidence'), records=list(world.records.values()),
                                 captured_exchange=(exch_sha, exch), committed_checker=AE.is_committed)
            outcomes = evidence['category_outcomes']
        except (OSError, ValueError, TypeError) as e:
            unmet.append({"code":"AUDIT_EXCHANGE_UNBOUND", "detail":str(e)})

    trained = list((world.gen_cfg.get("trained_categories") or {}).get("categories", []))
    selection = category_selection
    if (type(selection) is not list or not selection or any(type(c) is not str or not c for c in selection)
            or len(set(selection)) != len(selection)):
        unmet.append({"code":"CATEGORY_SELECTION_INVALID", "detail":"explicit non-empty unique category list required"})
        selection = []
    # A world already contains its assignment, families and quotas. Reject a mismatched
    # selection rather than silently generating under a different configuration.
    if set(selection) != set(trained):
        unmet.append({"code":"CATEGORY_SELECTION_NOT_IN_CONFIG", "detail":"selection must match the effective world's trained_categories; rebuild the world for a subset"})
    if outcomes is not None:
        not_pass = sorted(c for c in selection if outcomes.get(c) != OUTCOME_PASS)
        if not_pass:
            unmet.append({"code": "CATEGORY_SELECTION_NOT_ADMITTED",
                          "detail": f"selected categories without PASS_AI_AUDITED: {not_pass}"})

    unmet += real_build_preconditions(world.gen_cfg, list(world.records.values()), world.pool_values,
                                      preregistration_sha256=preregistration_sha256,
                                      build_authorization=auth, category_outcomes=outcomes,
                                      build_purpose=build_purpose,split_cfg=world.split_cfg)

    meta = {"authorization_sha256": auth_sha, "audit_exchange_sha256": exch_sha,
            "source_report_sha256": exch.get("source_report_sha256") if isinstance(exch, dict) else None,
            "category_selection": sorted(selection), "build_purpose":build_purpose,
            "audit_components": audit_components_meta,   # links each component's pool+outcomes; no joint PASS
            "pools_without_real_builder": missing_real_pools(world.pool_values),
            "pools_loaded": sorted(world.pool_values.keys())}
    if unmet:
        return {"status": "REFUSED", "unmet": unmet, **meta}

    # Configure the proposed r4 emitter on a copy; the caller's World stays intact.
    if world.gen_cfg.get('mode') == 'real':
        training_dir = os.path.join(REPO_ROOT,'scripts','training')
        if training_dir not in sys.path:sys.path.insert(0,training_dir)
        import v5_train_data as TD
        spec = auth.get('dataset_spec')
        problems = []
        if spec not in TD.SUPPORTED_SPECS or 'ai_audited' not in TD.SPEC_AUDIT_TYPES.get(spec,()):
            problems.append({'code':'BUILD_AI_SPEC_NOT_ACTIVE','detail':'dataset_spec is not active for ai_audited data'})
        if auth.get('row_contract') != RC.SCHEMA or RC.TRAINING_REFERENCE not in TD.AI_AUDIT_ROW_STATUS_ALLOWED:
            problems.append({'code':'BUILD_AI_ROW_CONTRACT_NOT_ACTIVE','detail':'training-reference row contract is not ratified/authorized'})
        if problems:return {'status':'REFUSED','unmet':problems,**meta}
        passed = frozenset(c for c,o in outcomes.items() if o == OUTCOME_PASS)
        world = replace(world,basis=L.AttackBasis('post_filter_audit',passed,'ai_audited',RC.SCHEMA),row_contract=RC.SCHEMA)
    # Authorized and eligible → generate + persist.
    gen = generate_balanced(world)
    if world.gen_cfg.get('mode') == 'real':
        # Validate the emitted provenance before persistence. Audit results do
        # not confer VERIFIED; policy-labelled rows keep their existing policy IDs.
        training_dir = os.path.join(REPO_ROOT,'scripts','training')
        if training_dir not in sys.path:sys.path.insert(0,training_dir)
        import v5_train_data as TD
        problems = []
        rows = [{'split':r['meta']['split'],'index':i,'meta':r['meta']} for i,r in enumerate(gen['rows'])]
        problems += [{'code':d.code,'detail':d.detail} for d in TD.check_audit_rows(rows,'ai_audited')]
        if problems:
            return {'status':'REFUSED','unmet':problems,**meta}
    gates = run_gates(world, gen, pool_values_list if pool_values_list is not None else world.pool_values)
    if gates.get('ok') is not True:
        return {"status":"REFUSED", "unmet":[{"code":"BUILD_GATES_FAILED","detail":"generated rows did not pass all gates"}], "gates":gates, **meta}
    audit_extra = {**(extra or {}), "authorized_build":meta, "audit_type":"ai_audited" if world.gen_cfg.get('mode') == 'real' else None,
                   "spec":auth.get('dataset_spec') if world.gen_cfg.get('mode') == 'real' else S.SPEC_ID,
                   "fixture":world.gen_cfg.get('mode') == 'fixture',
                   "row_contract":world.row_contract,
                   "attack_pool_sha256": (evidence['pool_sha256'] if evidence else
                                          auth.get('assembled_pool_sha256') if audit_components_meta is not None else None),
                   "audit_components": audit_components_meta,
                   "audit_evidence": (auth.get('audit_evidence') if audit_components_meta is None else None),
                   "preregistration_sha256":preregistration_sha256}
    audit_extra['build_purpose'] = build_purpose
    if build_purpose == 'PILOT_BUILD':
        audit_extra.update(status='PROVISIONAL_PILOT',calibration_only=True,training_authorized=False)
    wr = write_outputs(world, gen, gates, out_dir, audit_extra)
    return {"status": "BUILT", "gates_ok": gates.get("ok"), **wr, **meta}
