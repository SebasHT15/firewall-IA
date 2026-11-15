#!/usr/bin/env python3
"""Count-only pre-seal integrity and L7/L8/L9 checks for STAB-HELD."""
from __future__ import annotations

from collections import Counter
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unicodedata

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts/dataset"))
sys.path.insert(0, str(ROOT / "scripts/evaluation"))
sys.path.insert(0, str(ROOT / "data_plane"))
import v5_pilot_inputs as PI  # noqa: E402
import v5_protected_collision_check as PC  # noqa: E402
import minimal_pair_probe_cases as P1  # noqa: E402
import minimal_pair_probe_v2_cases as P2  # noqa: E402
from build_v5_stab_held import chunked_source_wire  # noqa: E402
from canonical_request import parse_canonical  # noqa: E402


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def flatten(item):
    if isinstance(item, str):
        yield item
    elif isinstance(item, (list, tuple, set)):
        for child in item:
            yield from flatten(child)
    elif isinstance(item, dict):
        for child in item.values():
            yield from flatten(child)


def norm(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


def check(directory: Path, pilot_pools: Path, benign_pools: Path, attack_pool: Path) -> dict:
    manifest_path = directory / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    cases_path = directory / "cases.jsonl"
    with cases_path.open(encoding="utf-8") as fh:
        rows = [json.loads(line) for line in fh]
    integrity = sha(cases_path) == manifest["cases_sha256"] and len(rows) == manifest["cases"]
    pair_counts = Counter((r["kind"], r["family"], r["carrier"], r["pair_id"]) for r in rows)
    pair_ok = all(n == 2 for n in pair_counts.values())
    pair_rows = {}
    for row in rows:
        pair_rows.setdefault((row["kind"], row["family"], row["carrier"], row["pair_id"]), []).append(row)
    role_ok = all({r["side"] for r in group} == {"A", "B"} and
                  {r["label"] for r in group} ==
                  ({"ALLOW", "BLOCK"} if group[0]["kind"] == "attack_twin" else {"ALLOW"})
                  for group in pair_rows.values())
    canonical_failures = 0
    for row in rows:
        try:
            parse_canonical(row["text"])
        except (ValueError, UnicodeError):
            canonical_failures += 1
    control = Counter(r["carrier"] for r in rows if r["kind"] == "control" and r["side"] == "A")
    contrast = Counter(r["family"] for r in rows if r["kind"] == "contrast" and r["side"] == "A")
    attack = Counter(r["carrier"] for r in rows if r["kind"] == "attack_twin" and r["side"] == "A")
    chunked = [r for r in rows if r["source_framing"] == "chunked"]
    chunked_ok = len(chunked) == 30 and all(
        r["family"] == "chunked_envelope" and
        hashlib.sha256(chunked_source_wire(r["text"])).hexdigest() == r["source_wire_sha256"]
        for r in chunked)

    own_elements = [norm(r["value_element"]) for r in rows]
    own_elements += [norm(x) for x in ("ledger_note", "ledger_mode", "summary", "/research-stability",
                                      "catalogue-stability.invalid")]
    own_unique = set(own_elements)
    v5_pools, _ = PI.load_pool_values(str(pilot_pools), str(benign_pools))
    v5_elements = {norm(x) for vs in v5_pools.values() for x in vs}
    with attack_pool.open(encoding="utf-8") as fh:
        v5_elements |= {norm(json.loads(x)["payload_wire"]) for x in fh}
    probes = {norm(x) for poolset in (P1.POOLS, P2.POOLS) for x in flatten(poolset)}

    # PC.run applies exactly the same policy for v5_internal_test and
    # v5_stability_heldout in the current registry; assert that equivalence.
    registry = json.loads((ROOT / "reports/v5/freeze-prep/consumed_sets.json").read_text())
    if any(x.get("collision_policy", {}).get("v5_internal_test") !=
           x.get("collision_policy", {}).get("v5_stability_heldout") for x in registry):
        raise ValueError("L7 registry policy differs for INTERNAL_TEST and STAB-HELD")
    with tempfile.TemporaryDirectory() as temp:
        pseudo = Path(temp)
        (pseudo / "manifest.json").write_text(json.dumps({"source_manifest_sha256": sha(manifest_path)}))
        for split in ("TRAIN", "VALIDATION"):
            (pseudo / f"rows.{split}.jsonl").write_text("")
        with (pseudo / "rows.INTERNAL_TEST.jsonl").open("w", encoding="utf-8") as out:
            for row in rows:
                out.write(json.dumps({"text": row["text"]}, ensure_ascii=False) + "\n")
        collisions = PC.run(pseudo)

    return {"schema": "v5-stab-held-preseal-check/v1", "candidate_manifest_sha256": sha(manifest_path),
            "candidate_cases_sha256": sha(cases_path), "integrity": integrity,
            "pair_integrity": pair_ok and role_ok, "canonical_parse_failures": canonical_failures,
            "control_base_pairs": dict(control),
            "chunked_source_envelopes": len(chunked), "chunked_source_hashes_ok": chunked_ok,
            "high_contrast_base_pairs": dict(contrast), "attack_twin_base_pairs": dict(attack),
            "L9_duplicate_own_elements": len(own_elements) - len(own_unique),
            "L9_overlap_v5_pool_elements": len(own_unique & v5_elements),
            "L8_overlap_probe_pool_elements": len(own_unique & probes),
            "L7_blocking_pass": collisions["blocking_pass"],
            "L7_entries": collisions["entries"],
            "preseal_pass": integrity and pair_ok and role_ok and canonical_failures == 0 and chunked_ok
            and all(n >= 100 for n in control.values())
            and len(control) == 3 and len(contrast) == 8 and all(n >= 30 for n in contrast.values())
            and len(attack) == 3 and all(n >= 30 for n in attack.values())
            and len(own_elements) == len(own_unique) and not (own_unique & v5_elements)
            and not (own_unique & probes) and collisions["blocking_pass"]}


def main() -> None:
    import argparse
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("directory", type=Path)
    p.add_argument("--pilot-pools", type=Path, required=True)
    p.add_argument("--benign-pools", type=Path, required=True)
    p.add_argument("--attack-pool", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    a = p.parse_args()
    r = check(a.directory, a.pilot_pools, a.benign_pools, a.attack_pool)
    a.out.write_text(json.dumps(r, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"preseal_pass": r["preseal_pass"],
                      "L9_overlap_v5": r["L9_overlap_v5_pool_elements"],
                      "L8_overlap_probes": r["L8_overlap_probe_pool_elements"],
                      "L7_blocking_pass": r["L7_blocking_pass"]}, sort_keys=True))


if __name__ == "__main__":
    main()
