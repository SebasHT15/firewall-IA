#!/usr/bin/env python3
"""Build the prospective SQLi v3 source candidate; never reads review votes.

The v2 audit showed classes of source-extraction errors. This stage applies
source-scope and structural rules to every v2 pool record, preserving all prior
records and results. It emits a new population and a deterministic blind sample.
"""
import collections
import hashlib
import json
import pathlib
import re

HERE = pathlib.Path(__file__).resolve().parent
REPO = HERE.parents[3]
SOURCE = REPO / "reports/v5/postfilter-audit/sqli-v2-correction/sqli_corrected_pool.jsonl"
SOURCE_SHA = "2db4db956c43992d809a40f6c798e369fee4f6452eab9aeb61d8dded16ad0748"
SEED = "v5-sqli-v3-quality-2026-10-25"
N = 50

DEFECTS = (
    ("source_code", re.compile(r"(?:\bprint_r\s*\(|\$\w+->(?:execute|prepare)\s*\(|\$\w+\s*=.*\$_(?:GET|POST)|<\?php)", re.I)),
    ("schema_fragment", re.compile(r"^\s*`?\w+`?\s+(?:varchar|char|int|text|date|timestamp)\s*\(", re.I)),
    ("setup_statement", re.compile(r"^\s*(?:CREATE\s+TABLE|exec\s+dbms_java\.grant_permission|\$\$\s+language\b)|\bsp_configure\b", re.I)),
    ("tool_or_prose", re.compile(r"^\s*(?:mysql>|Email:|Username:|--\s|#\s)|\bReturns\s+\d+\b|(?:^|\s)(?:True|False)$", re.I)),
    ("malformed_fused_keyword", re.compile(r"\bSELECTCHAR\s*\(", re.I)),
    ("generic_template_identifier", re.compile(r"\b(?:data_info|data_table|data_column|data_offset|DBNAME)\b|<[A-Z_]+>|\bFROM\s+table_name\b|\bsubstring\(column\s*,", re.I)),
)
MECHANISM = re.compile(
    r"\bUNION\s+(?:ALL\s+)?SELECT\b|"
    r"\b(?:SLEEP|BENCHMARK|WAITFOR|PG_SLEEP|DBMS_PIPE|UPDATEXML|EXTRACTVALUE|xp_cmdshell|LOAD_FILE|OPENROWSET|UTL_FILE|sys_eval|DBMS_XMLGEN|writefile)\s*\(?|"
    r"(?:^|\s)(?:OR|AND)\s+(?:\d+|\w+)\s*(?:=|>|<)|"
    r"\b(?:CAST|CONVERT)\s*\([^\n]*\bAS\s+(?:NUMERIC|INT)\b|"
    r"[\'\";]\s*(?:OR|AND)\b",
    re.I,
)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def classify(record):
    source = record["source_file"]
    wire = record["payload_wire"]
    if (not source.endswith(".md") or source.endswith("/README.md")
            or source.endswith("/Cassandra Injection.md")):
        return "source_scope:wordlist_or_overview_document"
    for name, pattern in DEFECTS:
        if pattern.search(wire):
            return name
    if not MECHANISM.search(wire):
        return "no_recognizable_attack_mechanism"
    return None


def emit(name, obj):
    path = HERE / name
    path.write_bytes((json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode())
    return sha(path.read_bytes())


def main():
    raw = SOURCE.read_bytes()
    assert sha(raw) == SOURCE_SHA
    rows = [json.loads(line) for line in raw.splitlines() if line]
    assert len(rows) == 726 and len({r["record_id"] for r in rows}) == len(rows)
    kept, rejected = [], []
    for row in rows:
        reason = classify(row)
        if reason is None:
            kept.append(row)
        else:
            rejected.append({"record_id": row["record_id"], "source_file": row["source_file"],
                             "payload_wire": row["payload_wire"], "reason": reason})
    assert len(kept) >= N and len(kept) + len(rejected) == len(rows)
    pool_bytes = b"".join((json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n").encode() for r in kept)
    (HERE / "pool.jsonl").write_bytes(pool_bytes)
    pool_sha = sha(pool_bytes)

    by_file = collections.defaultdict(list)
    for row in kept:
        by_file[row["source_file"]].append(row)
    for source in by_file:
        by_file[source].sort(key=lambda row: sha(f"{SEED}\0{source}\0{row['record_id']}".encode()))
    files = sorted(by_file, key=lambda source: (-len(by_file[source]), source))
    exact = {source: N * len(by_file[source]) / len(kept) for source in files}
    quota = {source: int(exact[source]) for source in files}
    left = N - sum(quota.values())
    for source in sorted(files, key=lambda source: (-(exact[source] - quota[source]), source))[:left]:
        quota[source] += 1
    selected = sorted((row for source in files for row in by_file[source][:quota[source]]),
                      key=lambda row: row["record_id"])
    assert len(selected) == len({row["record_id"] for row in selected}) == N
    sample_bytes = b"".join((json.dumps({"record_id": row["record_id"], "source_file": row["source_file"],
                                       "payload_wire": row["payload_wire"]}, ensure_ascii=False, sort_keys=True) + "\n").encode()
                            for row in selected)
    (HERE / "sample_n50.jsonl").write_bytes(sample_bytes)
    sample_sha = sha(sample_bytes)
    diff_sha = emit("removed_diff.json", {"schema": "sqli-v3-source-defect-diff/v1", "input_sha256": SOURCE_SHA,
                                            "removed": len(rejected), "by_reason": dict(collections.Counter(r["reason"] for r in rejected)),
                                            "removed_units": rejected})
    manifest_sha = emit("manifest.json", {"schema": "sqli-v3-source-candidate/v1", "input_path": str(SOURCE.relative_to(REPO)),
                                          "input_sha256": SOURCE_SHA, "input_rows": len(rows), "removed": len(rejected),
                                          "population_rows": len(kept), "population_sha256": pool_sha,
                                          "sample_n": N, "sample_sha256": sample_sha, "seed": SEED,
                                          "by_source_file": dict(collections.Counter(r["source_file"] for r in kept)),
                                          "status": "PROPOSED_NOT_ADMITTED", "training_eligible": False})
    sample_manifest_sha = emit("sample_n50.manifest.json", {"schema": "sqli-v3-audit-sample/v1", "seed": SEED,
                                                        "n": N, "population_sha256": pool_sha, "sample_sha256": sample_sha,
                                                        "allocation_by_file": {source: quota[source] for source in files if quota[source]},
                                                        "sample_ids": [r["record_id"] for r in selected]})
    prereg_sha = emit("preregistration.json", {
        "schema": "v5-source-census-preregistration/sqli-v3-PROPOSED", "status": "PROPOSED_BEFORE_VOTES",
        "source_correction": {"input_sha256": SOURCE_SHA, "rule_source": "build_candidate.py",
                              "source_scope": "SQL Injection Markdown mechanism examples, excluding overview README, Intruder wordlists and Cassandra/CQL",
                              "negative_rules": [name for name, _ in DEFECTS],
                              "positive_rule": "recognizable SQL injection mechanism required; see MECHANISM",
                              "removed_diff_sha256": diff_sha},
        "population": {"path": "pool.jsonl", "sha256": pool_sha, "rows": len(kept), "manifest_sha256": manifest_sha},
        "sample": {"path": "sample_n50.jsonl", "sha256": sample_sha, "rows": N,
                   "manifest_sha256": sample_manifest_sha, "seed": SEED,
                   "method": "source_file stratified, largest remainder; SHA256 rank(seed NUL source_file NUL record_id)"},
        "criteria_r4": {"C1": {"metric": "Wilson95 upper INCORRECT", "limit": 0.20},
                        "C2": {"metric": "Wilson95 upper UNCERTAIN+INCORRECT", "limit": 0.35},
                        "coverage": 1.0, "unresolved_max": 0, "wilson_z": 1.96},
        "reviewers": {"a1": "gpt-6.1-sol", "a2": "gpt-6-astra", "r3": "gpt-6-sol",
                      "procedure": "fresh blind Codex sessions, one fixed sample per role, no fork/history, R3 blind"},
        "relation_to_prior": "v1/v2 votes and failed outcomes preserved, never reused or relabeled",
        "execution_authorized": False, "training_authorized": False,
    })
    checks = ["pool.jsonl", "sample_n50.jsonl", "removed_diff.json", "manifest.json",
              "sample_n50.manifest.json", "preregistration.json", "build_candidate.py"]
    (HERE / "SHA256SUMS").write_text("".join(f"{sha((HERE / name).read_bytes())}  {name}\n" for name in checks))
    print(json.dumps({"population_rows": len(kept), "population_sha256": pool_sha,
                      "sample_n": N, "sample_sha256": sample_sha, "preregistration_sha256": prereg_sha,
                      "removed_by_reason": dict(collections.Counter(r["reason"] for r in rejected))}, sort_keys=True))


if __name__ == "__main__":
    main()
