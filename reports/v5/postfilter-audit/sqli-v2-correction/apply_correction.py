#!/usr/bin/env python3
"""Reproducible SQLi v2 source/filter correction stage (PROPOSED — no commit, no vote).

Input : the FROZEN post-filter attack pool (hash-verified). This stage applies GENERAL, uniformly-applied
        structural defect classes to the accepted SQL Injection records and emits the corrected pool, a diff
        per record_id, a manifest with hashes/distribution, and the stratified n=50 audit sample fixed by the
        preregistered seed. It consumes NO PF2 votes to pick units.
Run   : python3 -I reports/v5/postfilter-audit/sqli-v2-correction/apply_correction.py
Defect classes (remove), general and vocabulary-based (NOT per-unit):
  C1_cli_argument       payload is a CLI invocation, not a SQL payload: starts with '--' or contains ' --flag='
                        (e.g. sqlmap '--proxy="..."'). Credential placeholders like [username] ride inside these.
  C2_placeholder_token  a bracketed token from the fixed sqlmap placeholder vocabulary (SLEEPTIME, RANDNUM,
                        RANDSTR, INFERENCE, BOOLEAN_QUERY, INJECT HERE, ORIGVALUE, GENERIC_SQL_COMMENT, ...).
  C3_placeholder_literal 'your ... here', 'path/to', 'C:\\path\\to', bare 'blah'.
  C4_source_code        defensive/source code line: $x=...$_GET/$_POST/... , check_addslashes, function(.
  C5_doc_token          a bare ALL-CAPS single token (e.g. COLLATIONS) or a tool prompt ('MariaDB [dummydb]>').
KEEP  : ordinary T-SQL bracket identifiers ([users], [TESTING], [dummydb]) — NOT in the sqlmap vocabulary.
"""
import json, re, hashlib, os, sys, collections

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(HERE))))
POOL = os.path.join(REPO, "datasets/v5_sources/attack/attack_pool.jsonl")
POOL_SHA = "ba385fa256d5e5c5f591d4055ab272136eb4d14415de86a21dcd95a3b88c0f21"
SEED = "v5-sqli-v2-corrected-2026-10-25"      # fixed a priori, before any vote
N = 50

SQLMAP_TOKENS = ("SLEEPTIME", "SLEEP_TIME", "RANDNUM1", "RANDNUM", "RANDSTR", "INFERENCE", "BOOLEAN_QUERY",
                 "INJECT HERE", "ORIGVALUE", "GENERIC_SQL_COMMENT", "DELIMITER_START", "DELIMITER_STOP",
                 "QUERY", "PAYLOAD", "COLUMN", "TABLE", "DATABASE_NAME")
C1 = re.compile(r'(^|\s)--[a-z][a-z0-9-]+(=|\s|$)')
C2 = re.compile(r'\[(' + '|'.join(re.escape(t) for t in SQLMAP_TOKENS) + r')\]')
C3 = re.compile(r'(your [^\n]*? here|path/to|C:\\\\?path\\\\?to|(^|\W)blah(\W|$))', re.I)
C4 = re.compile(r'\$\w+\s*=.*\$_(GET|POST|REQUEST|SERVER|COOKIE)|check_addslashes|function\s*\(')
C5_DOC = re.compile(r'^[A-Z][A-Z_]{3,}$')
C5_PROMPT = re.compile(r'^\w+ \[[^\]]+\]>')


def classify(w):
    s = w.strip(); out = []
    if C1.search(w): out.append("C1_cli_argument")
    if C2.search(w): out.append("C2_placeholder_token")
    if C3.search(w): out.append("C3_placeholder_literal")
    if C4.search(w): out.append("C4_source_code")
    if C5_PROMPT.search(s): out.append("C5_doc_token")
    elif C5_DOC.match(s): out.append("C5_doc_token")
    return out


def sha(b): return hashlib.sha256(b).hexdigest()


def main():
    raw = open(POOL, "rb").read()
    assert sha(raw) == POOL_SHA, "input pool hash mismatch"
    sq = [json.loads(l) for l in raw.split(b"\n") if l.strip() and json.loads(l).get("category_v4") == "SQL Injection"]
    removed, kept = [], []
    for r in sq:
        cl = classify(r["payload_wire"])
        (removed if cl else kept).append((r, cl))

    corrected = [r for r, _ in kept]
    blob = "".join(json.dumps(r, ensure_ascii=False, sort_keys=True) + "\n" for r in corrected).encode()
    corr_sha = sha(blob)
    open(os.path.join(HERE, "sqli_corrected_pool.jsonl"), "wb").write(blob)

    diff = [{"record_id": r["record_id"], "source_file": r["source_file"],
             "payload_wire": r["payload_wire"], "defect_classes": cl} for r, cl in removed]
    json.dump({"schema": "sqli-v2-defect-diff/v2", "source_pool_sha256": POOL_SHA,
               "accepted_before": len(sq), "removed": len(removed), "corrected": len(corrected),
               "classes": dict(collections.Counter(c for _, cl in removed for c in cl)),
               "removed_units": diff},
              open(os.path.join(HERE, "removed_diff.json"), "w"), ensure_ascii=False, indent=2)

    dist = dict(collections.Counter(r["source_file"] for r in corrected))
    json.dump({"schema": "sqli-v2-corrected-pool-manifest/v2-PROPOSED", "source_pool": "datasets/v5_sources/attack/attack_pool.jsonl",
               "source_pool_sha256": POOL_SHA, "corrected_pool": "sqli_corrected_pool.jsonl",
               "corrected_pool_sha256": corr_sha, "accepted_before": len(sq), "removed": len(removed),
               "corrected": len(corrected), "by_source_file": dist, "status": "PROPOSED_NOT_SEALED",
               "training_eligible": False},
              open(os.path.join(HERE, "manifest.json"), "w"), ensure_ascii=False, indent=2)

    # --- deterministic stratified n=50 sample over the corrected pool (seed fixed a priori) ---
    by_file = collections.defaultdict(list)
    for r in corrected:
        by_file[r["source_file"]].append(r)
    for f in by_file:
        by_file[f].sort(key=lambda r: hashlib.sha256(f"{SEED}\x00{r['source_file']}\x00{r['record_id']}".encode()).hexdigest())
    files = sorted(by_file, key=lambda f: (-len(by_file[f]), f))
    total = len(corrected)
    # largest-remainder proportional allocation, then top-ranked per file
    quota = {}
    rema = []
    assigned = 0
    for f in files:
        exact = N * len(by_file[f]) / total
        quota[f] = min(len(by_file[f]), int(exact))
        assigned += quota[f]
        rema.append((exact - int(exact), f))
    for _, f in sorted(rema, reverse=True):
        if assigned >= N: break
        if quota[f] < len(by_file[f]):
            quota[f] += 1; assigned += 1
    sample = []
    for f in files:
        sample.extend(by_file[f][:quota[f]])
    sample.sort(key=lambda r: r["record_id"])
    sample_ids = [r["record_id"] for r in sample]
    sblob = "".join(json.dumps({"record_id": r["record_id"], "source_file": r["source_file"],
                                "payload_wire": r["payload_wire"]}, ensure_ascii=False, sort_keys=True) + "\n"
                    for r in sample).encode()
    open(os.path.join(HERE, "sample_n50.jsonl"), "wb").write(sblob)
    json.dump({"schema": "sqli-v2-audit-sample/v1-PROPOSED", "seed": SEED, "n": len(sample),
               "method": "stratified by source_file; within file rank by sha256(seed NUL source_file NUL record_id); largest-remainder proportional allocation",
               "corrected_pool_sha256": corr_sha, "sample_sha256": sha(sblob),
               "allocation_by_file": {f: quota[f] for f in files if quota[f]},
               "sample_ids": sample_ids},
              open(os.path.join(HERE, "sample_n50.manifest.json"), "w"), ensure_ascii=False, indent=2)

    print(json.dumps({"accepted_before": len(sq), "removed": len(removed), "corrected": len(corrected),
                      "classes": dict(collections.Counter(c for _, cl in removed for c in cl)),
                      "corrected_pool_sha256": corr_sha, "sample_n": len(sample),
                      "sample_sha256": sha(sblob)}, indent=2))


if __name__ == "__main__":
    main()
