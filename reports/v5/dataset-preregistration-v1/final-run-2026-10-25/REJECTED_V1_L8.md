# Full build v1 rejected at L8

The source-backed REAL_BUILD v1 completed its implemented generator gates (`gates_ok=true`) and emitted manifest SHA-256 `c1e5aa1a344795869f7f1bca85b50ea2169c4b01e08d1dd3825d5a9ce7aaa880` in `datasets/v5_sources/final_source_2026-10-25-v1/`.

The separate pre-freeze L8 audit found **56** V5 value-pool elements also present in the published pool constants of minimal-pair probes v1/v2: names_given 25, names_family 15, streets 7, symbols 9. That violates the required element disjointness. The build is **REJECTED**, is not a training input, and its output remains intact as evidence. No model read it.

The correction filters those elements with NFC+casefold before D-3 value equivalence and split assignment. Only aggregate counts and a SHA-256 of excluded V5 value-entry IDs are recorded; protected probe values are never copied to a training artifact. The attack pool, component audit outcomes, family merges, and D60 split rules are unchanged. A versioned pilot r3 and full build v2 must pass before freeze.
