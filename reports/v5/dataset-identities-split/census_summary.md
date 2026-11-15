# V5 stage 3 — real-pool census (counts only, generated)

Status: DIAGNOSTIC — counts only; no split persisted; pool PENDING_ADJUDICATION.

- Attack pool sha256 `4c5d5869651fff35023d1fa538d1b0b7060751d7e6f4c9f05e76437b08666dbf`, 4139 records; rules `pfid-rules/v3`; SPL-9 representation: set of contiguous 4-grams of Unicode code points of each pre-merge family key/v2.
- Records with an empty family key: 0. Stage-2 identity exclusions (EXCLUDED, in the reconciliation ledger): {'identity_degenerate:command_separator_lost': 6, 'identity_degenerate:digits_only_key': 2, 'identity_undefined:empty_canonical_key': 2, 'identity_unobservable_spl9': 16, 'not_a_payload:isolated_arithmetic': 1, 'not_a_payload:result_table_border': 24}.
- Families: 3754; multi-category 16; with a native held-out form 29; records whose family key would change if NFC were applied first (I-19): 0.

| Category (stage-2 `dedup_scope`) | Records | Families (occurring) | Families (stratum) | Families under v1 rules |
|---|---:|---:|---:|---:|
| CRLF Injection | 22 | 22 | 22 | 22 |
| Command Injection | 422 | 389 | 389 | 394 |
| NoSQL Injection | 62 | 60 | 60 | 60 |
| Open Redirect | 212 | 98 | 98 | 121 |
| SQL Injection | 920 | 877 | 876 | 877 |
| Server Side Request Forgery | 156 | 125 | 121 | 126 |
| Server Side Template Injection | 334 | 332 | 331 | 333 |
| XPath Injection | 31 | 29 | 22 | 29 |
| XSS Injection | 382 | 377 | 373 | 378 |
| path_file_access | 1598 | 1464 | 1462 | 1467 |

## Step-2 projection before any merge (counts; nothing persisted)

| Stratum category | n | R | Outcome | Reserve | TEST | VAL | TRAIN | Foreign counted | Families / TEST counted | Final flag |
|---|---:|---:|---|---:|---:|---:|---:|---:|---|---|
| CRLF Injection | 22 | 2 | NOT_EVALUABLE | 0 | 0 | 0 | 22 | 0 | 22 / 0 | NOT_EVALUABLE |
| Command Injection | 389 | 32 | attempt_1_with_reserve | 32 | 71 | 36 | 250 | 0 | 357 / 71 | EVALUABLE |
| NoSQL Injection | 60 | 5 | NOT_EVALUABLE | 0 | 0 | 0 | 60 | 0 | 60 / 0 | NOT_EVALUABLE |
| Open Redirect | 98 | 8 | NOT_EVALUABLE | 0 | 0 | 0 | 98 | 0 | 98 / 0 | NOT_EVALUABLE |
| SQL Injection | 876 | 71 | attempt_1_with_reserve | 71 | 161 | 81 | 563 | 1 | 806 / 161 | EVALUABLE |
| Server Side Request Forgery | 121 | 10 | NOT_EVALUABLE | 0 | 0 | 0 | 121 | 4 | 125 / 0 | NOT_EVALUABLE |
| Server Side Template Injection | 331 | 27 | attempt_2_no_reserve | 0 | 66 | 33 | 232 | 1 | 332 / 66 | EVALUABLE |
| XPath Injection | 22 | 2 | NOT_EVALUABLE | 0 | 0 | 0 | 22 | 6 | 28 / 0 | NOT_EVALUABLE |
| XSS Injection | 373 | 30 | attempt_1_with_reserve | 30 | 69 | 34 | 240 | 4 | 347 / 69 | EVALUABLE |
| path_file_access | 1462 | 117 | attempt_1_with_reserve | 117 | 269 | 135 | 941 | 2 | 1347 / 269 | EVALUABLE |

## Near-duplicate families (SPL-9 representation, Jaccard ≥ 0.60, all families, no split)

- Family pairs: 17048 (140 across stratum categories); components: 437, holding 2499 families.
- Units after merging every component, by size: {'1': 1255, '2': 206, '3-5': 132, '6-10': 58, '11-50': 33, '51-100': 8, '>100': 0}.
- Unobservable keys (shorter than 4 code points; SPL-9 cannot compare them, gate BLOCKED_UNOBSERVABLE while any exists): 0 (the stage-2 records that had one are EXCLUDED upstream, owner ruling round 3).

| # | Size | Stratum categories | Shortest member | Internal median J | Internal pairs < 0.3 |
|---:|---:|---|---|---:|---:|
| 1 | 90 | {'SQL Injection': 90} | `unionallselect'inj'||'ect'||'xxx'` | 0.943 | 0.0 |
| 2 | 80 | {'SQL Injection': 80} | `orderby0,sleep(0),benchmark(0,md0('a'))` | 0.976 | 0.0 |
| 3 | 78 | {'SQL Injection': 78} | `unionselect@@version,sleep(0),user(),benchmark(0,md0('a')),0` | 0.967 | 0.0 |
| 4 | 76 | {'path_file_access': 76} | `/..//` | 0.429 | 0.346 |
| 5 | 60 | {'path_file_access': 60} | `/logs/access.log` | 0.321 | 0.434 |
| 6 | 57 | {'path_file_access': 57} | `/etc/httpd.conf` | 0.364 | 0.384 |
| 7 | 57 | {'SQL Injection': 57} | `and0=convert(int,(unionallselectchar(0)))` | 0.953 | 0.0 |
| 8 | 52 | {'Server Side Template Injection': 52} | `${self.module.cache.util.os.system("id")}` | 0.427 | 0.191 |
| 9 | 36 | {'path_file_access': 36} | `/..\..\` | 0.5 | 0.192 |
| 10 | 35 | {'path_file_access': 35} | `/logs/error.log` | 0.393 | 0.277 |

Largest component, own stratum families / stratum families: CRLF Injection 3/22, Command Injection 23/389, NoSQL Injection 7/60, Open Redirect 20/98, SQL Injection 90/876, Server Side Request Forgery 9/121, Server Side Template Injection 52/331, XPath Injection 1/22, XSS Injection 19/373, path_file_access 76/1462.

## Step-2 projection if every proposed component became an explicit merge (1692 families; largest merged family = 90 pre-merge families; cross-partition near-duplicate pairs 0; unobservable keys 0)

| Stratum category | n | R | Outcome | Reserve | TEST | VAL | TRAIN | Foreign counted | Families / TEST counted | Final flag |
|---|---:|---:|---|---:|---:|---:|---:|---:|---|---|
| CRLF Injection | 19 | 2 | NOT_EVALUABLE | 0 | 0 | 0 | 19 | 0 | 19 / 0 | NOT_EVALUABLE |
| Command Injection | 179 | 15 | attempt_2_no_reserve | 0 | 36 | 18 | 125 | 0 | 179 / 36 | EVALUABLE |
| NoSQL Injection | 45 | 4 | NOT_EVALUABLE | 0 | 0 | 0 | 45 | 0 | 45 / 0 | NOT_EVALUABLE |
| Open Redirect | 33 | 3 | NOT_EVALUABLE | 0 | 0 | 0 | 33 | 0 | 33 / 0 | NOT_EVALUABLE |
| SQL Injection | 383 | 31 | attempt_1_with_reserve | 31 | 70 | 35 | 247 | 2 | 354 / 70 | EVALUABLE |
| Server Side Request Forgery | 78 | 7 | NOT_EVALUABLE | 0 | 0 | 0 | 78 | 4 | 82 / 0 | NOT_EVALUABLE |
| Server Side Template Injection | 233 | 19 | attempt_2_no_reserve | 0 | 47 | 23 | 163 | 5 | 238 / 49 | EVALUABLE |
| XPath Injection | 19 | 2 | NOT_EVALUABLE | 0 | 0 | 0 | 19 | 5 | 24 / 0 | NOT_EVALUABLE |
| XSS Injection | 271 | 22 | attempt_2_no_reserve | 0 | 54 | 27 | 190 | 7 | 278 / 55 | EVALUABLE |
| path_file_access | 432 | 35 | attempt_1_with_reserve | 35 | 79 | 40 | 278 | 6 | 403 / 79 | EVALUABLE |

## Value pools (equivalence `nfc_casefold/v1` on every group, no hold; precedence PROPOSED)

- Equivalence groups: 56 (within one pool {'names_given': 18, 'prose_en': 3, 'streets': 32}; across pools {'names_given+symbols': 3}); excluded: 56 {'value_equivalence_policy:split_contamination_guard': 1, 'value_equivalent_duplicate': 55}.
- Groups with a recorded semantic difference (not synonyms; excluded by policy): 1 — prose_en `fd9e7ff1b06c6f88` (kept `d8cfc83a205727d5`).
- Precedence (PROPOSED): ['symbols', 'streets', 'names_given', 'names_family', 'prose_en'].

| Pool | Before | After | Excluded | Flag loss (lost/before) | TEST / VAL / TRAIN after | ≥ 20 each |
|---|---:|---:|---:|---|---|---|
| names_given | 26050 | 26029 | 21 | {'has_apostrophe': '3/80', 'has_hyphen': '2/1215', 'has_symbol': '3/80'} | 5206 / 2603 / 18220 | True |
| names_family | — | — | — | — | — | BLOCKED (no pool file) |
| prose_en | 34048 | 34045 | 3 | {'has_apostrophe': '1/9067', 'has_symbol': '1/10439'} | 6809 / 3405 / 23831 | True |
| streets | 12604 | 12572 | 32 | {'has_hyphen': '1/1070', 'non_ascii': '17/1142'} | 2514 / 1257 / 8801 | True |
| symbols | 295 | 295 | 0 | — | 59 / 30 / 206 | True |
