# V5 benign source pools: summary (stage 2, Agent B)

Status (updated 2026-10-14 by the coordinator, after the owner authorized the downloads):
- `prose_en`, `names_given`, `streets` and `symbols` are BUILT from pinned inputs.
- `names_family` is **BLOCKED**. WDQS was under an outage rule: it returned HTTP 429 (1 request per minute) and then truncated JSON at LIMIT 200000, 50000 and 15000 alike. Nothing was substituted for the missing source.

## Files
- `scripts/dataset/build_v5_benign_pools.py` (stdlib only): sub-commands `acquire` and `build`.
- `scripts/dataset/v5_lexicon/streets_v1.json`, `benign_symbols_v1.json` (repo-authored, MIT, `notes` document the risks).
- `tests/test_v5_benign_pools.py` (55 tests) and `tests/fixtures/v5_benign/` (invented text, real column layout, valid sidecars).
- Shared helpers: `scripts/dataset/v5_pools_common.py`. Output (gitignored): `datasets/v5_sources/benign/`.

## Pools
| pool_id | source | licence | state | accepted |
|---|---|---|---|---|
| `names_given` | Wikidata given-name items (Q202444), labels `en`/`mul`; response sha256 `d72e4e9c…`, 42,233 bindings, retrieved 2026-10-14T19:56:12Z | CC0-1.0 | BUILT | 26,050 |
| `names_family` | Wikidata family-name items (Q101352), same labels | CC0-1.0 | **BLOCKED** (WDQS outage) | n/a |
| `prose_en` | Tatoeba `sentences_CC0` (CSV sha256 `7aa76236…`, 41,860,119 B, retrieved 2026-10-14T04:32:18Z), `eng` only | CC0-1.0 | BUILT | 34,048 |
| `streets` | `streets_v1.json` expansion | MIT (repo) | BUILT | 12,604 |
| `symbols` | `benign_symbols_v1.json` | MIT (repo) | BUILT | 295 (298 listed, 3 exact duplicates dropped) |

Record: `pool_id, value (NFC), value_entry_id = sha256(pool_id NUL NFC(value)), source_id, source_ref, license, status, exclusion_reason, flags` (+ `source_lang` for names and prose). Flags describe and never filter. Excluded rows go to `benign_excluded.jsonl`.

## Filters (first matching reason wins, deterministic order)
- Names: `empty`, `control_char` (Cc/Cf/Zl/Zp), `contains_digit`, `parenthesis_or_disambiguation`, `at_or_url`, `contains_colon`, `non_name_char` (only letters, marks, `'`, U+2019, `-`, `.`, space allowed), `too_long` (> 40), `looks_like_full_name` (given: 2+ capitalised tokens), `too_many_tokens` (family: > 4), `duplicate_value` (first by QID order kept), `malformed_row`.
- Names: also `descriptive_label` (labels containing "name", e.g. "female given name") and `not_capitalised` (given names only; family names such as "van der Berg" may start lowercase). Both were added after the independent review.
- Prose (`eng`, configurable and recorded): `empty`, `control_char`, `too_short` (< 3), `too_long` (> 200), `email_like`, `at_sign`, `url_like` (scheme, `www.`, bare common TLD), `digit_run_ge6`, `phone_like` (>= 8 digits with optional separators), `dated_event` (4-digit year with a month name), `possible_full_name`, `duplicate_value` (first by id kept), `malformed_row`, `invalid_utf8`.
  - `possible_full_name`: two adjacent capitalised words. It was added because the independent review found sentences that name real people with health or political claims. It is conservative and also drops place names. Single first names are kept. SQL/shell homonyms, `--`, `;`, `a<b` are kept on purpose (spec 2.1).
- Streets and symbols: `empty`, `control_char`, `duplicate_value` (symbols also `at_or_url`).
- Oracle, `--attack-pool PATH`: `oracle_exact_collision` when V4 `canonical_key(value)` equals an attack-pool `canonical_key`. Containment (length L) and breakout signatures are PENDING and implemented nowhere; the manifest says so.
- Survival fixture (`O'Neil`, `Apt #4`, `AT&T`, `100%`, `a<b`): the build exits 3 if any is not ACCEPTED. It passes with and without an attack pool.

## Measured counts (streets and symbols, real build)
- `streets`: 12,604 distinct strings (>= 2,000 required); apostrophe 938, hyphen 1,070, non-ASCII 1,142, digit 3,029, symbol 1,299. By pattern: English plain 6,672, Spanish plain 960, French 738, Portuguese 362, Italian 288, German 256, Dutch 78, directionals 520, unit designators 856, cross streets 333, numbered roads 1,512, fixed phrases 29.
- `symbols`: apostrophe 58, hyphen 39, non-ASCII 3, digit 111, symbol 275 of 295.
- Pool sizes against the 200 minimum of spec 4.6 step 3 (report only): every BUILT pool meets it.
- `names_given` (real build): 26,050 accepted, 42,233 rows read.
  - Exclusions: duplicates 15,628 (`en` and `mul` labels are often identical), `looks_like_full_name` 248, `not_capitalised` 223, disambiguation 58, `non_name_char` 13, digit 7, `too_long` 3, `descriptive_label` 2, colon 1.
  - Measured yield: apostrophe 83, hyphen 1,215, non-ASCII 2,387.
- `prose_en` (real build): 34,048 accepted of 41,524 English rows.
  - Exclusions: `possible_full_name` 4,107, `too_long` 3,303, `dated_event` 43, `malformed_row` 12, `url_like` 6, `phone_like` 3, `digit_run_ge6` 1, `control_char` 1.
  - The pre-review count, before the full-name filter, was 38,155.
- Oracle exact rule against the 4,163-record attack pool: 0 collisions.
- Determinism: two full builds produced byte-identical pool files and manifest. Independent review D also rebuilt them identically.
- Fixture builds (tests only): given 7, family 6, prose 6 accepted.
- Wikidata yield is measured for given names only (above). The family-name yield is PENDING (BLOCKED).

## Acquisition (authorized by the owner 2026-10-14; Tatoeba and given names done, family names BLOCKED)
```
python3 scripts/dataset/build_v5_benign_pools.py acquire --dry-run          # plan only, no network
python3 scripts/dataset/build_v5_benign_pools.py acquire --yes-download     # only once authorized
python3 scripts/dataset/build_v5_benign_pools.py build [--attack-pool datasets/v5_sources/attack/attack_pool.jsonl]
```
- Tatoeba: `https://downloads.tatoeba.org/exports/sentences_CC0.tar.bz2` (about 7.96 MB measured earlier). One member is extracted, rejecting absolute paths, `..`, backslashes, links and devices. Pins: the archive and the CSV.
- Wikidata: WDQS `https://query.wikidata.org/sparql` (`format=json`), User-Agent `firewall-IA-v5-dataset/0.1 (research; contact via repo)`; given-name query LIMIT 100000, family-name query LIMIT 50000 (lowered from 200000 after truncated responses; see the comment in the code), exact text in the code and in each sidecar. No ORDER BY, so when LIMIT binds the subset is arbitrary and pinned by SHA-256.
- Each raw file gets `<file>.source.json` {url, retrieved_at (UTC, once), sha256, bytes, licence, licence_evidence_url, query}. Limits: 64 MiB archive, 256 MiB extracted, 128 MiB per SPARQL response; timeouts 120 to 300 s. Existing pins are never overwritten.
- `build` refuses a file without a sidecar, a sha256 or size mismatch, or a WDQS sidecar whose query differs from the code.

## Privacy policy
- Names: name items only (never Q5, descriptions, dates or person properties); given and family are separate pools, recombined at generation, never as one person's record.
- Prose: long digit runs, phone-like numbers, e-mail, URLs, dated events and possible full names are removed. Tatoeba's recurring single first names ("Tom", "Mary") are not filtered (known limitation).
- Streets: no house number and no city in any value; no real postal record. Pools are local and gitignored; protected paths are refused.

## Spec notes and ambiguities
- Spec 4.6 names one "names" pool; D58 says given and family are recombined, so two leaf pools (`names_given`, `names_family`) are produced. The owner should confirm which pool ids enter `value_entry_id`.
- The spec says "pin a query snapshot by SHA-256", but a LIMITed unordered query is not reproducible; the response hash is the pin.
- Fingerprint risk of the street grammar and English skew (66% of the pool) are documented in the lexicon `notes`; a per-language cap is needed at sampling time.
- `canonical_key` decodes `+` to a space (so `C++` becomes `c`); a short attack key could collide with such benign values.

## Tests
`python3 -m unittest tests.test_v5_benign_pools -v` : 60 tests, OK, offline (`urlopen` is patched to raise).
