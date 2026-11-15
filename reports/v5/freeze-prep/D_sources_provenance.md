# D — Sources, licensing and provenance for the V5 training dataset

> **Dated note (2026-10-13).** Superseded where it differs by **D58** and V5 DRAFT r3 §3. Adopted: streets come from the in-repo synthetic lexicon (not TIGER); the third-party deny-list is rule-based (20 files, `README.md` §S3), not the 2-file proposal of §6. This report is kept unchanged as historical evidence.


Issue #64 · Subagent A · date of all checks: **2026-10-11** · branch `research/v5-data-spec-freeze-prep`

Labels: **FACT** = verified against an official source consulted today (URL or local path given).
**INFERENCE** = reasoned from facts. **PROPOSAL** = recommendation, not decided. **UNVERIFIED** = could not be checked (reason stated).
This is a licensing/provenance engineering note, **not legal advice**. Standards-style wording follows the project rule "alignment, not compliance": no claim of certification or legal clearance is made anywhere here.

---

## 1. Summary

1. **Minimal recommended source set (PROPOSAL):** PayloadsAllTheThings (attack pool, with a file-level exclusion list) + Tatoeba **CC0 export** (prose) + Wikidata *given-name / family-name items* (names) + a **hand-written street lexicon authored in this repo** (primary) with US Census TIGER/Line `FEATNAMES` as an optional, verified-usable alternative. GitHub/Stripe OpenAPI specs: statistics only, optional.
2. **Verified (FACT):** PATT is MIT; GitHub and Stripe OpenAPI repos are MIT; Wikidata main-namespace data is CC0; Tatoeba publishes a separate `sentences_CC0` export; Common Voice repo sentence text is stated as CC0 ("majority"); NQ is CC BY-SA 3.0 (HF card); open-appsec Legitimate dataset is Apache-2.0 (its malicious set is mixed, "mostly under MIT").
3. **New finding that changes V4 provenance:** PATT's SQL `Intruder/` folder embeds third-party material that V4's extraction reads (`.txt` files): `FUZZDB_*.txt` (FuzzDB = New BSD + CC BY, **citation required**), `Generic_TimeBased.txt` headed `# from wapiti` (Wapiti repo is **GPL-2.0**), `FUZZDB_Oracle.txt` headed `# contains statements from jbrofuzz`. At least one V4 train row contains a string from `FUZZDB_Oracle.txt`.
4. **CSIC 2010: no licence or terms exist on the (archived) official page**; the live host refused connections today. Its page states values come "from real databases" (names, surnames, addresses) → personal-data risk. **Not TRAIN; at most local report-only evaluation slices; never redistributed.**
5. **TIGER/Line:** in-file metadata says "not copyrighted" with a **required acknowledgement** of the Census Bureau and a trademark note. It is *not* a formal public-domain dedication on the pages fetched. `FEATNAMES` has street names only (no house numbers/cities) → low privacy risk.
6. **Reject:** Natural Questions (CC BY-SA 3.0 share-alike), OpenStreetMap (ODbL share-alike), OpenAddresses (mixed per-source licences + real dwelling addresses), Project Gutenberg as *primary* (archaic register; trademark conditions; keep only as a last fallback).
7. **Mandatory before freeze:** PATT file-level provenance decision (item 3), prose/street/name pool decisions, CSIC TRAIN exclusion, third-party NOTICE policy. **Deferrable:** open-appsec (EVAL v2), GitHub/Stripe API ToS, Gutenberg, OSM/OpenAddresses.
8. **Remaining blockers** are listed in §7 (CSIC live terms and distribution origin, Common Voice per-file status, NQ official page, FuzzDB LICENSE file, WDQS usage policy, Wikidata apostrophe-name yield).

---

## 2. Provenance matrix

Columns: Source | Purpose in V5 | Verified licence (exact) | Evidence (URL/path + short quote) | Restrictions | Recommendation | Blockers.

### 2.1 Attack and structure sources

**PayloadsAllTheThings (PATT)** — pinned `e961fef231d8327bae83b563fab50aec2e6b77c0` (FACT: `git rev-parse HEAD` in `~/PayloadsAllTheThings`, commit date 2026-04-22)

- **Purpose:** attack pool (via `scripts/dataset/parse_dataset_v4.py` `extract_sources`, line ~522-570, which reads fenced blocks of `*.md` and every `*.txt` under 16 category dirs, recording `source` = relative path).
- **Licence (FACT):** MIT License, "Copyright (c) 2019 Swissky". Evidence: local `~/PayloadsAllTheThings/LICENSE:3,5,12` — "Permission is hereby granted, free of charge, to any person"; "shall be included in all copies or substantial portions". Same repo has `DISCLAIMER.md` (educational use, no liability); no other licence file; `README.md` and `CONTRIBUTING.md` contain no licence/copyright clause (grep, 0 hits).
- **Restrictions:** MIT notice must accompany copies/substantial portions (INFERENCE: a generated attack-payload corpus is a derivative of a substantial portion → carry the notice in a THIRD_PARTY_NOTICES file). DISCLAIMER: "only on systems for which they have explicit authorization" (project is an authorized lab: consistent).
- **Third-party content embedded (FACT, local grep, commit above):**
  - `SQL Injection/Intruder/FUZZDB_{MSSQL,MSSQL-WHERE_Time,MSSQL_Enumeration,MYSQL,MySQL-WHERE_Time,MySQL_ReadLocalFiles,Oracle,Postgres_Enumeration}.txt` — file names carry the FuzzDB prefix. FuzzDB README (<https://raw.githubusercontent.com/fuzzdb-project/fuzzdb/master/README.md>, fetched today): "The FuzzDB license is New BSD and Creative Commons by Attribution." and a citation request ("you are required to cite it"). CC BY version not stated there; `…/master/LICENSE` returned HTTP 404.
  - `SQL Injection/Intruder/FUZZDB_Oracle.txt:1` — `# contains statements from jbrofuzz`. jbrofuzz licence: **UNVERIFIED** (not fetched).
  - `SQL Injection/Intruder/Generic_TimeBased.txt:1` — `# from wapiti`. Wapiti repo `LICENSE` (<https://raw.githubusercontent.com/wapiti-scanner/wapiti/master/LICENSE>): "GNU GENERAL PUBLIC LICENSE Version 2, June 1991". Whether a 10-line payload list is copyrightable/derivative is not assessed.
  - Markdown files only *link* to SecLists (`Upload Insecure Files/README.md:128`, `GraphQL Injection/README.md:68`) and `File Inclusion/Intruders/Traversal.txt:854` mentions wfuzz in a comment; no SecLists text embedded was found by grep. Absence of headers elsewhere is not proof of original authorship (INFERENCE): other Intruder files lack provenance comments.
  - 12 distinct commit authors in the clone's history (`git log --format=%an`) → many contributors; the MIT notice names only Swissky (INFERENCE: contributions are licensed by the repo's MIT under normal GitHub terms; not verified).
- **V4 impact (FACT):** `datasets/v4_clean/train.jsonl` contains 1 row with `utl_http.request` (a `FUZZDB_Oracle.txt` line); the extraction code does not exclude `FUZZDB_*`. Origin of that row not traced to a single file (it could also appear in another PATT file).
- **Recommendation:** **TRAIN** (attack pool), subject to the PROPOSAL in §6 item P-1 (path-based exclusion or attribution of `FUZZDB_*.txt`, `Generic_TimeBased.txt`, `FUZZDB_Oracle.txt`). The extraction already records `source`, so a path deny-list is cheap and deterministic.
- **Blockers:** jbrofuzz licence; per-line origin inside PATT; legal reading of GPL "from wapiti" header.

**GitHub REST OpenAPI description** (`github/rest-api-description`)

- **Purpose:** structure / shape statistics only (calibration of field counts, types, nesting).
- **Licence (FACT):** MIT License, copyright GitHub (2020). Evidence: <https://raw.githubusercontent.com/github/rest-api-description/main/LICENSE.md> — "Permission is hereby granted, free of charge, to any person obtaining a copy"; README: "github/rest-api-description is licensed under the MIT license".
- **Restrictions:** notice retained in copies/substantial portions. Statistics (counts, histograms) reproduce no expressive content. Terms of Service of the GitHub API: **UNVERIFIED** (not checked).
- **Recommendation:** optional **statistics only**; no spec text or example values in the dataset. Pin commit (B notes `734bc9c1`, not re-verified today).
- **Blockers:** none for statistics use.

**Stripe OpenAPI** (`stripe/openapi`)

- **Purpose:** same as above.
- **Licence (FACT):** "The MIT License", Stripe, Inc., 2011–present. Evidence: <https://raw.githubusercontent.com/stripe/openapi/master/LICENSE> — "to use, copy, modify, merge, publish, distribute, sublicense, and/or sell"; notice clause "shall be included in all copies or substantial portions". Repo README states no licence/terms for the specs and notes a "custom closed-source generator" (FACT, README fetched today).
- **Restrictions:** as above; MIT covers copyright only, not the Stripe trademark (INFERENCE, general). API ToS **UNVERIFIED**.
- **Recommendation:** optional **statistics only**. **Blockers:** none for statistics.

### 2.2 Benign value pools — names and addresses

**Wikidata** (given-name / family-name items)

- **Purpose:** value pool (person names; recombine first × last).
- **Licence (FACT):** CC0 for main, Property, Lexeme and EntitySchema namespaces. Evidence: <https://www.wikidata.org/wiki/Wikidata:Licensing> — "is released into the public domain under Creative Commons Zero"; same page: other namespaces are CC BY-SA 4.0. <https://www.wikidata.org/wiki/Wikidata:Database_download> cites both CC BY-SA 3.0 and 4.0 for non-data text (version unclear), and lists a 2024-01-01 JSON dump at **130.53 GiB**.
- **What to take (PROPOSAL, based on a live WDQS count today):** items with `wdt:P31 wd:Q202444` (given name) → **32,099** items; `wd:Q101352` (family name) → **699,643** items (FACT: Wikidata Query Service, 2026-10-11, user-agent `firewall-IA-research-licence-check/0.1`). These are *name entities*, not human items (`Q5`), so no individual's record is touched. The labels are main-namespace data (CC0).
- **Restrictions:** none legal for CC0. Personal data: see §4. WDQS usage policy/rate limits **UNVERIFIED**.
- **Recommendation:** **TRAIN** (primary for names). Do **not** download the 130 GiB dump; use a few bounded SPARQL queries and store only the resulting two lists (+SHA-256 + query text + date) in `/tmp` or ignored data dir.
- **Blockers:** yield of names with apostrophes/hyphens/non-ASCII was not measured (the verification query timed out); B's claim of "real apostrophe, hyphen and non-ASCII names" is carried over, not re-verified.

**US Census TIGER/Line** (`FEATNAMES`; also `ADDRFEAT`, `EDGES`)

- **Purpose:** street-name value pool.
- **Licence (FACT, in-file metadata of `tl_2025_01001_featnames.dbf.iso.xml`, downloaded to scratch, 277,243-byte zip, not kept in repo):** "The TIGER/Line Shapefile products are not copyrighted" … "acknowledgement must be given to the U.S. Census Bureau as the source"; also "TIGER/Line and Census TIGER are registered trademarks". Access constraints: None. So the status is **not copyrighted + free use + required acknowledgement + trademark notice**; it is not worded as a CC0/public-domain dedication.
- **Corroboration (FACT):** 17 U.S.C. §105(a), <https://www.law.cornell.edu/uscode/text/17/105> — protection "is not available for any work of the United States Government". The Census web pages I fetched (`/geographies/mapping-files/time-series/geo/tiger-line-file.html`, `/about/policies/open-gov/open-data.html`) state **no** licence or public-domain text, and `…/tiger.html` returned 404.
- **Where the street names are (FACT, measured on county 01001):** `FEATNAMES` DBF fields = `TLID, FULLNAME, NAME, PREDIRABRV, PRETYPABRV, PREQUALABR, SUFDIRABRV, SUFTYPABRV, SUFQUALABR, PREDIR, PRETYP, PREQUAL, SUFDIR, SUFTYP, SUFQUAL, LINEARID, MTFCC, PAFLAG`; 18,308 records, 7.56 MB DBF, rows like `Old Camp Rd`. One zip per county; the `TIGER2025/FEATNAMES/` listing has about 3,200 zip links (3,235 counted incl. non-county links). Typical county zip ≈ 0.3 MB (HEAD request: 277,243 B). `EDGES` for the same county is 3.7 MB zip. `FEATNAMES` has **no house numbers, no city, no ZIP** → no full postal addresses. `MTFCC` allows filtering road classes (also includes non-street features; filter needed).
- **Restrictions:** acknowledgement in notices; do not imply Census endorsement; trademark.
- **Recommendation:** **TRAIN, alternative to the in-repo lexicon (PROPOSAL):** pick a small, pre-registered set of counties (e.g. 5–10 across states) to avoid regional skew; use `FULLNAME` after `MTFCC` filter. Fingerprint: US-English street naming only (INFERENCE).
- **Blockers:** no official "public domain" sentence found on census.gov pages fetched; relies on per-file metadata + §105. Decide whether "acknowledgement" suffices as attribution in a gitignored dataset's manifest (PROPOSAL: yes, plus NOTICE file).

**Alternatives (not recommended)**

- **OpenStreetMap — ODbL (FACT).** <https://www.openstreetmap.org/copyright>: "OpenStreetMap is open data, licensed under the Open Data Commons Open Database License (ODbL)."; "you may distribute the result only under the same license." → share-alike for derived databases; attribution required. **FLAG: reject for TRAIN** (a generated dataset embedding OSM-derived pools may become a derivative database; weights status unsettled).
- **OpenAddresses — mixed (FACT).** <https://www.openaddresses.io/>: "All data is openly licensed." and "Most sources only require attribution" (i.e. per-source terms). Also contains real house-number+street+city records of dwellings (INFERENCE: personal-data risk). **Reject.** Per-source licence audit would be needed.

### 2.3 Benign value pools — natural prose

**Tatoeba** (sentence corpus)

- **Purpose:** prose pool with real punctuation.
- **Licence (FACT):** terms page <https://tatoeba.org/en/terms_of_use> §6.2: text sentences use "the default Creative Commons Attribution 2.0 France license" (CC BY 2.0 FR); reuse "is only allowed if the name of the author is cited". Downloads page <https://tatoeba.org/en/downloads>: "These files are released under CC BY 2.0 FR." and "A part of our sentences are also available under CC0 1.0."; the export `Sentences (CC0)` "Contains all the sentences available under CC0." The terms page itself describes no CC0 subset (CC0 only as an example of a licence change, §6.4). Tatoeba §6.6: "It is forbidden to contribute copyrighted content".
- **CC0 export (FACT, measured today):** `https://downloads.tatoeba.org/exports/sentences_CC0.tar.bz2` = 7,959,741 bytes; extracted `sentences_CC0.csv` = 41,860,119 bytes, tab-separated `id, lang, text, date`, 562,242 rows over all languages; **41,512 English** (`eng`). English subset properties (my measurement on that file): median 46 characters; ASCII apostrophe in 9,861 (23.8%); double-quote in 1,620; comma in 12,632; question mark 4,993; semicolon 825; digits 2,592; `%` 42; `&` 13; `#` 2; no `<`; no `@`, `http(s)://` or `www.` matches; essentially all start with an upper-case letter (1 lower-case start). Extraction left in scratch only.
- **Restrictions:** CC0 file: none legal. The non-CC0 `sentences.csv`/`sentences_detailed` need per-author attribution (CC BY 2.0 FR) → avoid. Personal data: §4.
- **Recommendation:** **TRAIN — primary prose pool (CC0 file only).** Fingerprint risk: translation-learner register, short, with recurring first names (INFERENCE) → cap per-sentence reuse, mix with other text.
- **Blockers:** CC0 status of each sentence relies on the contributor's declaration (terms §6.3/6.6); no independent check.

**Common Voice sentence corpus** (`common-voice/common-voice`, `server/data/<lang>/`)

- **Licence (FACT):** repo code MPL 2.0; README: "This repository is released under MPL (Mozilla Public License) 2.0." and sentence text "released under a CC0 public domain Creative Commons license" for the *majority* of `/server/data` (user submissions + Wikipedia-extractor output); Europarl files are "covered separately". `server/data/en/LICENSE` = "CC0 1.0 Universal" (fetched). Dataset page <https://commonvoice.mozilla.org/en/datasets> returned only the title (no terms).
- **Restrictions:** none for CC0 files; some files outside "majority" (Europarl-style) have other terms. The 24 listed `en` files are contributor-named or wiki-extract files; which of them are CC0 individually is not stated beyond the directory `LICENSE` (INFERENCE: directory LICENSE applies, but the README caveat means verify before using any non-`sentence-collector.txt` file).
- **Recommendation:** **TRAIN, fallback #1 for prose** (only `sentence-collector.txt`, if per-file status is confirmed). Fingerprint: read-aloud sentences, mostly no digits/odd punctuation (INFERENCE, not measured).
- **Blockers:** per-file licence for `en`; the Wikipedia-scraped files (CC BY-SA source text, CC0 claimed via extraction rule) should be **excluded** (INFERENCE).

**Project Gutenberg**

- **Licence (FACT):** most items are US public domain; <https://www.gutenberg.org/policy/permission.html>: "No permission is needed for non-commercial use" of the trademark; commercial use trading on the name triggers royalties. <https://www.gutenberg.org/policy/license.html> §1.C: you may use a US-unrestricted work provided "all references to Project Gutenberg are removed"; outside the US check local law; works posted with a copyright holder's permission need that holder's consent to remove the header. Neither page addresses ML/dataset/bulk use (contact PG).
- **Restrictions:** strip header/footer and every "Project Gutenberg" mention; per-title copyright flag in header; non-US status differs.
- **Recommendation:** **last-resort fallback** only (archaic register, curly quotes, hard-wrapped lines, paragraph-length text → fingerprint risk, INFERENCE). If used: select titles by explicit ID, pre-register, strip, record title IDs.
- **Blockers:** bulk-ML policy not documented on the fetched pages.

**Natural Questions (NQ)**

- **Licence (FACT, secondary):** Hugging Face card <https://huggingface.co/datasets/google-research-datasets/natural_questions> "Creative Commons Attribution-ShareAlike 3.0 Unported" (tag `cc-by-sa-3.0`). Google's official page (`ai.google.com/research/NaturalQuestions/download`) rendered only "Loading…", so the primary source is **UNVERIFIED**.
- **Restrictions:** attribution + share-alike; the "lowercase, punctuation-poor" reason for rejection comes from `B_datasets.md`, not re-measured here.
- **Recommendation:** **reject** (confirmed licence reason, secondary source). **Blocker:** primary-source licence page.

### 2.4 Evaluation / report-only sources

**CSIC 2010 HTTP dataset**

- **Purpose in V5:** excluded from TRAIN; possibly report-only evaluation slices.
- **Licence (FACT: none stated):** official page `http://www.tic.itefi.csic.es/dataset/` — **live host refused the connection today** (`ECONNREFUSED 161.111.32.51:443`; `curl` also failed on http). Read instead from a Wayback snapshot (`web.archive.org/web/2020id_/http://www.tic.itefi.csic.es/dataset/`, 200, 9,246 bytes, page footer "Last update: 20th January 2012"). That snapshot contains **no licence, terms of use, redistribution rule or citation requirement**; it names the authors (Torrano Giménez, Pérez Villegas, Álvarez Marañón), lists references including "An anomaly-based approach for intrusion detection in web traffic" (J. Information Assurance and Security 5(4), 2010) and download links for Normal Traffic (Training), Normal Traffic (Test), Anomalous Traffic (Test). `isi.csic.es/dataset/` archive: 404.
- **Content facts (FACT, same snapshot):** "36,000 normal requests and more than 25,000 anomalous requests"; generated against an e-commerce app developed at CSIC; "All the data (names, surnames, addresses, etc.) are extracted from real databases"; attacks generated with Paros and W3AF; anomalous labels include "Unintentional illegal requests" (non-malicious) — consistent with the project's earlier audit that CSIC labels are heuristic.
- **Restrictions:** absent a licence, copyright default applies (INFERENCE: all rights reserved; academic custom is citation). Repository already treats it as not redistributable (`.gitignore` `/csic_database.csv`; `docs/data_sources.md`). The local `csic_database.csv` (61,065 rows, SHA-256 in `docs/data_sources.md`) is a tabular re-distribution of unknown origin (FACT per `docs/data_sources.md`: distribution not recorded).
- **Recommendation:** **not TRAIN; EVAL (report-only, local, never redistributed) or drop.** Cite as above if used. V4 weights already derive from CSIC rows (FACT: `docs/data_sources.md`) → keep V4 adapter/dataset undistributed.
- **Blockers:** live terms page unreachable; no author permission; unknown distribution origin; personal-data provenance.

**open-appsec WAF Comparison Project**

- **Purpose:** EVAL-ONLY (External v2 candidate; vendor-scored public benchmark → training would break independence, per B2).
- **Licence (FACT):** `https://raw.githubusercontent.com/openappsec/waf-comparison-project/main/README.md`: "The Legitimate Requests Dataset and the Tooling are available under Apache 2.0 license." Malicious set: "a collection of datasets assembled by MGM" "with different copyrights, mostly under MIT." (quote fragments); `…/main/LICENSE` = "Apache License, Version 2.0". The MGM `WAF-Payload-Collection` README: "We do not claim any copyright" and says users must honour each source's licence. README has no anonymisation/personal-data statement (FACT).
- **Restrictions:** Apache-2.0 notices if redistributed (we do not). Personal data inside recordings: B reported e-mail/credential-shaped strings (carried over from B §1.4/1.5; **not re-verified**). Not downloaded (≈1.2 GB).
- **Recommendation:** **EVAL only**; never TRAIN. **Blockers:** privacy review before any use; third-party site content in recordings.

---

## 3. Use matrix (research / train / eval / redistribute)

"Redistribute" = sharing the *generated V5 dataset* (gitignored; pinned by manifest) with the academic advisor and, in the worst case, publishing it. Public repo facts (FACT): `LICENSE` = MIT, "Copyright (c) 2026 SebasHT15"; `.gitignore` ignores `train.jsonl`/`eval.jsonl` at any depth (`git check-ignore -v` confirms `datasets/v4_clean/train.jsonl` and a hypothetical `datasets/v5/train.jsonl`), `/csic_database.csv`, `datasets/hybrid_analyzer_v1/`, `datasets/hybrid_analyzer_v2/`; tracked: dataset *manifests* (`datasets/manifest_*.json`), `datasets/external_v1/` metadata/candidates (not read here), and reports (some with CSIC excerpts, `docs/data_sources.md`). `docs/data_sources.md`: the MIT licence "covers its original code and documentation only".

| Source | Research | Training (weights derived) | Evaluation | Redistribute generated dataset |
|---|---|---|---|---|
| PATT | OK (MIT) | OK; add MIT notice; handle embedded FuzzDB/wapiti files (P-1) | OK | Private sharing OK with notice; public: also FuzzDB citation if its payloads remain |
| GitHub / Stripe OpenAPI | OK (MIT) | statistics only: nothing expressive copied | n/a | OK (only statistics); if spec text were copied, keep MIT notice |
| Wikidata names | OK (CC0) | OK | OK | OK (CC0); no attribution legally required (credit recommended) |
| TIGER FEATNAMES | OK | OK (not copyrighted) | OK | OK with Census acknowledgement; no endorsement claim |
| Tatoeba **CC0 export** | OK | OK | OK | OK (CC0). Do **not** mix in CC BY 2.0 FR rows |
| Common Voice sentences (CC0 files) | OK | OK if per-file CC0 confirmed | OK | OK for confirmed-CC0 files |
| Gutenberg | OK | OK in US after stripping (reference only) | OK | Strip all PG references; US-only reading |
| NQ | OK (attribution) | share-alike implications for dataset; weights status unsettled (INFERENCE) → avoid | OK | Only under CC BY-SA → avoid |
| OSM | OK | ODbL share-alike risk → avoid | OK with attribution | Derived DB must be ODbL → avoid |
| OpenAddresses | per-source | per-source; real addresses → avoid | per-source | per-source → avoid |
| CSIC 2010 | OK (cite) | **no stated licence** → avoid | report-only, local | **No** (no permission); already not redistributed |
| open-appsec Legit. | OK (Apache-2.0) | Not by design (independence) | OK (EVAL-ONLY) | Apache notices; privacy review first; not planned |

INFERENCE on weights: none of the recommended sources imposes share-alike or non-commercial terms; the unresolved attribution items are FuzzDB (cite) and TIGER (acknowledge). No claim is made about legal status of model weights beyond that.

---

## 4. Privacy

| Risk | Where | Assessment | Mitigation (PROPOSAL) |
|---|---|---|---|
| Real person names | Wikidata *person* items | Avoided by design: use only name-entity items (`Q202444`, `Q101352`) | Recombine given × family randomly at generation; never emit a name as it appears for a single person; do not use item descriptions, birth data, or `Q5` items |
| Living persons | Wikidata | Not applicable if only name items used (INFERENCE) | Keep a record of the SPARQL used in the manifest |
| Real addresses | OpenAddresses, OSM, CSIC | OA/OSM contain real house+street+city; CSIC states addresses "extracted from real databases" | Use street names only (TIGER `FULLNAME` or lexicon); generate house numbers and cities synthetically/independently from a closed list of cities that is not paired to the street (avoid `number + street + city` that exists in reality) |
| Sentences with personal info | Tatoeba, Common Voice | Tatoeba CC0 English: 0 matches for `@`/URL/`www.`, but 2,592 sentences contain digits; phone-number/ID patterns not scanned; frequent given names (Tom/Mary style, INFERENCE) | Filter at build: drop digit runs ≥ 6, `@`, URLs, 4-digit+month dates; drop sentences containing capitalised tokens not in a stop/lexicon list if desired; sample, don't dump; keep pools local |
| CSIC personal data | CSIC | Official statement on real-data origin; unknown anonymisation | Do not ship; report-only; do not paste rows into committed reports (existing excerpts: see `docs/data_sources.md`) |
| open-appsec | recordings | No anonymisation statement; credential/e-mail shaped strings (B, not re-verified) | EVAL-ONLY, local, scrub before any export |
| Dataset re-identification via the model | all pools | Low if names are recombined and street names have no house/city pairing | Document the policy in the dataset manifest |

---

## 5. Minimal recommended source set with fallbacks

Target (task): PATT + ≤ 3 benign pools + optional GitHub/Stripe statistics. **PROPOSAL.**

| Component | Primary | Fallback | Fingerprint risk of the fallback |
|---|---|---|---|
| Attack pool | PATT `e961fef`, minus a deny-list (P-1) | PATT without any `Intruder/` `.txt` in the SQL category (use only fenced `.md`) | Lower SQLi diversity; V4 evidence says extraction yields ≥ 2,500 groups (manifest `cap_per_category`), so reduced pool likely still capped; confirm numerically at freeze |
| Pool 1 — person names | Wikidata `Q202444`/`Q101352` label lists (CC0), recombined | Hand-written lexicon authored in this repo (e.g. 300 first, 300 last names, with apostrophe/hyphen/non-ASCII items), licence = repo MIT | **Medium-high:** small closed vocabulary becomes a benign cue; mitigate by large size, random casing variants and by also using the same lexicon in attack-context slots (value-matched controls) |
| Pool 2 — street names | Hand-written street lexicon authored in this repo **or** TIGER `FEATNAMES` for ~5 counties (not copyrighted + acknowledgement) | The other of the two | Lexicon: **medium-high** (grammar `<Name> <Suffix>` is regular). TIGER: medium (real distribution, US-only; abbreviations `Rd`, `St`) |
| Pool 3 — prose | Tatoeba **CC0** English (41,512 sentences, 23.8% with apostrophe) | Common Voice `sentence-collector.txt` (if CC0 confirmed per file); then Gutenberg (stripped) | CV: read-aloud style; Gutenberg: archaic/hard-wrapped (high); synthetic prose templates: **high** (n-gram regularity) — not recommended |
| Structure statistics | GitHub + Stripe OpenAPI (MIT), numeric only | Skip; use hand-picked shapes | Slight loss of calibration |

Notes on hand-written lexicon fallback (FACT: licence = this repo's MIT, `LICENSE`; INFERENCE on fingerprint): a lexicon authored by the project has no third-party licence burden, but any closed list is learnable as a "benign token set"; the check in the spec should include a leave-pool-out test (train on lexicon A, evaluate on lexicon B/real names).

---

## 6. Pre-freeze: mandatory vs deferred

**Mandatory to settle before the spec freeze**

- P-1 **PATT embedded third-party files**: choose deny-list vs attribute. Proposed deny-list by relative path: `SQL Injection/Intruder/FUZZDB_*.txt`, `SQL Injection/Intruder/Generic_TimeBased.txt`. If kept, add FuzzDB citation and the GPL/"from wapiti" risk acceptance in the NOTICE. Record the decision as a numbered D-entry.
- P-2 **Prose pool**: Tatoeba `sentences_CC0` (verified). Pin file SHA-256 and download date.
- P-3 **Names**: Wikidata name-entity lists via bounded WDQS queries (verified licence); confirm apostrophe/hyphen yield before freeze (currently UNVERIFIED).
- P-4 **Streets**: choose lexicon vs TIGER; if TIGER, pre-register counties, MTFCC filter and acknowledgement text.
- P-5 **CSIC**: exclude anomalous and normal from TRAIN (or drop); decide whether any report-only slice stays and under what citation.
- P-6 **NOTICE policy**: a THIRD_PARTY_NOTICES entry (MIT PATT, FuzzDB if kept, Census acknowledgement, Wikidata/Tatoeba CC0 credit); decide what lexicon/pool files may be committed (CC0 and in-repo lexicon: yes; PATT-derived and TIGER-derived: keep ignored, consistent with V4 policy); add an explicit ignore for the V5 dataset directory so differently named files are not committed accidentally.
- P-7 **Manifest fields**: per source: URL, commit/date/SHA-256, licence text, verification date, pool size, filters.

**Can be deferred**

- GitHub/Stripe API Terms of Service (only if specs are fetched; statistics are low risk).
- Common Voice per-file licences (only if used as fallback).
- Gutenberg bulk-use policy (fallback only).
- open-appsec privacy review (External v2, not the V5 train freeze).
- OSM/OpenAddresses/NQ (rejected; no further work).
- Contacting CSIC/ISI for explicit terms (only if CSIC is retained for evaluation in a published artefact).

---

## 7. Blockers (could not verify)

1. **CSIC live terms page** unreachable on 2026-10-11 (ECONNREFUSED); archived 2012-era snapshot has no licence; no author contact done; which distribution of the CSV the repo holds is unrecorded.
2. **Common Voice:** dataset page returned no terms; per-file CC0 status of `server/data/en/*` files is not established; Wikipedia-extracted files exist.
3. **Natural Questions:** Google official page unreadable ("Loading…"); licence confirmed only by the Hugging Face card.
4. **FuzzDB:** repo `LICENSE` returned 404 at the tried path; CC BY version unspecified; jbrofuzz and Wapiti-header scope not legally assessed.
5. **Wikidata:** WDQS usage policy not read; apostrophe/hyphen name yield not measured (query timed out); GFDL/"CC BY-SA" version ambiguity applies only to non-data text.
6. **TIGER:** no explicit "public domain" statement on census.gov pages fetched; acknowledgement obligation derived from in-file metadata of one county file (assumed uniform across files and vintages).
7. **Tatoeba:** CC0 per-sentence status relies on contributor declarations; terms page does not describe the CC0 export.
8. **GitHub/Stripe API ToS** not checked (low relevance for statistics).
9. **open-appsec personal data:** only carried over from B, not re-verified; not downloaded.
10. **Legal:** nothing here is legal advice; GDPR basis for any real-person data (CSIC, open-appsec) not assessed.

---

## 8. Method and limitations

**URLs fetched successfully (2026-10-11):** raw `LICENSE.md` of github/rest-api-description; raw `LICENSE` and `README.md` of stripe/openapi; raw `README.md` of github/rest-api-description; <https://www.wikidata.org/wiki/Wikidata:Licensing>; <https://www.wikidata.org/wiki/Wikidata:Database_download>; Wikidata Query Service (two COUNT queries); FuzzDB `README.md`; Wapiti `LICENSE`; mgm-sp `WAF-Payload-Collection` `README.md`; <https://tatoeba.org/en/terms_of_use>; <https://tatoeba.org/en/downloads>; `downloads.tatoeba.org/exports/` listing and `sentences_CC0.tar.bz2` (7.96 MB, scratch); <https://www.gutenberg.org/policy/permission.html>; <https://www.gutenberg.org/policy/license.html>; Common Voice `README.md` and `server/data/en/` listing and `LICENSE`; <https://www.openstreetmap.org/copyright>; <https://www.openaddresses.io/>; Hugging Face NQ card; open-appsec `README.md` and `LICENSE`; Census `tiger-line-file.html`, `open-data.html`, `www2.census.gov` HEAD requests and one county `FEATNAMES` zip (277 KB, scratch, metadata XML read); <https://www.law.cornell.edu/uscode/text/17/105>; Wayback snapshot of the CSIC page (curl). Local: `~/PayloadsAllTheThings` (LICENSE, README, DISCLAIMER, CONTRIBUTING, Intruder headers, git log), repo `LICENSE`, `.gitignore`, `docs/data_sources.md`, `scripts/dataset/parse_dataset_v4.py`, `datasets/manifest_v4_clean.json`, `datasets/v4_clean/train.jsonl` (string check only).

**Not fetched / failed:** `tic.itefi.csic.es` live (ECONNREFUSED); `fuzzdb/master/LICENSE` (404); `ai.google.com/.../NaturalQuestions/download` (no content); Common Voice dataset page (title only); `census.gov/.../tiger.html` (404); TIGER technical-documentation PDF (binary, not parsed); `web.archive.org` via WebFetch (blocked; used `curl`); jbrofuzz licence; GitHub/Stripe API ToS.

**Data hygiene:** all downloads were placed in the session scratchpad (`tiger_sample/`, `tat/`), not in the repository. `External Test v1` cases were not read. No git write operation was run. Only this file was created.

**Limitations:** WebFetch answers are produced by a small model summarising the page; quotes marked as such were checked against short returned text but long licence texts were not read in full by me. The Tatoeba statistics are my own computation on the downloaded CC0 file and are reproducible from its SHA-256 (not recorded here; PROPOSAL: record it in the V5 manifest).
