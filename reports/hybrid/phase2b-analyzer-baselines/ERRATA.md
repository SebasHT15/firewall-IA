# Run-001 — errata and status (added 2026-10-03, after run-001)

This folder is the frozen record of Phase 2B **run-001** (`hybrid_analyzer_v1`, D51). Its files
are not edited; `SHA256SUMS` still verifies them. Corrections and later status live here.

| # | Where | Recorded | Correct | Effect |
|---|---|---|---|---|
| 1 | `frozen_selection.json` → `rationale` | HGB leads the category on "6 of 8" classes | **7 of 8** (only `ssrf` is better under RF on VALIDATION, 0.508 vs 0.480) | none on any metric; a counting error in free text. Already noted in `README.md` §8 |
| 2 | `README.md` §10, `validation_sibling_diagnostic.json` | 556 / 4,980 VALIDATION rows (11.2%) with a generator-group sibling in TRAIN (proxy: exact for CSIC, approximate for synthetic attacks) | **646 / 4,980 (13.0%)**, 520 generator groups split across TRAIN / VALIDATION, measured with the generator groups recovered exactly by byte-identical regeneration (`scripts/dataset/recover_v4_provenance.py`). CSIC counts were exact (95 + 132); the attack proxy undercounted (329 → 419) | the finding is stronger than reported; conclusions unchanged |

**Status.** Run-001 was not frozen. The grouping defect is corrected by **D54**
(`hybrid_analyzer_v2`), and the Analyzer is re-selected in **run-002**:
[`../phase2b-analyzer-v2-run-002/`](../phase2b-analyzer-v2-run-002/). INTERNAL TEST was read
once here; run-002's test is its labelled second look.
