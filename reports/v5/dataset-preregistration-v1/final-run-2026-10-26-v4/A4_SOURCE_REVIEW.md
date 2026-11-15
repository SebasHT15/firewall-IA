# A4 — v4 sources, retained provenance and licences

V4 contains only byte-identical subsets of the v3 admitted attack/source pools; no payload text was rewritten and no new source was introduced. `source-hygiene-ledger.json` records 12 attack exclusions and one symbols exclusion, with hashes. The build checks every retained attack against its own original path, census or SQLi-v3 component; no combined PASS.

The parent A4 review is `reports/v5/dataset-preregistration-v1/final-run-2026-10-25-v3/A4_SOURCE_REVIEW.md`. Its limits remain: PATT 1666 legacy rows lack per-row source SHA in the parent; 149 contextual records are hash/offset-bound. Subsetting does not repair historical attribution. MIT is assumed for unattributed PATT material, not verified per payload; preserve PATT_LICENSE.txt and attribution. Benign public pools retain their CC0/Wikidata/synthetic source declarations. CSIC is not used as training source or redistributed.

New input manifests and source archives pin every consumed artifact; `input-retention.json` records local retention and verified extraction, not an off-device backup. The sealed STAB-HELD is unchanged and its disjointness is preserved by the source-subset proof; no sealed cases were opened here.
