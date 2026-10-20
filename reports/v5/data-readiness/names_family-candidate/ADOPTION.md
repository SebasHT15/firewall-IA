# Pinned family-name acquisition

The acquisition code accepts the archived Wikidata Q101352 snapshot using LIMIT 20000. The limit is an acquisition setting, not a change to the approved source or minimum pool-size contract. Raw source data remains outside Git. The stored source SHA-256 is `039882220480b029074243f740f4eec07646029a0b6de8ce70f99454686d3ead`.

The source and its sidecar were installed locally under `datasets/v5_sources/raw/`. Building with the existing attack-pool exact-match oracle produced 12,104 accepted family-name values; no source pool remained blocked and all survival fixtures passed. The other accepted counts were names_given 26,050, prose_en 34,048, streets 12,604, symbols 295.

Reproducibility relies on the archived snapshot and checksum, not repeating a live WDQS query. The subset is arbitrary and no representativeness claim is made.

The generator still excludes names_family from SLOT_POOLS. Pool precedence, generator inclusion and any affected preregistration remain separate work. This change does not approve a final dataset or authorize training.
