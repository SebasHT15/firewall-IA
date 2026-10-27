# Branch cleanup — 2026-10-26

Owner requested committing necessary artifacts and discarding the rest before updating the existing PR #88.

Reviewed 819 untracked files. Retained 43 necessary source/test, decision-reference and provenance metadata files for commit. Removed 775 temporary/obsolete/raw artifacts from the checkout after verified recovery archival. One required historical SQLi source pool remains local/ignored; source bytes and location are pinned in inventory.json. No dataset, model, frozen evidence or tracked file was deleted.

Archive: `/home/sebas/Documents/Codex/2026-10-26/ta/outputs/Recuperacion_limpieza_firewall_2026-10-26.tar.gz`
SHA-256: `6bad427b6b157d45df85f7bc31c10c183f7cfb5d6f8be8d2b012a8e8afc7f59d`

Recovery: verify this SHA, extract selected members to a new directory, verify individual hashes from inventory.json, then restore only the desired paths. All reviewed members were temporarily extracted and hash-checked before removal. Raw review packets and historical proposals can be restored without publishing third-party contents. The archive is local, not an off-device backup.

The selected historical files retain their original text and temporal statuses. Some SHA manifests reference raw data moved to the archive; restore those members before replaying the old audits. The active v4 freeze and training gates use the committed evidence and untouched local source pools.

The only new ignore rules cover disposable test fixtures and the required historical source pool; unrelated remaining changes are not hidden by a broad ignore rule.
