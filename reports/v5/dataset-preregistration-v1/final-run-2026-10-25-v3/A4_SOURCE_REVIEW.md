# A4 — procedencia y licencias del build v3

Revisión local del 2026-10-25. Alcance: fuentes realmente seleccionadas para el lote v3; no constituye dictamen legal.

## Ataques

- Pool ensamblado `datasets/v5_sources/final_candidate/attack_pool.jsonl`: 1.815 registros, 39 archivos de PayloadsAllTheThings (PATT). El clone local está fijado en `e961fef231d8327bae83b563fab50aec2e6b77c0`; los 39 archivos existen allí.
- Los 149 registros de la curación contextual contienen `source_sha256` y offsets: **149/149 hashes del archivo coinciden** con los bytes del clone. Los 1.666 registros heredados carecen de hash por fila; su pool, fuente y procedencia están ligados al manifest/component binding y los 39 paths se verificaron en el clone fijado. La ausencia de hash por fila se conserva como limitación; no se inventa.
- Los 39 archivos seleccionados pertenecen al conjunto `reviewed_not_denied` de D66; **0** están en `denied`, `not_read_by_extraction` o `unresolved_for_human_review`. Denylist vigente: `scripts/dataset/v5_lexicon/patt_third_party_denylist_v2.json`.
- PATT publica licencia MIT; copia exacta del archivo de licencia del clone: `PATT_LICENSE.txt`, SHA-256 `f21ad49cdad2bf18c06543fb064a81d04bd2bff497dd20a1ecc45c5df8643691`. La fila `license` del pool dice “MIT (PATT, assumed for unattributed content)” en 1.666 casos y queda vacía en 149; el vínculo de esos 149 se resuelve por `source_file`/hash y el clone, **sin atribuir autoría individual**. Las atribuciones de terceros inline están divulgadas según D66; la denylist no equivale a una garantía de derechos sobre cada línea.

## Benignos y estructuras

- Manifest de pools benignos `datasets/v5_sources/benign/manifest.json`, SHA-256 `48474e3bf7adf868eea95f20337e406601624b1442bbc7c533f50f4fccf9bd0d`, fija Tatoeba `sentences_CC0` y nombres Wikidata bajo CC0-1.0 con URLs, fechas y SHA de los archivos fuente. `streets` procede del léxico sintético del repositorio. El build v3 consume ese manifest mediante `pilot_inputs.pool_provenance`; el precheck verificó la integridad de los artefactos finales.
- CSIC está excluido de TRAIN; solo se usa localmente para el screen L11. Su distribución no se presume autorizada. Otros conjuntos consumidos/protegidos se consultan solo para colisiones, según `reports/v5/freeze-prep/consumed_sets.json`.

## Declaración de uso

Conservar `PATT_LICENSE.txt` y estas atribuciones junto con cualquier copia distribuida del corpus derivado. No redistribuir CSIC. La procedencia técnica de los 1.815 registros está vinculada; la autoría/lícencia de cada payload no se declara verificada individualmente. Estas limitaciones deben acompañar el freeze report y cualquier publicación del experimento.
