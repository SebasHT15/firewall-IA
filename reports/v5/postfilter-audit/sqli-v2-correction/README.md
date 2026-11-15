# SQLi v2 — corrección reproducible + pool y muestra fijados (PROPUESTA; sin commit/firma/ejecución)

Ubicación durable (repo, sin commit). 2026-10-25. z=**1.96**. Semilla y n fijados **antes** de cualquier voto.

## Reproducible (no es una resta a mano)
Comando: `python3 -I reports/v5/postfilter-audit/sqli-v2-correction/apply_correction.py`
Entrada: pool congelado `datasets/v5_sources/attack/attack_pool.jsonl` (sha `ba385fa2…`, verificado).
La etapa aplica **clases de defecto generales y uniformes** (no por unidad, sin usar votos PF2):
- **C1_cli_argument** — invocaciones CLI (sqlmap `--flag=…`), no payloads SQL (cubre `--proxy="…[username]…"`).
- **C2_placeholder_token** — token entre corchetes del **vocabulario sqlmap** (`[SLEEPTIME]`/`[RANDNUM]`/`[RANDSTR]`/`[INFERENCE]`/`[BOOLEAN_QUERY]`/…).
- **C3_placeholder_literal** — `'your … here'`, `'C:\path\to'`, `'path/to'`, `'blah'`.
- **C4_source_code** — código defensivo/fuente (`$_GET/$_POST`, `check_addslashes`, `function(`).
- **C5_doc_token** — token suelto en MAYÚSCULAS (p. ej. `COLLATIONS`) o prompt de herramienta (`MariaDB [dummydb]>`).
**CONSERVA** los identificadores T-SQL legítimos entre corchetes (`[users]`, `[TESTING]`, `[dummydb]`) — no están en el vocabulario sqlmap.

## Resultado (reconciliado)
- Aceptadas antes: **759** → **removidas 33** (C1 6 · C2 9 · C3 7 · C4 2 · C5 9) → **pool corregido 726**.
- **Los 6 INCORRECT de PF2 quedan removidos** por las clases generales (consecuencia, no selección por id); `[TESTING]` se conserva. (Antes quedaban residuos `--proxy` y `[BOOLEAN_QUERY]`; las clases generales los resuelven.)
- `sqli_corrected_pool.jsonl` sha256 **`2db4db956c43992d809a40f6c798e369fee4f6452eab9aeb61d8dded16ad0748`**.
- `removed_diff.json` — las 33 unidades con su clase y procedencia. `manifest.json` — hashes + distribución por archivo.

## Muestra de auditoría fijada a priori (antes de votos)
- `sample_n50.jsonl` + `sample_n50.manifest.json`: **n=50**, semilla **`v5-sqli-v2-corrected-2026-10-25`**,
  estratificada por `source_file` (rank interno por `sha256(seed NUL source_file NUL record_id)`, asignación por mayor resto).
- **sample_sha256 `164ad50b133b5ba815abf2b05d9cb1f5f635df0d31d6af2ae1c32322972cc0d3`**; los `record_id` quedan registrados
  en el manifiesto **ahora**, antes de llamar a ningún revisor. Ni n ni la semilla se eligieron por el resultado previo.

## prereg
`preregistration.v2.json` — criterios r4 sin cambios (z=1.96), etapa de corrección, pool corregido y muestra con sus
hashes finales, modelos D67 (rutas Codex aprobadas, no Claude), `execution_authorized:false`. Toda la evidencia previa intacta.

## Separación
SQLi v2 es **independiente** de los 12 handbacks 06–09 (SSTI/XSS) del censo vigente; no se mezclan.

## Decisión única (para ti)
Firmar **una** autorización de ejecución (`v5-source-census-execution-authorization/proposal-v2`) ligada al sha de este
prereg y al `sample_sha256` fijado, para **una** campaña C-R6 sobre el pool corregido (A1=gpt-6.1-sol, A2=gpt-6-astra,
R3=gpt-6-sol; r4; z=1.96). Sin promesa de PASS.
