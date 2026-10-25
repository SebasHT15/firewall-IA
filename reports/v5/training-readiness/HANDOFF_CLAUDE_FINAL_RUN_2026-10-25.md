# Handoff operativo a Claude Code — V5 + Model 2 FINAL

Fecha: 2026-10-25. Repo: `/home/sebas/Desktop/firewall-IA`, rama `feat/hybrid-training-ready`, preparación v2 en `d988501`, handoff y precheck en `3fda72f`. El usuario quiere **terminar los controles, congelar el dataset y recibir los comandos exactos para lanzar ambos entrenamientos**. No quiere comandos provisionales ni claims de protección en producción. Autorizó corregir fallos y ratificó el alcance de investigación D74 y los valores D75. No hay más votos LLM pendientes.

## Estado verificado, sin reconstruir la historia

1. Las cinco categorías del generador están admitidas por tres componentes separados: `path_file_access`, CmdI/SSTI/XSS del censo y SQLi v3. Bindings: `reports/v5/postfilter-audit/final-component-bindings.json`. No hay PASS combinado ni se transfiere el PASS entre pools.
2. D74: CmdI, SQLi, SSTI y XSS son TRAIN-only/NOT_EVALUABLE bajo D60; solo `path_file_access` es evaluable. Entrenamiento **experimental de investigación** permitido, pero sin métricas por categoría para esas cuatro. I-9 WARN 8%, BLOCK 12%, cap WARN; únicamente `path-media`/VALIDATION y `path-export`/INTERNAL_TEST tienen excepción específica, visible (100% del split). D75 ratifica cuota completa 20 pares/celda, piloto 2, fuente ≤75% por archivo/categoría, oráculo L12 y firmas, política/catálogo, placement 3:1:1:1, umbrales §7 e I7 2500 casos + barrido de 256 bytes. Decisiones en `DECISIONS.md`.
3. Piloto r3 corregido y aprobado: `datasets/v5_sources/pilot_source_2026-10-25-r3/manifest.json` SHA-256 `373f341fd90555592e8a1372d60504556af50ce24800e8f4495677d301c72166`, mediciones SHA-256 `db7e64c40ba1d7bd8e1838534b64d27c6ac62bc650bd86d09eae06e9d3013cda`. `gates_ok=true`, SPL-3…9 verdaderos. El piloto r2 también pasó, pero luego se descubrió el fallo L8.
4. **Build completo v1 RECHAZADO** por L8: 56 elementos de pools benignos coincidían con pools publicados de probes v1/v2. Conservar íntegro `datasets/v5_sources/final_source_2026-10-25-v1/` (manifest SHA `c1e5aa1a…`), jamás entrenar con él. Registro: `reports/v5/dataset-preregistration-v1/final-run-2026-10-25/REJECTED_V1_L8.md`.
5. Corrección L8 en `scripts/dataset/v5_pilot_inputs.py`: filtro NFC+casefold previo al D-3 dedup/split, excluye exactamente 56 (names_given 25, names_family 15, streets 7, symbols 9), deja cero solapes y guarda solo conteos/digest. Código/test y piloto r3 commiteados en `7865f54`.
6. **Build completo v2 construido**: `datasets/v5_sources/final_source_2026-10-25-v2/manifest.json` SHA-256 **`b873c3418d1c15437ee39c6ebce34a28f7cb0b506e672e830f0a4fa064e5c211`**. Prerregistro/autorización commiteados en `reports/v5/dataset-preregistration-v1/final-run-2026-10-25-v2/`, commit `d988501`. `status=REAL`, `gates.ok=true`, 3,080 TRAIN + 40 VALIDATION + 40 INTERNAL_TEST = 3,160 filas de split; 1,580 pares completos, cero shortfalls; 44 filas TRAIN en slices y 2 excluidas por presupuesto (≤1%). I-9 converge con solo las dos excepciones D74; L8=0.
7. L7 colisiones contra todos los conjuntos bloqueantes extraíbles: **0 exactas y 0 canónicas**, salida count-only `reports/v5/dataset-preregistration-v1/final-run-2026-10-25-v2/protected-collision-counts.json` SHA `1a25289c…`, `blocking_pass=true`. `csic_database_csv` queda no chequeado ahí porque L11 es un screen distinto y WARN_RULING; no declarar L11 PASS. El script es `scripts/dataset/v5_protected_collision_check.py`, commit `7865f54`.
8. `scripts/dataset/v5_freeze_precheck.py` y `reports/v5/dataset-preregistration-v1/final-run-2026-10-25-v2/freeze-precheck.json` son trabajo nuevo **aún sin commit**: 10 comprobaciones factuales pasan (A1 hashes, alineación fila/meta, conteos, gates, I9, L8, L7, source cap, over-limit, C-M3). El informe dice explícitamente `freeze_ready=false`.
9. **No dataset FROZEN, no freeze record firmado, ningún Model 2/V5 FINAL entrenado.** El usuario pidió los comandos exactos **cuando todo esté listo**. No emitirlos como si ya fueran ejecutables.

## Hallazgo nuevo que hay que resolver primero

El control C-S7 ratificado (elemento dominante >3% de cualquier clase por split = BLOCK) **falla estructuralmente** en v2: VALIDATION e INTERNAL_TEST tienen solo 20 filas por clase. Un solo elemento usado una vez ya aporta 5%. Medición agregada sobre los metadatos:

| Split/clase ALLOW | Filas | Elemento máximo | Elementos >3% |
|---|---:|---:|---:|
| TRAIN | 1540 | 0.45% | 0 |
| VALIDATION | 20 | 20% | 15 |
| INTERNAL_TEST | 20 | 10% | 19 |

No falsear PASS ni cambiar silenciosamente el umbral D75. Opciones concretas: (a) ampliar pools y cuota/estructuras de los splits protegidos con nueva versión, repetir piloto/build/auditorías; (b) proponer una enmienda de investigación al C-S7 para splits pequeños con decisión expresa del propietario antes de cualquier modelo. El usuario prefiere avanzar rápido, pero la elección debe ser concreta y revisable. Además, cuatro inyecciones no tienen VALIDATION/INTERNAL_TEST por D60, limitación ya ratificada D74.

## Siguientes tareas en orden

1. Verificar el C-S7 con un checker reproducible (sin mostrar filas protegidas) y preparar decisión metodológica mínima si el fallo se confirma. No volver a ejecutar un entrenamiento sobre v2 mientras el freeze no pase. Conservar versiones rechazadas.
2. Completar §7: C-S1/2/3/4/6/7 bajo D75; L10 y L11 con conteos y rulings; A2 dos regeneraciones byte-idénticas con distinto `PYTHONHASHSEED` y cwd, A4 licencias/pins, A5 mutation tests, A6 checker de calidad, I7 sobre código commiteado. El generador solo hace parte; `gates.ok=true` no es freeze.
3. Implementar y sellar `STAB-HELD` con generador/lexicón/salt propios, elementos disjuntos de V5/probes, controles/contrastes/twins, L7/L8/L9 y hashes. No leer sus casos para diseño después del sello; entrenamiento solo abre TRAIN/VALIDATION.
4. Re-medir B=415 con el tokenizer exacto V5, verificar pins de librerías y CUDA en el host real. En esta sesión sandbox `nvidia-smi` no ve `/dev/nvidia*`; el usuario confirmó que la RTX 4090 sí está en su equipo. Claude Code deberá comprobarlo fuera de este sandbox.
5. Emitir freeze report y freeze record con cada ítem §11.3 DONE **solo con evidencia**, commit; preparar autorización ai-audit separada y autorizaciones FINAL de Model 2 y V5 ligadas al manifest/freeze/receta/código. Resolver el tracked tree sucio (muchos cambios preexistentes de Claude): revisar y commitear los archivos pertinentes, sin descartar trabajo ajeno. F9 exige árbol tracked limpio.
6. Ejecutar `--gate-only` de ambos entrenadores primero; cuando ambos pasen, entregar al usuario **dos comandos exactos** con rutas reales: Model 2 `python3 -m scripts.model2.final_training` y V5 `python3 scripts/training/finetune_v5.py` (ver `--help` para flags actuales). El usuario lanzará los entrenamientos. No activar gateway ni afirmar rendimiento de seis categorías.

## Comandos de reproducción ya válidos (no son comandos de entrenamiento)

```bash
cd /home/sebas/Desktop/firewall-IA
python3 scripts/dataset/v5_protected_collision_check.py datasets/v5_sources/final_source_2026-10-25-v2 --out reports/v5/dataset-preregistration-v1/final-run-2026-10-25-v2/protected-collision-counts.json
python3 scripts/dataset/v5_freeze_precheck.py --dataset datasets/v5_sources/final_source_2026-10-25-v2 --attack-pool datasets/v5_sources/final_candidate/attack_pool.jsonl --collisions reports/v5/dataset-preregistration-v1/final-run-2026-10-25-v2/protected-collision-counts.json --out reports/v5/dataset-preregistration-v1/final-run-2026-10-25-v2/freeze-precheck.json
TMPDIR=/home/sebas/Desktop/firewall-IA/reports/v5/.tmp-tests python3 -m unittest tests.test_canonical_request_review.TestTotalityFuzz -v
```

Fuente de origen del pool construido: `/home/sebas/Documents/Codex/2026-10-22/firewall-c1-model2-continuidad/work/pilot-integration-007/pools`; benignos `datasets/v5_sources/benign`. No usar los 256 payloads de desarrollo como evidencia de admisión. No sustituir modelos de auditoría: los tres componentes ya están cerrados.

## Instrucción para Claude

Continúa desde este estado, inspecciona solo los archivos necesarios, conserva v1 y v2, arregla los fallos concretos con versiones nuevas, prueba cada gate y no inventes firmas, PASS o resultados. El objetivo es dataset congelado y dos comandos FINAL que pasen `--gate-only`. Si necesitas cambiar una decisión D74/D75, prepara primero el cambio exacto y pide aprobación puntual al propietario mientras avanzas el trabajo independiente. Reporta estado por componente y deja un cierre único.
