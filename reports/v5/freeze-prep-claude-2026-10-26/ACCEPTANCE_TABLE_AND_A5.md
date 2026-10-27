# Aceptación y A5 — cierre Codex, 2026-10-26

**Dataset v3: BLOCKED por H1; no PASS global del dataset.** Se conserva el historial de A2/I7/A6 sin repetir sus ejecuciones reales.

## Ejecución y cobertura

Los resultados históricos son generator 60 + rebalance 23 (83, con 3 omitted), dataset-checks 31, C-S7 1 y shortcuts 3: 118 métodos, 3 omitted.
Nueva evidencia: `a5-closeout-tests.log` — 27 pruebas OK, sin omisiones. `h1-tests.log` — 34 pruebas OK, sin omisiones.
No se suman 61 a 118 para inventar un total único: la ejecución focalizada incluye métodos existentes repetidos para acreditar su correspondencia.

| Control | Detección negativa / control positivo | Evidencia |
|---|---|---|
| A1 / duplicados / L7 | tests/test_v5_dataset_checks.py: sha_mismatch, exact/canonical collisions, cross-split duplicates | suites históricas acreditadas, sin código cambiado |
| A3 / SPL-1…9 / L9 | tests/test_v5_split.py::Invariants, incluidas mutaciones de texto, payload y valores SPL-6 | a5-closeout-tests.log (clase completa) |
| C-M2 | tests/test_v5_generator.py::PairIntegrity.test_cm2_flags_a_second_difference | ejecución histórica generator |
| M-1…M-7 | tests/test_v5_freeze_precheck.py::LabelMutationTests.test_m1_to_m7_detect_their_injected_violation (subcaso por invariante + fixture limpio) | a5-closeout-tests.log |
| M-8 / H2 | LabelMutationTests.test_m8_detects_a_field_name_parameter + revisión de funciones de etiquetas y draw_scalar | a5-closeout-tests.log + h2-h3-evidence.json |
| C-M3 | NumericMutationTests.test_cm3_each_split_rejects_injected_imbalance: ambos extremos en cada split, y control limpio | a5-closeout-tests.log |
| cap fuente / over-limit | NumericMutationTests.test_source_cap_rejects_concentrated_source / test_over_limit_rejects_excess | a5-closeout-tests.log |
| C-S1/S2/S6 | tests/test_v5_freeze_shortcuts.py::FreezeShortcutMutationTest.test_envelope_label_leak_blocks_s1_and_s2; ya contiene assert específico C-S6 | a5-closeout-tests.log |
| C-S3/S4 | tests/test_v5_freeze_shortcuts.py: unmasked_label_token, structure_probe_passes_clean_and_blocks_injected_label_feature | ejecución histórica shortcuts |
| C-S7 | tests/test_v5_cs7_check.py, mutación y D76 | ejecución histórica, sin código cambiado |
| L8 | tests/test_v5_pilot_inputs.py::PilotInputs.test_l8_removes_probe_pool_elements_before_split + NumericMutationTests.test_l8_report_nonzero_cannot_pass | a5-closeout-tests.log |
| H1 | test_h1_identity_secrets.py, fuentes fijadas por hash y casos positivos/negativos de cada subcontrol | h1-tests.log: 34 OK; dataset H1 FAIL real |
| H3 | renderer usa canonicalize, no framing de transporte; scan de los 3160 textos | h2-h3-evidence.json |
| A2 / I7 / A6 | acreditados previamente; no repetidos | a2-regeneration-clean-tree.json / pin I7 / a6-fail-closed-evidence.json |
| L10/L11 | advertencias: no se exigen mutaciones bloqueantes nuevas | novelty-ancestry.json, WARN alto L10 / 0 hits L11 |

Las carencias identificadas C-M3/C-S6/L8/L9 están resueltas en cobertura; no eran opcionales. El nuevo test numérico y el checker/tests H1 siguen sin commit.
La cobertura del verificador no transforma un resultado negativo del dataset en PASS.

## Aceptación v3

| Grupo | Resultado |
|---|---|
| Integridad A1 / A2 | hashes preservados; A2 acreditado previo |
| C-M3 | 0.5000 por split, PASS en evidencia existente |
| C-S1/S2/S3/S4/S6 | PASS en reportes existentes; C-S4 accuracy 0.5 |
| C-S7 | TRAIN PASS; VALIDATION/INTERNAL_TEST WARN bajo D76 |
| L7 / L8 / L9 | reportes existentes: L7 13 conjuntos, L8 0, SPL-3/SPL-6 disjointness de valores/payloads y templates |
| Admisión | original path, censo CmdI/SSTI/XSS y SQLi v3 permanecen separados; nunca PASS combinado |
| H1 | FAIL: evil.site en 9 filas, google.com en una; Google+ en otra fila de symbols |
| H2 / H3 | PASS de revisión técnica, h2-h3-evidence.json |
| STAB | solo STAB-HELD, 1260 casos, sello previo intacto, D77 posterior intacto; no STAB-DEV |
| Advertencias | L10 alto; cuatro categorías TRAIN-only/NOT_EVALUABLE; concentración path; PATT legacy; STAB concept-built |

`blocking_checks.status=PARTIAL`, exclusivamente sin habilitar. No se emite freeze, autorización o permiso de entrenamiento.
