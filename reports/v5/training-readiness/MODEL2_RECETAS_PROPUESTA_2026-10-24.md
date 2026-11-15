# Model 2 — recetas y contrato de los dos candidatos (propuesta, 2026-10-24)

Consolida los **dos candidatos ya implementados** por Codex (sus JSON viven en
`reports/v5/hybrid/model2-readiness/`, **no los edito**): consumo este contrato y fijo representación,
features, transformaciones, parámetros, semillas y **protocolo de comparación** sobre TRAIN/VALIDATION.
**C1 extensions = metadatos** (`learned_input_admitted=false`); **C2 ausente**. Esto es **entrenamiento de
candidatos**, NO autorización operativa: no invento presupuesto de falsos bloqueos ni elijo umbral/ganador
con conjuntos protegidos.

## 1. Representación (común a ambos)

- `representation = canonical-request/v1`, `canonical_outcome_required = ACCEPT` (solo peticiones que
  canonizan y son ACCEPT entran como ejemplo; las REJECT/UNSUPPORTED no son entrada aprendida).
- Entrada aprendida = **features deterministas C1** (abajo). Las C1 extensions (valor/URL/léxico) siguen
  como **metadatos**, nunca feature. Ninguna señal canónica se admite como entrada aprendida sin decisión.

## 2. Features — dos vistas (candidatos implementados)

| Candidato | `feature_view` | #campos | Diferencia |
|---|---|---|---|
| **LR baseline** | `baseline_34` | **34** | todas las features C1 |
| **Ablación de path** | `target-path-neutralized/v1` | **32** | baseline_34 **menos** `path_length` y `path_depth` |

Campos baseline_34 (fuente: `c1-training-input-candidate-v1.json`): method, path_length, query_length,
body_length, has_body, content_type, body_format, query_param_count, body_param_count, total_param_count,
repeated_param_name_count, alnum_ratio, symbol_count, symbol_ratio, non_ascii_count, percent_encoded_count,
percent_encoded_ratio, has_percent_encoding, longest_char_run, entropy_bits_per_char, path_depth, json_depth,
single_quote_count, double_quote_count, parenthesis_count, semicolon_count, slash_count, backslash_count,
angle_bracket_count, pipe_count, ampersand_count, equals_count, percent_count, brace_count.
La **ablación** retira exactamente `path_length` y `path_depth` (32). Es la ablación completa del path del
request-target **antes** de la extracción; otras features derivadas del path no son parte de esta ablación
(se documenta como limitación, no se amplía por convenio).

## 3. Transformaciones y parámetros (común a ambos candidatos)

- `learner = LogisticRegression`, `C = 1.0`, `solver = lbfgs`, `max_iter = 500`, `tol = 1e-6`,
  `random_state = 0`.
- `scaler = StandardScaler(with_mean=False)` — **ajustado SOLO en TRAIN** (`fit_role = TRAIN`); se aplica a
  VALIDATION sin re-ajustar. Codificación/escalado nunca se ajustan en VALIDATION ni en conjuntos protegidos.
- `operating_threshold = null` — **no se elige umbral aquí** (no hay autorización operativa).
- Semillas: `random_state=0` (learner); el orden de ejemplos y splits viene del dataset V5 (identidades/split
  deterministas); ninguna aleatoriedad usa datos protegidos.

## 4. Protocolo de comparación (TRAIN/VALIDATION únicamente)

- **Ajuste:** encoder/escalado y el learner se ajustan en **TRAIN**; métricas se calculan en **VALIDATION**.
- **Sin selección con protegidos:** INTERNAL_TEST/E6_RESERVE/External/V4-eval **nunca** se abren; el
  ganador y cualquier umbral futuro no se eligen con ellos.
- **Métricas puntuales** (vía `scripts/model2/evaluation.py`, de Codex): con denominadores, procedencia y
  población explícitas; **no** se inventa un presupuesto de falsos bloqueos ni una tolerancia operativa.
- **Comparación baseline vs ablación:** mismas filas, mismos splits, misma evaluación; se reporta el efecto
  de retirar `path_length`/`path_depth`. **No** se declara ganador operativo: es evidencia de candidatos.
- **Incertidumbre por grupos:** reutilizar el protocolo agrupado de Codex
  (`grouped-fixture-experiment-v1.json`); con pocos grupos los intervalos quedan nulos y se reportan como
  tales (no se fabrican).
- **Población observada:** Model 2 ve tráfico con Fast Path inactivo = todo el tráfico; un Fast Path activo
  futuro cambia esa población y las métricas no se transfieren en silencio.

## 5. Distinción explícita

- **Candidato entrenado ≠ autorización operativa.** Entrenar estos candidatos (offline, sobre el dataset V5
  elegible) produce evidencia; **no** habilita que Model 2 bloquee tráfico real (eso exige contrato de
  decisión aprobado, umbral elegido bajo protocolo, y los gates de despliegue — ninguno aquí).
- Procedencia/labels/ids de grupo son metadatos para validación/reporte, **nunca** features.
- `c1_extensions = metadata_only`; `C2` fuera de alcance (sin predicciones Analyzer como semilla, sin V5
  entrenado requerido).

## 6. Dependencias concretas

- El **dataset V5 congelado** (TRAIN/VALIDATION elegibles) de Codex: estas recetas se ejecutan sobre él vía
  `v5_example_exchange.load_examples` + `scripts/model2/*` (de Codex). No hay conteos ni resultados aquí: no
  se fabrica evidencia de entrenamiento.
- **Interfaz a Codex (aviso, sin editar sus archivos):** ambos candidatos consumen el contrato de ejemplo
  (`text`+features C1 derivadas del texto canónico; `label`/`label_status`/`label_basis`/`audit_type`/
  `label_status_basis` como metadatos). Si Codex cambia la firma de `evaluation.py`/`contracts.py`, re-alinear
  este protocolo. Los JSON candidatos (`model2-recipe-candidate-v1.json`, `model2-recipe-path-ablation-
  candidate-v1.json`) y `c1-training-input-candidate-v1.json` son la fuente de valores exactos; este
  documento no los duplica ni los modifica.
