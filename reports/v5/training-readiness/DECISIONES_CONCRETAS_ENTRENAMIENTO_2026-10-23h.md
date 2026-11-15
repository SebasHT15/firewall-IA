# Decisiones concretas para avanzar a piloto y entrenamiento — 2026-10-23h

**Actualización: §1 ratificado expresamente por el owner y aplicado como D72; las demás recomendaciones siguen propuestas y no se firman permisos de datasets.** Rama `feat/hybrid-training-ready`, HEAD `97b0be0`. D71 conserva plantilla, vocabulario y B415 ya aprobados.

## 1. #80: ratificado y aplicado (D72)

El owner ratificó el siguiente addendum explícito al contrato de filas (sin reescribir el r4 congelado):

- Id: `v5-training-reference-contract/v1-PROPOSED`.
- Ataque genérico basado en IA: `label=BLOCK`, `label_status=TRAINING_REFERENCE`, `label_status_basis=ai_audit`, `label_rule=ATTACK_POOL_LEAF`, `policy_id=null`; manifest `audit_type=ai_audited` y `row_contract` igual al id anterior.
- Categoría PASS_AI_AUDITED y estado de fila siguen separados. No se crea VERIFIED ni una política de seguridad ficticia. Las filas sujetas a políticas existentes conservan su status/policy_id.
- Se amplía M-1 de forma explícita y acotada; M-3 conserva su semántica.
- D72 añade r4 a SUPPORTED_SPECS y autoriza únicamente TRAINING_REFERENCE en AI_AUDIT_ROW_STATUS_ALLOWED. La autorización REAL_BUILD propuesta es `v5-real-build-authorization/v1-PROPOSED`, y la autorización separada de entrenamiento FINAL es `v5-ai-audit-training-authorization/v1-PROPOSED`.

Ratificar los contratos/esquemas no firma permisos para un dataset: cada registro concreto todavía fija hashes, identidad, fecha, alcance y decisión. La autorización FINAL no activa runtime, Fast Path ni concede autoridad de bloqueo. Las plantillas siguen sin firmar.

Implementación y controles positivos/negativos ya ejecutados: `EMISOR_R4_PROPUESTO_2026-10-23e.md`, `INTEGRACION_PILOTO_2026-10-23g.md`.

## 2. Fuentes: corrección preparada; readmisión todavía pendiente

Candidato 006: SHA-256 `8383c00e670e8d6700f1d50bc8609511ff38022ee41458d5929c62fdd01958e5`, 3,875 registros PENDING_ADJUDICATION. Preparación reproducible en `scripts/dataset/v5_source_readmission.py`; evidencia en `FUENTES_PREPARADAS_READMISION_2026-10-23h.json`.

| Categoría | Antes | Candidato | Resultado sellado anterior |
|---|---:|---:|---|
| SQL Injection | 759 | 727 | FAIL |
| XSS Injection | 337 | 343 | INSUFFICIENT_EVIDENCE |
| Command Injection | 422 | 415 | INSUFFICIENT_EVIDENCE |
| Server Side Template Injection | 334 | 309 | FAIL |

El candidato valida hashes, conteos, estados pendientes, módulos de corrección fijados y continuidad de las fuentes. Las 2,081 filas fuera del foco conservan payload/categoría/procedencia; 2,079 son idénticas en todos los campos. No se transfieren resultados PASS al candidato. La comparación no es una adjudicación nueva ni demuestra que cada ataque sea válido.

**Corrección de la explicación anterior:** el texto r4 §7 contempla una única reauditoría posterior a corrección documentada para «Fail or insufficient evidence». El ejecutor legado `audit_v5_postfilter.check_round` selecciona únicamente FAIL de su reporte antiguo. No es correcto presentar esa limitación de código como si el texto exigiera una campaña adicional para XSS/CmdI. Antes de consumir esa continuación hay que integrar correctamente el resultado R3 autoritativo y conservar el límite/semillas/historial existentes. No se ejecutó muestra ni revisión nueva, no se reinició la historia y no se modificaron reportes sellados.

Recomiendo conservar las seis salidas de ataque previstas y aceptar/revisar la corrección concreta antes de usar la única continuación permitida. Recortar categorías cambiaría el alcance del modelo y requeriría otra decisión expresa. Aceptar la corrección no concede PASS a ninguna categoría ni autoriza entrenamiento con ella.

## 3. Model 2: entrenar dos candidatos fijos

Propuesta: ratificar los dos JSON ya implementados, sin búsqueda adicional de familias ni de hiperparámetros:

| Parámetro | Valor |
|---|---|
| Representación | canonical-request/v1 ACCEPT |
| Candidatos | baseline_34 y target-path-neutralized/v1 (32 campos) |
| Modelo | LogisticRegression, C=1, solver=lbfgs |
| Escalado | StandardScaler(with_mean=False), fit exclusivamente TRAIN |
| Optimización | max_iter=500, tol=1e-6, random_state=0 |
| Etiquetas/procedencia/grupos | metadatos; no features aprendidas |
| Extensiones C1 / C2 | extensiones metadata_only, C2 ausente |
| Umbral/política operativa | ninguno durante este entrenamiento |

Los archivos son `reports/v5/hybrid/model2-readiness/model2-recipe-candidate-v1.json`, `model2-recipe-path-ablation-candidate-v1.json` y `c1-training-input-candidate-v1.json`. Conservar ambos artefactos como candidatos evita elegir retrospectivamente el que favorezca una conclusión. Elegir el modelo/umbral de bloqueo requiere fijar el presupuesto de falsos bloqueos y un protocolo de evaluación; no se inventa ese presupuesto ni se utiliza un conjunto protegido para ajustarlo.

La autorización FINAL propia de Model 2 sigue siendo separada y exige receta/contrato/protocolo/snapshots/dataset fijados; no se activa por aprobar la representación C1.

## 4. V5: recomendación sobre la receta existente

Mantener TinyLlama-1.1B-Chat-v1.0, revisión `fe8a4ea1ffedaf415f4da2f062534de366a451e6`; loss solo completion+EOS; nf4 con double quant y bf16; LoRA r16/alpha32/dropout0.05/bias none en q/k/v/o/gate/up/down_proj; semilla/data_seed 20261019. Mantener como candidato el schedule existente: 4 epochs, batches train/eval4, acumulación8, checkpointing, LR2e-4, cosine, warmup0.05, paged_adamw_8bit, eval/save200, logging50, save_total_limit2 y load_best_model_at_end.

Los valores y pins completos están en `scripts/training/v5_training_recipe_v1.json`. Las secciones base_model/loss/lora/optimization/seed/library_pins siguen PROPOSED. La compatibilidad de bibliotecas/modelo local está comprobada; el consumo real de VRAM y la duración no se han medido con el dataset final. Las 4 epochs/eval_steps200 deben ratificarse frente al número de pasos del dataset congelado: una corrida que no llegue a una evaluación no queda justificada por copiar la receta V4. No se marca ahora el schedule como aprobado ni se presenta SMOKE como entrenamiento final.

## 5. Piloto: límite concreto de la integración actual

Los diez pools están disponibles/verificados. El preparador con fuentes llama a REAL_BUILD y conserva sus requisitos de valores ratificados. Eso **no resuelve por sí solo** el permiso para un piloto de calibración con parámetros provisionales: hay que fijar su alcance/configuración/permiso por separado del full build, tal como ya indica el paquete anterior. No se debe ratificar ficticiamente un umbral final para conseguir que arranque el piloto que lo medirá.

Recomiendo mantener el 10% de cuotas como propuesta existente, usar el tokenizer fijado y medir la distribución real para resolver §11.2. Cuotas, L, shares, límites por fuente y las listas de política necesitan sus valores explícitos antes de ejecutar; los L12/cuota2 de la prueba sintética son controles técnicos, no valores finales recomendados ni ratificados.

## 6. GPU: lo confirmado y el contexto de ejecución

Claude verificó los pins/modelo local y una RTX 4090 Laptop de ~16 GiB en el host. La reejecución integrada de Codex confirma pins y modelo local, pero su proceso aislado **no ve CUDA** (`torch.cuda.is_available=False`); por ello ese reporte devuelve env_ready=false. No se interpreta esto como un fallo de instalación del host ni se cambia CUDA por ese dato. El arranque debe verificarse en el contexto del intérprete/host que sí expone la GPU.

Se corrigieron dos defectos de integración del preflight: F9 ahora recibe también Python y la lista real de fuentes del trainer; los reportes gate-only quedan en `model-output-v5/gate-reports/<RUN_ID>`, fuera de `model-output-v5/final/<RUN_ID>`, para no bloquear el posterior arranque por una carpeta de salida ya creada. Emite argv con las rutas suministradas y comandos escapados. Su alcance es metadata; `ready_for_trainer_gate_only` no sustituye la comprobación real de filas que hace el trainer.

Sin commits, entrenamiento real ni cambios de autoridad. Lo que falta de evidencia y decisión se mantiene visible; esta propuesta no es una nueva campaña de auditoría.
