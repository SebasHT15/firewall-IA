# Receta V5 — bloque único de ratificación (2026-10-24)

Propuesta concreta y completa sobre `scripts/training/v5_training_recipe_v1.json`. **D71 ya ratificó**
plantilla (`V5_CANDIDATE_TEMPLATE`), vocabulario (`PILOT_VOCABULARY`) y `B=415`; **D72 ratificó el contrato
#80/r4 y sus esquemas**. **No vuelvo a pedir esas decisiones.** Aquí dejo los valores exactos de las
secciones que siguen PROPOSED y un **bloque único** para ratificarlas. **No marco RATIFIED** (ninguna
aprobación inexistente): el owner aplica el bloque.

## Estado por sección (gate `unratified_recipe_sections`)

| Sección | Estado | Decisión |
|---|---|---|
| template · vocabulary · token_budget | **RATIFIED** | D71 — no se re-pide |
| quantization | **APPROVED** | D11 — 4-bit nf4, double-quant, compute bf16 |
| base_model · loss · lora · optimization · seed · library_pins · (recipe top-level) | **PROPOSED** | bloque de abajo |

## Valores exactos a ratificar (verificados contra el entorno del host)

- **base_model**: `TinyLlama/TinyLlama-1.1B-Chat-v1.0`, `revision fe8a4ea1ffedaf415f4da2f062534de366a451e6`,
  `local_files_only: true`. *Comprobado:* snapshot + tokenizer presentes en la caché HF local.
- **loss**: `on: completion` (pérdida solo sobre la salida del asistente + EOS; `full_sequence` reservado
  para paridad).
- **lora**: `r 16`, `lora_alpha 32`, `lora_dropout 0.05`, `bias none`,
  `target_modules [q_proj,k_proj,v_proj,o_proj,gate_proj,up_proj,down_proj]`.
- **optimization**: `num_train_epochs 4`, `per_device_train_batch_size 4`, `per_device_eval_batch_size 4`,
  `gradient_accumulation_steps 8`, `gradient_checkpointing true`, `learning_rate 2e-4`,
  `lr_scheduler_type cosine`, `warmup_ratio 0.05`, `optim paged_adamw_8bit`, `bf16 true`,
  `save_total_limit 2`, `load_best_model_at_end true`.
  - **Cadencia eval/guardado:** la receta declara `eval_steps 200 / save_steps 200 / logging_steps 50`
    como **tope**; la **cadencia efectiva se DERIVA** por `finetune_v5.compute_schedule` del tamaño TRAIN
    congelado (eval == save, ≥1 evaluación+checkpoint incluso en datasets pequeños) y se **registra** en
    `run_record.json`/`gate_record.json` **antes** de entrenar. No es una edición silenciosa de la receta;
    `epochs/batch/accum/lr` son los de la receta ratificada. Ratificar la receta ratifica el tope y la
    política de derivación, no una cadencia fija de 200.
- **seed**: `seed 20261019`, `data_seed 20261019`.
- **library_pins**: `python 3.12`, `torch 2.6.0+cu124`, `transformers 5.8.0`, `trl 1.4.0`, `peft 0.19.1`,
  `bitsandbytes 0.49.2`, `datasets 4.8.5`, `accelerate 1.13.0`. *Comprobado:* las 8 versiones efectivas en
  el host coinciden exactamente (preflight).

## Bloque único de ratificación (para que el owner lo apruebe; NO aplicado)

```
RATIFY v5-training-recipe-v1 (owner decision Dxx, fecha):
  recipe.status           -> RATIFIED
  base_model.status       -> RATIFIED   # TinyLlama-1.1B-Chat-v1.0@fe8a4ea, local_files_only
  loss.status             -> RATIFIED   # completion
  lora.status             -> RATIFIED   # r16/alpha32/dropout0.05/bias none/7 target_modules
  optimization.status     -> RATIFIED   # epochs4/bs4/accum8/lr2e-4 cosine/warmup0.05/paged_adamw_8bit/bf16
                                        #   eval/save = tope; cadencia efectiva derivada+registrada (compute_schedule)
  seed.status             -> RATIFIED   # 20261019 / 20261019
  library_pins.status     -> RATIFIED   # los 8 pines verificados en el host
  # template/vocabulary/token_budget ya RATIFIED (D71); quantization APPROVED (D11)
```

Al aplicarse, `unratified_recipe_sections(recipe)` queda vacío y **F7** (y, con `library_pins`, **F9**) deja
de rechazar en FINAL. **Sigue pendiente para FINAL** (no es parte de este bloque): dataset real
construido+congelado, preregistro/freeze/autorizaciones, árbol limpio, y los gates F1–F6/F8/F10 vacíos.

## Qué NO se ratifica aquí

Nada de Model 2 (ver `MODEL2_RECETAS_PROPUESTA_2026-10-24.md`), ningún umbral operativo, ninguna
autorización de datos. Ratificar la receta **no** autoriza un build/entrenamiento real; solo cierra la
sección "receta" de los gates. No se tocó la receta congelada ni se marcó aprobación alguna.
