# Consolidated ratification candidate — 2026-10-24

Status: ratified explicitly by the owner and applied as D73, 2026-10-24. Individual dataset/run permission records remain unsigned. D71/D72 remain approved.

## A. V5 recipe

Ratify the exact candidate in scripts/training/v5_training_recipe_v1.json and Claude's RECIPE_V5_RATIFICATION_BLOCK_2026-10-24.md: TinyLlama-1.1B-Chat-v1.0@fe8a4ea1ffedaf415f4da2f062534de366a451e6 local-only, completion loss; LoRA r16/alpha32/dropout0.05/bias none on q/k/v/o/gate/up/down; 4 epochs, batches4, accumulation8, checkpointing, LR2e-4 cosine/warmup0.05/paged_adamw_8bit/bf16, two retained checkpoints, best model at end; seeds20261019; the installed pins recorded in that JSON. Existing quantization approval and D71 remain unchanged.

Ratify the cadence policy: total steps = epochs × ceil(TRAIN rows/(batch×accumulation)) for the intended single GPU; eval/save = max(1,min(200,total_steps//4)), logging capped at that cadence. The effective schedule is computed from the admitted TRAIN rows and recorded before fitting. This matches the installed Trainer update-step rule. It does not authorize empty TRAIN or waive eligibility gates.

Apply RATIFIED to the recipe and its remaining proposed sections only after owner approval. No dataset authorization follows from this.

## B. Model 2 candidates and C1 input

Ratify the two existing model2-recipe JSONs and c1-training-input-candidate-v1.json: canonical-request/v1 ACCEPT; logistic regression C1/lbfgs/max_iter500/tol1e-6/seed0; DictVectorizer and StandardScaler(with_mean=False) fit only on TRAIN; baseline34 and target-path-neutralized32, with path neutralized BEFORE all extraction in the latter. Same TRAIN/VALIDATION for both; preserve group separation and report uncertainty only when groups support it. C1 extensions stay metadata_only; C2 absent.

Ratify Claude's MODEL2_RECETAS_PROPUESTA_2026-10-24.md as the fixed candidate-comparison protocol. Retain both candidates without selecting an operating threshold or deploying a winner. No false-block budget is invented; operational selection remains a later decision. Source candidate JSONs remain the exact field/parameter source.

Ratify the model2-final-training-authorization/v1-PROPOSED schema definition and activate FINAL_AUTH_SCHEMA. Every actual training still requires a separate, complete, committed permission record pinning code, recipe, contract, protocol and eligible frozen dataset. Existing templates remain unsigned.

## C. Pilot calibration contract

Ratify v5-pilot-build-authorization/v1-PROPOSED as implemented in scripts/dataset/v5_pilot_authorization.py and described in pilot-calibration-proposal-2026-10-24/README.md. It permits only a specifically authorized, hash-bound calibration build at ceil(full quota/10), preserving PROPOSED/PENDING final-value statuses. Outputs remain PROVISIONAL_PILOT and are refused by both shared training readers. Full-build final-value checks are unchanged. Every category still needs actual PASS_AI_AUDITED evidence.

This ratifies only the schema/controls. It does not choose the full quota, oracle L, shares, split seed or other calibration values; sign a concrete record; admit the four families; start a pilot; authorize training; or activate runtime. The exact parameter bundle and actual source evidence remain required.

## Scope

Approval of A/B/C records the definitions and recipes in one owner decision, and activates their corresponding schema constants. It does not rewrite frozen D67 evidence, mark candidate corrections as PASS, commit/push/merge, or start training. The PR to develop remains immediately before the agreed training stage, once the remaining data work and launch checks are complete.
