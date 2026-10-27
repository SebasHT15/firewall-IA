#!/usr/bin/env bash
set -euo pipefail
cd /home/sebas/Desktop/firewall-IA
if [ -n "$(git status --porcelain --untracked-files=no)" ]; then
  echo 'Hay cambios versionados pendientes; los gates requieren un árbol limpio.' >&2
  exit 1
fi
pr_count=$(gh pr list --repo SebasHT15/firewall-IA --head feat/hybrid-training-ready --base develop --state all --json state --jq '[.[] | select(.state == "OPEN" or .state == "MERGED")] | length')
if [ "$pr_count" -lt 1 ]; then
  echo 'Falta el PR a develop requerido por D73.' >&2
  exit 1
fi
records=reports/v5/dataset-preregistration-v1/final-run-2026-10-26-v4
dataset=datasets/v5_sources/final_source_2026-10-26-v4

run_root="model-output-model2/final/v4-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$run_root"
shared=(--dataset "$dataset"
  --c1-contract reports/v5/hybrid/model2-readiness/c1-training-input-candidate-v1.json
  --selection-protocol reports/v5/training-readiness/MODEL2_RECETAS_PROPUESTA_2026-10-24.md
  --dataset-prereg "$records/preregistration.json"
  --freeze-record "$records/freeze-record.json"
  --vocabulary-recipe scripts/training/v5_training_recipe_v1.json
  --ai-audit-authorization "$records/v5-ai-audit-training-authorization.json")
baseline=(--recipe-path reports/v5/hybrid/model2-readiness/model2-recipe-candidate-v1.json
  --authorization "$records/model2-authorization.baseline34.json")
ablation=(--recipe-path reports/v5/hybrid/model2-readiness/model2-recipe-path-ablation-candidate-v1.json
  --authorization "$records/model2-authorization.path-ablation32.json")
.venv-analyzer/bin/python -B -m scripts.model2.final_training "${shared[@]}" "${baseline[@]}" --gate-only
.venv-analyzer/bin/python -B -m scripts.model2.final_training "${shared[@]}" "${ablation[@]}" --gate-only
.venv-analyzer/bin/python -B -m scripts.model2.final_training "${shared[@]}" "${baseline[@]}" --output "$run_root/baseline34.json" > "$run_root/baseline34.report.json"
.venv-analyzer/bin/python -B -m scripts.model2.final_training "${shared[@]}" "${ablation[@]}" --output "$run_root/path-ablation32.json" > "$run_root/path-ablation32.report.json"
printf 'Model 2: ambos candidatos guardados en %s\n' "$run_root"
