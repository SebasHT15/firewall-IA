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

run_id="v5-final-v4-$(date -u +%Y%m%dT%H%M%SZ)"
args=(--mode final --dataset "$dataset"
  --recipe scripts/training/v5_training_recipe_v1.json
  --dataset-prereg "$records/preregistration.json"
  --freeze-record "$records/freeze-record.json"
  --training-prereg "$records/v5-training-preregistration.json"
  --ai-audit-authorization "$records/v5-ai-audit-training-authorization.json"
  --run-id "$run_id" --report-dir "model-output-v5/gate-reports/$run_id")
/usr/bin/python3.12 -B scripts/training/finetune_v5.py "${args[@]}" --gate-only
exec /usr/bin/python3.12 -B scripts/training/finetune_v5.py "${args[@]}"
