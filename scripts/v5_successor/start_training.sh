#!/usr/bin/env bash
# Owner-run wrapper: existing admission gates first, then a new training run.
set -euo pipefail

if [[ ${1:-} == --help ]]; then
  printf '%s\n' 'Usage: bash scripts/v5_successor/start_training.sh [unique-run-id]' \
    'Requires the approved, committed owner admission and bound training files.' \
    'Does not approve, stage, commit, change a recipe, or bypass any gate.'
  exit 0
fi

repo_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd -- "$repo_dir"
package_dir=reports/v5/successor-training-2026-10-31-reviewed
authorization="$package_dir/owner-admission.APPROVED.json"
if [[ ! -f "$authorization" ]]; then
  printf '%s\n' "Missing $authorization. See the package README; only Sebas approves and commits." >&2
  exit 3
fi

run_id=${1:-v51-policy-$(date -u +%Y%m%dT%H%M%SZ)}
if [[ ! "$run_id" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
  printf '%s\n' 'Use a single run name containing letters, digits, dots, underscores or hyphens.' >&2
  exit 3
fi
report_root="reports/v5/successor-training-runs/$run_id"
private_logs="/home/sebas/Documents/Codex/2026-10-26/ta/work/v51-training-logs/$run_id"
if [[ -e "$report_root" || -e "$private_logs" || -e "model-output-v5/experimental/$run_id" ]]; then
  printf '%s\n' 'Run name already used; choose a new name. Existing evidence will not be overwritten.' >&2
  exit 3
fi

umask 077
mkdir -p -- "$report_root" "$private_logs"
printf '%s\n' 'Checking owner admission, committed files, dataset and tokenization. No model loaded yet.'
/usr/bin/python3.12 -B scripts/v5_successor/train_successor.py \
  --mode gate --manifest "$package_dir/dataset-manifest.EXPERIMENTAL.json" \
  --authorization "$authorization" --report-dir "$report_root/gate" \
  2>&1 | tee "$private_logs/gate.log"

printf '%s\n' 'Gates passed. Training will check and reserve the GPU before loading weights.'
/usr/bin/python3.12 -B scripts/v5_successor/train_successor.py \
  --mode train --manifest "$package_dir/dataset-manifest.EXPERIMENTAL.json" \
  --authorization "$authorization" --report-dir "$report_root/training" --run-id "$run_id" \
  2>&1 | tee "$private_logs/training.log"

printf '%s\n' "Training command completed; inspect $report_root/training/run_record.json for its outcome." \
  "Adapter: $repo_dir/model-output-v5/experimental/$run_id/adapter" \
  "Recipe: $repo_dir/$package_dir/recipe.EXPERIMENTAL.json" \
  "Private console logs: $private_logs"
