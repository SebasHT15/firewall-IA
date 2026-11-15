#!/usr/bin/env bash
# Mechanism checks of the local stack with the V5 DOUBLE (no GPU, no model). Each check refuses to reuse
# a directory. Usage:
#   scripts/local_stack/run_checks.sh <new evidence dir> <new private work dir>
set -euo pipefail
cd "$(dirname "$0")/../.."
EVIDENCE=${1:?evidence dir}
WORK=${2:?private work dir}
PY=.venv-dataplane/bin/python
CFG=${CONFIG:-scripts/local_stack/stack.example.json}
mkdir -p "$EVIDENCE"
$PY -B -m unittest discover -s tests -p 'test_local_stack.py' -v 2>&1 | tee "$EVIDENCE/unit-tests.txt"
$PY -B scripts/local_stack/transport_check.py --config "$CFG" --out "$EVIDENCE/transport-check" --work "$WORK/transport-check" 2>&1 | tee "$EVIDENCE/transport-check.stdout.txt"
$PY -B scripts/local_stack/app_check.py --config "$CFG" --out "$EVIDENCE/app-check" --work "$WORK/app-check" --effect-smoke 2>&1 | tee "$EVIDENCE/app-check.stdout.txt"
$PY -B scripts/local_stack/failure_check.py --config "$CFG" --out "$EVIDENCE/failure-check" --work "$WORK/failure-check" 2>&1 | tee "$EVIDENCE/failure-check.stdout.txt"
$PY -B scripts/local_stack/crs_check.py --config "$CFG" --out "$EVIDENCE/crs-check" --work "$WORK/crs-check" 2>&1 | tee "$EVIDENCE/crs-check.stdout.txt"
echo "ALL CHECKS FINISHED"
