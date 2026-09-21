#!/usr/bin/env bash
# firewall-IA Docker Lab — infrastructure smoke tests, host side.
#
# Sequences the four checks of docker/README.md. The fail-closed case needs the
# control plane stopped and restarted, which the client container cannot and must
# not do itself (that would mean handing it the Docker socket), so it is driven
# from here.
#
# INFRASTRUCTURE ONLY. These are not External Test v1, not an evaluation and not a
# benchmark. No accuracy, FPR, FNR or latency claim may be derived from the output.
#
#   ./docker/smoke_test.sh
#
# Exits non-zero if any check fails. Always attempts to restore the control plane.

set -uo pipefail

cd "$(dirname "$0")/.." || exit 1

COMPOSE="${COMPOSE:-docker compose}"
LOG_DIR="${LAB_LOG_DIR:-./docker/.lab-logs}"
ACCESS_LOG="$LOG_DIR/destination-access.jsonl"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
RUN_LOG="$LOG_DIR/smoke-$RUN_ID.log"
failures=0

mkdir -p "$LOG_DIR"

# Everything this run prints is kept on disk, not only in a terminal that scrolls
# away: docs/ml_evaluation_methodology.md section 13 requires per-run logs stored with
# the run's results, and a previous experiment's raw data was lost to /tmp
# (reports/diagnostics/real-http-fp-v1 exists because of that). The log lives under
# the repository, gitignored, ready to be promoted into reports/ if the run matters.
exec > >(tee -a "$RUN_LOG") 2>&1
echo "firewall-IA Docker Lab smoke run $RUN_ID"
echo "log: $RUN_LOG"

say()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
fail() { printf '\033[31mFAIL\033[0m %s\n' "$*"; failures=$((failures + 1)); }
pass() { printf '\033[32mPASS\033[0m %s\n' "$*"; }

# Container state of a service, or "absent" when it has none. Same `ps --format json`
# parsing the health wait below already relies on.
service_state() {
  $COMPOSE ps -a --format json "$1" 2>/dev/null \
    | grep -o '"State":"[a-z]*"' | head -1 | cut -d'"' -f4 \
    | grep . || echo absent
}

# Guard for the fail-closed case. A 503 only proves fail-closed if the classifier was
# genuinely down when the request was sent; if anything restarted it, a 200 (or even a
# 503 from a half-started service) would be measuring nothing.
assert_control_plane_stopped() {
  state=$(service_state control-plane)
  if [ "$state" = "running" ]; then
    fail "control plane is '$state' — the fail-closed case cannot be trusted"
    return 1
  fi
  pass "control plane confirmed '$state' before the request"
  return 0
}

restore_control_plane() {
  say "restoring the control plane"
  $COMPOSE start control-plane >/dev/null 2>&1
  # Wait for the healthcheck to report the model loaded again.
  for _ in $(seq 1 60); do
    state=$($COMPOSE ps --format json control-plane 2>/dev/null | grep -o '"Health":"[a-z]*"' | head -1)
    [ "$state" = '"Health":"healthy"' ] && { pass "control plane healthy again"; return 0; }
    sleep 2
  done
  fail "control plane did not become healthy again"
}
trap restore_control_plane EXIT

# ── A. startup / readiness ────────────────────────────────────────────────
say "A. startup and readiness"
$COMPOSE up -d control-plane data-plane destination || exit 1

printf 'waiting for the control plane healthcheck (model load)'
healthy=0
for _ in $(seq 1 90); do
  state=$($COMPOSE ps --format json control-plane 2>/dev/null | grep -o '"Health":"[a-z]*"' | head -1)
  if [ "$state" = '"Health":"healthy"' ]; then healthy=1; break; fi
  printf '.'; sleep 2
done
printf '\n'
if [ "$healthy" = 1 ]; then
  pass "control plane healthy (/health reports model_loaded: true)"
else
  fail "control plane never became healthy"
  $COMPOSE logs --tail 40 control-plane
fi

$COMPOSE ps

# Record where the destination log stands before any smoke traffic.
before=$( [ -f "$ACCESS_LOG" ] && wc -l < "$ACCESS_LOG" || echo 0 )
echo "destination receipts before smoke traffic: $before"

# ── B. ALLOW ──────────────────────────────────────────────────────────────
say "B. ALLOW path"
if $COMPOSE run --rm client allow; then pass "ALLOW forwarded and received"; else fail "ALLOW case"; fi

# ── C. BLOCK ──────────────────────────────────────────────────────────────
say "C. BLOCK path"
if $COMPOSE run --rm client block; then pass "BLOCK answered 403 and not forwarded"; else fail "BLOCK case"; fi

# ── D. fail-closed ────────────────────────────────────────────────────────
# `--no-deps` is REQUIRED here, and only here. The client depends on data-plane, which
# depends on control-plane with `condition: service_healthy`, so a plain
# `compose run client` resolves that graph, RESTARTS the classifier just stopped and
# waits until it is healthy. The first run hit exactly that: the request got a normal
# ALLOW/200 and reached the destination, testing nothing. data-plane and destination are
# already up from phase A, so skipping dependency resolution costs nothing.
say "D. fail-closed path (classifier made unavailable)"
$COMPOSE stop control-plane || fail "could not stop the control plane"
if assert_control_plane_stopped; then
  if $COMPOSE run --rm --no-deps client failclosed; then
    # Re-check afterwards: a 503 from a classifier that came back mid-request would be
    # a race, not fail-closed.
    after=$(service_state control-plane)
    if [ "$after" = "running" ]; then
      fail "control plane was '$after' after the request — fail-closed result is not trustworthy"
    else
      pass "fail-closed 503 and not forwarded (classifier '$after' throughout)"
    fi
  else
    fail "fail-closed case"
  fi
else
  fail "fail-closed case SKIPPED — classifier was not stopped, result would be meaningless"
fi

# restore_control_plane runs from the EXIT trap, then re-verify normal operation.
restore_control_plane
trap - EXIT

say "E. normal operation restored"
if $COMPOSE run --rm client allow; then pass "ALLOW works again after restart"; else fail "post-restore ALLOW"; fi

# ── Service logs, captured with the run ───────────────────────────────────
say "service logs (kept with this run)"
for svc in control-plane data-plane destination; do
  echo "----- $svc -----"
  $COMPOSE logs --no-color --tail 200 "$svc" 2>&1
done

say "summary"
echo "destination receipt log: $ACCESS_LOG"
echo "this run's log:          $RUN_LOG"
if [ "$failures" = 0 ]; then
  printf '\033[32mall infrastructure smoke checks passed\033[0m\n'
  echo "These are plumbing checks. They are NOT External Test v1 and imply no model metric."
  exit 0
fi
printf '\033[31m%d check(s) failed\033[0m\n' "$failures"
exit 1
