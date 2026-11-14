# Public audit records

Copied byte for byte on 2026-11-14 from the closed architecture coordination directory.
Original audit, coverage and freeze records are preserved; copy digests are in
[COPIED_SOURCE_SHA256.json](COPIED_SOURCE_SHA256.json).

- [AUDIT_FINAL.md](AUDIT_FINAL.md): independent C1–C5 recount, adjudications, limits and closure.
- [CROSS_REVIEW_CLAUDE.md](CROSS_REVIEW_CLAUDE.md): reciprocal check of runtime/policy semantics.
- [METRICS_COVERAGE_FINAL.md](METRICS_COVERAGE_FINAL.md) and
  [JSON](METRICS_COVERAGE_FINAL.json): M01–M35 measured/partial/not-applicable coverage.
- [SOURCE_FREEZE.json](SOURCE_FREEZE.json): original 451-file frozen manifest, with original absolute paths.

The audit retains its historical errata section; the results report already incorporates those
corrections. Its earlier AUDITING/DONE wording records that handoff and is not the status of the new
flag campaign. Subsequent documentation updates do not change the measured runtime identity.

This public package contains counts, hashes and audit findings. It does not redistribute private
request bodies, raw campaigns, credentials or model weights. Rechecking every frozen entry requires
the original local artifacts, including ignored model files and coordination records. A fresh clone
alone cannot reproduce those checks or acquire the selected trained adapter.
