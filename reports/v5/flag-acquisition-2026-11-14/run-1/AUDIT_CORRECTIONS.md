# Independent interpretation review — 14 November 2026

Codex reviewed retained cases, generator, trial/oracle implementation, all 30 H1 row files,
run summaries, cleanup records, seals and the public metrics. This is a CPU/read-only audit,
not another acquisition run. Original measured rows, metric values and case hashes are unchanged.
This note qualifies the earlier narrative in RESULTS, PROTOCOL, HANDOFF and D86.

## What the recorded outcomes establish

| Outcome, three repetitions per primitive | Direct | Candidate prevented | V5-only / fastv5 / CRS prevented |
| --- | --- | --- | --- |
| CatP1cs exploit-driven flag retrieval | 3/3 flags | 3/3, V5 | 3/3 each |
| Inf3ct exploit-driven flag retrieval | 3/3 flags | 3/3, request_guard | 0/3 each |
| An0nB0ard SQLi credential disclosure | 3/3 credential reads | 3/3, V5 | 3/3 each |
| An0nB0ard independent fixed-credential login | 3/3 flags | 0/3; flag returned on all arms | 0/3 each; legitimate login |
| D33pTh0ught legitimate correct answer | 3/3 flags | 0/3; correctly allowed | 0/3 each; correctly allowed |

The candidate's combined **9/9 prevented exploit primitives** is **6/6 flag retrievals**
plus **3/3 credential disclosures**. The corresponding other-arm total 6/9 is 3/6 flag
retrievals plus 3/3 disclosures. These are repeated primitives, not independent techniques.
Flag responses were recorded in four of six apps on direct; this does not mean only four
apps can have an HTTP flag (ag3ncy's password branch remains unmeasured).

## An0nB0ard chain qualification

The sealed generator defines the known seeded credential before replay and places it
literally in the login case. SQLi and login use separate session IDs. The client replays
sealed cases; it does not extract a value from the SQLi response and use that value to
construct or conditionally permit the login. The login's flag oracle succeeds on every arm.

The SQLi response does disclose the credential according to its recorded oracle, and each
firewall blocks that disclosure before app receipt. This is a useful measured security
result. However, a claim that the firewall experimentally prevented An0nB0ard's complete
flag-acquisition chain, or that the login password was unknown to the test constructor,
is not supported. Blocking disclosure would break a chain for an attacker who depended
on that disclosure; that is an inference with an explicit knowledge assumption, not the
measured login result. No new chain is run merely to improve an administrative closure.

## Evidence strength

Thirty ROWS hashes and eighteen case/seal/score hashes match. All 260 H1 rows agree with
their run transport, source-case identity and summaries; all 30 cleanup records are clean.
Twenty target/arm count comparisons match METRICS. The 451 frozen sources and 70 Model-2
bound immutable sources are intact. No model, dataset, decoder or policy was changed.

The trial evaluates full-string body oracles at request time and retains response hashes,
sizes and oracle outcomes in ROWS. This review independently recounts those outcomes and
checks the oracle/case definitions; it does not reconstruct full response bodies from hashes
or claim a second independent full-body examination. Existing plaintext bodies should not
be inferred from the phrase 'raw runs'. ObC00ki3s and ag3ncy retain their declared limits.

## Transport history

Primary run-1 metrics cover `h1_tls_new`. An existing Inf3ct H2 exploration was also found:
five arms, 21 rows per arm, 105 rows total, all row hashes verified and all cleanup records
clean. Its metadata is preserved in [H2_SCOPE_RECORD.json](H2_SCOPE_RECORD.json).
It remains excluded from primary run-1 totals and is not credited to the 13 November H2
subset. The documentation task prohibited new measurement runs; it did not require
erasing already collected evidence. No claim of independent preregistration or complete
six-app H2 coverage follows from preserving these records.
