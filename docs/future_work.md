# Future work and remaining deployment work

This file preserves research proposals independently of the current PC integration.
Listing an item here does not mean it was implemented, experimentally accepted or academically removed
from the approved plan. Issue state changes need their own reason and reference.

## Embedded deployment path

- [#10](https://github.com/SebasHT15/firewall-IA/issues/10) and
  [#11](https://github.com/SebasHT15/firewall-IA/issues/11): reconcile historical V4/smoke merge and
  quantization evidence with export of the selected V5.1 model. Q4_K_M was experimentally rejected;
  producing an artifact did not approve it for security decisions.
- [#12](https://github.com/SebasHT15/firewall-IA/issues/12):
  integrate the selected destination inference backend with template/tokenization/parser parity.
- [#13](https://github.com/SebasHT15/firewall-IA/issues/13) and
  [#14](https://github.com/SebasHT15/firewall-IA/issues/14):
  compare security, latency, memory and size under a frozen, comparable evaluation protocol.
- [#19](https://github.com/SebasHT15/firewall-IA/issues/19) through
  [#22](https://github.com/SebasHT15/firewall-IA/issues/22):
  requirements, platform selection, physical deployment and measurement.

Historical V4 exports do not constitute an export of the selected V5.1 adapter.
Docker on the development laptop does not complete the physical embedded objective.

## Research proposals outside the current PC result

| Issue | Question / deliverable | What current evidence does not establish |
| --- | --- | --- |
| [#27](https://github.com/SebasHT15/firewall-IA/issues/27) | Evaluate the reserved 19,165 CSIC anomalies under independent ground-truth treatment. | Six challenge apps do not evaluate that reserved corpus. |
| [#29](https://github.com/SebasHT15/firewall-IA/issues/29) | Held-out evasion evaluation with seen/held-out transform families and distinct base payload identities. | The 65 attack sessions are not a substitute for this transformation-family protocol. |
| [#30](https://github.com/SebasHT15/firewall-IA/issues/30) | Design a genuinely stateful classifier using request history/application state and compare it with stateless classification. | Evaluating multi-step sessions does not make the model stateful. |
| [#31](https://github.com/SebasHT15/firewall-IA/issues/31) | Define an advanced telemetry/SIEM integration and its operational acceptance criteria. | Structured local logs alone do not demonstrate a SIEM integration. |

The PC integration adopts an outside-this-delivery disposition for these proposals under the owner's
closeout instruction (D87). A `not_planned` closure records that scope decision, not completion or
negative experimental evidence. Their original issue descriptions remain the historical requirements.

## Legacy security and broader validation

- [#65](https://github.com/SebasHT15/firewall-IA/issues/65): V5 uses template-safe tokenization,
  but V4's prompt input issue remains unresolved. Its functional steering effect and ordinary textual
  role-marker risk are not established by tokenizer-only evidence. V4 operational support is retired
  in this PC delivery; closing #65 as not_planned does not patch the defect. Reintroduction needs its
  DEV diagnostic, train/serve fix and special-ID invariant/revalidation, plus admission-control work.
- V4 has no admission control under overload and is not a supported fallback for this candidate.
  Historical reproduction modes remain available in isolation.
- A general header-aware model representation, stored-HTML prevention, organic traffic evaluation,
  adaptive adversaries, prolonged soak and isolated energy measurements require separate protocols.
  The [14 November flag campaign](../reports/v5/flag-acquisition-2026-11-14/run-1/RESULTS.md) reconfirmed
  that header-borne SSTI is caught only by the app-bound deterministic guard (not by V5.1 under
  `canonical-request/v1`, and not by CRS PL1); a general header-aware representation remains future work.
- Protected datasets remain protected; documentation cleanup is not authorization to tune on them.

## Explicitly retained criteria from retired umbrella issues

See the [requirement map](integration_resolution_2026-11-14.md) for every #68 item and the
#18/#38 performance boundary. Remaining work includes original inbound-wire-byte attestation,
broader proxy/H2/H3 support, contextual JWT/origin signals, general decoder-window/production-policy
validation, and a complete no-Fast-Path direct/gateway cold-start and paired-added-latency matrix.
Their retirement from this PC integration does not accredit them as implemented. The destination
runtime and embedded benchmarks (#14/#22) must identify applicable timing gaps before measuring.
