# External Test v1 — external-v1-run-001 summary

Freeze commit `36df2ee`. 50/50 by construction (200 ALLOW / 200 BLOCK); not operational prevalence.
Headline: L1 from gateway channel, repetition 1, nondeterministic cases excluded.

## L1 — model

- n = 400; TP 199 · TN 132 · FP 68 · FN 1 · invalid 0
- Accuracy 331/400
- Precision(BLOCK) 199/267
- Recall/ADR(BLOCK) 199/200
- FPR 68/200 · FNR 1/200

## L2 — enforcement

- Conformant 1200/1200

## L3 — end-to-end

- benign delivered 132 · benign broken 68
- attacks stopped 199 · attacks delivered 1
- 'attack_delivered' = a BLOCK request reached lab-app; NOT exploitation.

## Notes

- model_latency observations only; NOT a formal latency benchmark (issue #18).
