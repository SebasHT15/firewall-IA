| Comparison | Block | N | A→A | A→B | B→A | B→B | flip rate [95% CI] | cond. A→B | base ALLOW | McNemar p | Holm p | Class | Flags |
|---|---|---:|---:|---:|---:|---:|---|---:|---:|---:|---:|---|---|
| `F2-ADDR:n_prose->n_street` | CONTENT | 30 | 6 | 22 | 0 | 2 | 0.73 [0.54, 0.88] | 0.79 | 0.93 | 0.0000 | 0.0000 | STRONG EFFECT (A→B) |  |
| `F2-ADDR:n_prose->n_numfmt` | CONTENT | 30 | 23 | 5 | 2 | 0 | 0.23 [0.10, 0.42] | 0.18 | 0.93 | 0.4531 | 1.0000 | WEAK/INCONCLUSIVE |  |
| `F2-ADDR:n_numfmt->n_street` | CONTENT | 30 | 5 | 20 | 1 | 4 | 0.70 [0.51, 0.85] | 0.80 | 0.83 | 0.0000 | 0.0001 | STRONG EFFECT (A→B) |  |
| `F2-ADDR:n_prose->a_prose` | CONTENT | 30 | 25 | 3 | 0 | 2 | 0.10 [0.02, 0.27] | 0.11 | 0.93 | 0.2500 | 1.0000 | WEAK/INCONCLUSIVE |  |
| `F2-ADDR:n_street->a_street` | CONTENT | 30 | 2 | 4 | 0 | 24 | 0.13 [0.04, 0.31] | 0.67 | 0.20 | 0.1250 | 0.6250 | WEAK/INCONCLUSIVE | UNTESTABLE_A_TO_B |
| `F2-ADDR:n_prose->n2_prose` | CONTENT | 30 | 28 | 0 | 2 | 0 | 0.07 [0.01, 0.22] | 0.00 | 0.93 | 0.5000 | 1.0000 | WEAK/INCONCLUSIVE |  |
| `F2-HASH:base->hash` | CONTENT | 60 | 8 | 32 | 1 | 19 | 0.55 [0.42, 0.68] | 0.80 | 0.67 | 0.0000 | 0.0000 | STRONG EFFECT (A→B) |  |
| `F2-HASH:base->punct` | CONTENT | 60 | 8 | 32 | 0 | 20 | 0.53 [0.40, 0.66] | 0.80 | 0.67 | 0.0000 | 0.0000 | STRONG EFFECT (A→B) |  |
| `F2-HASH:punct->hash` | CONTENT | 60 | 1 | 7 | 8 | 44 | 0.25 [0.15, 0.38] | 0.88 | 0.13 | 1.0000 | 1.0000 | WEAK/INCONCLUSIVE | UNTESTABLE_A_TO_B |
| `F2-APOS:plain->apostrophe` | CONTENT | 75 | 34 | 37 | 0 | 4 | 0.49 [0.38, 0.61] | 0.52 | 0.95 | 0.0000 | 0.0000 | STRONG EFFECT (A→B) |  |
| `CONTROL-COV2:val_a->val_b` | CONTROL | 40 | 33 | 5 | 2 | 0 | 0.17 [0.07, 0.33] | 0.13 | 0.95 | 0.4531 | — | WEAK/INCONCLUSIVE |  |
