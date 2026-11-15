| Comparison | Block | N | A→A | A→B | B→A | B→B | flip rate [95% CI] | base ALLOW | McNemar p | Holm p | Class | Flags |
|---|---|---:|---:|---:|---:|---:|---|---:|---:|---:|---|---|
| `F-CL:absent->present` | ENVELOPE | 40 | 32 | 1 | 0 | 7 | 0.03 [0.00, 0.13] | 0.82 | 1.0000 | 1.0000 | WEAK/INCONCLUSIVE | LOW_SENSITIVITY_B_TO_A |
| `F-CL:absent->te_chunked` | ENVELOPE | 40 | 15 | 18 | 0 | 7 | 0.45 [0.29, 0.62] | 0.82 | 0.0000 | 0.0001 | STRONG EFFECT | LOW_SENSITIVITY_B_TO_A |
| `F-PORT:none->port_8080` | ENVELOPE | 30 | 29 | 0 | 0 | 1 | 0.00 [0.00, 0.12] | 0.97 | 1.0000 | 1.0000 | NO OBSERVED EFFECT | LOW_SENSITIVITY_B_TO_A |
| `F-PORT:none->port_8443` | ENVELOPE | 30 | 29 | 0 | 0 | 1 | 0.00 [0.00, 0.12] | 0.97 | 1.0000 | 1.0000 | NO OBSERVED EFFECT | LOW_SENSITIVITY_B_TO_A |
| `F-PORT:none->port_30000` | ENVELOPE | 30 | 29 | 0 | 0 | 1 | 0.00 [0.00, 0.12] | 0.97 | 1.0000 | 1.0000 | NO OBSERVED EFFECT | LOW_SENSITIVITY_B_TO_A |
| `F-HOSTIP:dns->ip_127.0.0.1` | ENVELOPE | 30 | 27 | 0 | 0 | 3 | 0.00 [0.00, 0.12] | 0.90 | 1.0000 | 1.0000 | NO OBSERVED EFFECT | LOW_SENSITIVITY_B_TO_A |
| `F-HOSTIP:dns->ip_10.0.0.5` | ENVELOPE | 30 | 27 | 0 | 0 | 3 | 0.00 [0.00, 0.12] | 0.90 | 1.0000 | 1.0000 | NO OBSERVED EFFECT | LOW_SENSITIVITY_B_TO_A |
| `F-HOSTIP:dns->ip_203.0.113.10` | ENVELOPE | 30 | 27 | 0 | 0 | 3 | 0.00 [0.00, 0.12] | 0.90 | 1.0000 | 1.0000 | NO OBSERVED EFFECT | LOW_SENSITIVITY_B_TO_A |
| `F-HOSTIP:ip_203.0.113.10->ip_127.0.0.1` | ENVELOPE | 30 | 27 | 0 | 0 | 3 | 0.00 [0.00, 0.12] | 0.90 | 1.0000 | 1.0000 | NO OBSERVED EFFECT | LOW_SENSITIVITY_B_TO_A |
| `F-HOSTIP:ip_203.0.113.10->ip_10.0.0.5` | ENVELOPE | 30 | 27 | 0 | 0 | 3 | 0.00 [0.00, 0.12] | 0.90 | 1.0000 | 1.0000 | NO OBSERVED EFFECT | LOW_SENSITIVITY_B_TO_A |
| `F-PXY:absent->present` | ENVELOPE | 30 | 26 | 0 | 0 | 4 | 0.00 [0.00, 0.12] | 0.87 | 1.0000 | 1.0000 | NO OBSERVED EFFECT | LOW_SENSITIVITY_B_TO_A |
| `F-NQUERY:n1->n2` | CONTENT | 30 | 30 | 0 | 0 | 0 | 0.00 [0.00, 0.12] | 1.00 | 1.0000 | 1.0000 | NO OBSERVED EFFECT | LOW_SENSITIVITY_B_TO_A |
| `F-NQUERY:n1->n4` | CONTENT | 30 | 30 | 0 | 0 | 0 | 0.00 [0.00, 0.12] | 1.00 | 1.0000 | 1.0000 | NO OBSERVED EFFECT | LOW_SENSITIVITY_B_TO_A |
| `F-NFIELDS:n1->n2` | CONTENT | 30 | 21 | 0 | 1 | 8 | 0.03 [0.00, 0.17] | 0.70 | 1.0000 | 1.0000 | WEAK/INCONCLUSIVE | LOW_SENSITIVITY_B_TO_A |
| `F-NFIELDS:n1->n3` | CONTENT | 30 | 21 | 0 | 2 | 7 | 0.07 [0.01, 0.22] | 0.70 | 0.5000 | 1.0000 | WEAK/INCONCLUSIVE | LOW_SENSITIVITY_B_TO_A |
| `F-NFIELDS:n1->n5` | CONTENT | 30 | 21 | 0 | 2 | 7 | 0.07 [0.01, 0.22] | 0.70 | 0.5000 | 1.0000 | WEAK/INCONCLUSIVE | LOW_SENSITIVITY_B_TO_A |
| `F-NFIELDS:n1_cl->n2_cl` | CONTENT | 30 | 21 | 0 | 1 | 8 | 0.03 [0.00, 0.17] | 0.70 | 1.0000 | 1.0000 | WEAK/INCONCLUSIVE | LOW_SENSITIVITY_B_TO_A |
| `F-PWD:alnum->bang` | CONTENT | 30 | 29 | 1 | 0 | 0 | 0.03 [0.00, 0.17] | 1.00 | 1.0000 | 1.0000 | WEAK/INCONCLUSIVE | LOW_SENSITIVITY_B_TO_A |
| `F-PWD:alnum->hash` | CONTENT | 30 | 11 | 19 | 0 | 0 | 0.63 [0.44, 0.80] | 1.00 | 0.0000 | 0.0001 | STRONG EFFECT | LOW_SENSITIVITY_B_TO_A |
| `F-PWD:alnum->dash` | CONTENT | 30 | 30 | 0 | 0 | 0 | 0.00 [0.00, 0.12] | 1.00 | 1.0000 | 1.0000 | NO OBSERVED EFFECT | LOW_SENSITIVITY_B_TO_A |
| `F-PWD:alnum->at` | CONTENT | 30 | 27 | 3 | 0 | 0 | 0.10 [0.02, 0.27] | 1.00 | 0.2500 | 1.0000 | WEAK/INCONCLUSIVE | LOW_SENSITIVITY_B_TO_A |
| `F-APOS:plain->apostrophe` | CONTENT | 30 | 0 | 30 | 0 | 0 | 1.00 [0.88, 1.00] | 1.00 | 0.0000 | 0.0000 | STRONG EFFECT | LOW_SENSITIVITY_B_TO_A |
| `F-ADDR:plain->comma` | CONTENT | 30 | 4 | 0 | 0 | 26 | 0.00 [0.00, 0.12] | 0.13 | 1.0000 | 1.0000 | NO OBSERVED EFFECT | LOW_SENSITIVITY_A_TO_B |
| `F-ADDR:plain->hash` | CONTENT | 30 | 0 | 4 | 0 | 26 | 0.13 [0.04, 0.31] | 0.13 | 0.1250 | 1.0000 | WEAK/INCONCLUSIVE | LOW_SENSITIVITY_A_TO_B |
| `F-ADDR:comma->hash` | CONTENT | 30 | 0 | 4 | 0 | 26 | 0.13 [0.04, 0.31] | 0.13 | 0.1250 | 1.0000 | WEAK/INCONCLUSIVE | LOW_SENSITIVITY_A_TO_B |
| `F-PUNCT:comma_period->semicolon` | CONTENT | 30 | 23 | 1 | 1 | 5 | 0.07 [0.01, 0.22] | 0.80 | 1.0000 | 1.0000 | WEAK/INCONCLUSIVE | LOW_SENSITIVITY_B_TO_A |
| `F-PUNCT:comma_period->ampersand` | CONTENT | 30 | 24 | 0 | 1 | 5 | 0.03 [0.00, 0.17] | 0.80 | 1.0000 | 1.0000 | WEAK/INCONCLUSIVE | LOW_SENSITIVITY_B_TO_A |
| `F-PUNCT:comma_period->exclamation` | CONTENT | 30 | 22 | 2 | 0 | 6 | 0.07 [0.01, 0.22] | 0.80 | 0.5000 | 1.0000 | WEAK/INCONCLUSIVE | LOW_SENSITIVITY_B_TO_A |
| `F-PUNCT:comma_period->question` | CONTENT | 30 | 20 | 4 | 0 | 6 | 0.13 [0.04, 0.31] | 0.80 | 0.1250 | 1.0000 | WEAK/INCONCLUSIVE | LOW_SENSITIVITY_B_TO_A |
| `F-WORD:neutral->homonym` | CONTENT | 60 | 56 | 0 | 2 | 2 | 0.03 [0.00, 0.12] | 0.93 | 0.5000 | 1.0000 | WEAK/INCONCLUSIVE | LOW_SENSITIVITY_B_TO_A |
| `F-FREETEXT:keyword->sentence` | CONTENT | 30 | 26 | 4 | 0 | 0 | 0.13 [0.04, 0.31] | 1.00 | 0.1250 | 1.0000 | WEAK/INCONCLUSIVE | LOW_SENSITIVITY_B_TO_A |
| `F-JSON:k1_string->k4_strings` | CONTENT | 30 | 25 | 0 | 5 | 0 | 0.17 [0.06, 0.35] | 0.83 | 0.0625 | 1.0000 | WEAK/INCONCLUSIVE | LOW_SENSITIVITY_B_TO_A |
| `F-JSON:k4_strings->k4_number` | CONTENT | 30 | 30 | 0 | 0 | 0 | 0.00 [0.00, 0.12] | 1.00 | 1.0000 | 1.0000 | NO OBSERVED EFFECT | LOW_SENSITIVITY_B_TO_A |
| `F-JSON:k4_strings->k4_boolean` | CONTENT | 30 | 30 | 0 | 0 | 0 | 0.00 [0.00, 0.12] | 1.00 | 1.0000 | 1.0000 | NO OBSERVED EFFECT | LOW_SENSITIVITY_B_TO_A |
| `F-JSON:k4_strings->k4_nested` | CONTENT | 30 | 28 | 2 | 0 | 0 | 0.07 [0.01, 0.22] | 1.00 | 0.5000 | 1.0000 | WEAK/INCONCLUSIVE | LOW_SENSITIVITY_B_TO_A |
| `F-JSON:k4_strings->k4_array` | CONTENT | 30 | 30 | 0 | 0 | 0 | 0.00 [0.00, 0.12] | 1.00 | 1.0000 | 1.0000 | NO OBSERVED EFFECT | LOW_SENSITIVITY_B_TO_A |
| `F-JSON:k1_cl->k4_cl` | CONTENT | 30 | 23 | 0 | 7 | 0 | 0.23 [0.10, 0.42] | 0.77 | 0.0156 | 0.5000 | WEAK/INCONCLUSIVE | LOW_SENSITIVITY_B_TO_A |
| `F-CTB:form_type->json_type` | CONTENT | 30 | 22 | 0 | 0 | 8 | 0.00 [0.00, 0.12] | 0.73 | 1.0000 | 1.0000 | NO OBSERVED EFFECT | LOW_SENSITIVITY_B_TO_A |
| `F-ENC:pct20->plus` | CONTENT | 30 | 30 | 0 | 0 | 0 | 0.00 [0.00, 0.12] | 1.00 | 1.0000 | 1.0000 | NO OBSERVED EFFECT | LOW_SENSITIVITY_B_TO_A |
| `F-PATH:depth3->depth5` | CONTENT | 30 | 30 | 0 | 0 | 0 | 0.00 [0.00, 0.12] | 1.00 | 1.0000 | 1.0000 | NO OBSERVED EFFECT | LOW_SENSITIVITY_B_TO_A |
| `F-PATH:depth3->encoded_slash` | CONTENT | 30 | 30 | 0 | 0 | 0 | 0.00 [0.00, 0.12] | 1.00 | 1.0000 | 1.0000 | NO OBSERVED EFFECT | LOW_SENSITIVITY_B_TO_A |
| `F-URL:https_same_host->https_external` | CONTENT | 30 | 29 | 0 | 1 | 0 | 0.03 [0.00, 0.17] | 0.97 | 1.0000 | 1.0000 | WEAK/INCONCLUSIVE | LOW_SENSITIVITY_B_TO_A |
| `F-URL:https_external->http_external` | CONTENT | 30 | 12 | 18 | 0 | 0 | 0.60 [0.41, 0.77] | 1.00 | 0.0000 | 0.0003 | STRONG EFFECT | LOW_SENSITIVITY_B_TO_A |
| `F-NAME:note->template` | CONTENT | 30 | 29 | 0 | 1 | 0 | 0.03 [0.00, 0.17] | 0.97 | 1.0000 | 1.0000 | WEAK/INCONCLUSIVE | LOW_SENSITIVITY_B_TO_A |
| `F-NAME:note->callback` | CONTENT | 30 | 28 | 1 | 0 | 1 | 0.03 [0.00, 0.17] | 0.97 | 1.0000 | 1.0000 | WEAK/INCONCLUSIVE | LOW_SENSITIVITY_B_TO_A |
| `F-NAME:note->file` | CONTENT | 30 | 29 | 0 | 1 | 0 | 0.03 [0.00, 0.17] | 0.97 | 1.0000 | 1.0000 | WEAK/INCONCLUSIVE | LOW_SENSITIVITY_B_TO_A |
| `CONTROL-COV:user_a->user_b` | CONTROL | 40 | 35 | 4 | 1 | 0 | 0.12 [0.04, 0.27] | 0.97 | 0.3750 | — | WEAK/INCONCLUSIVE | LOW_SENSITIVITY_B_TO_A |
| `CONTROL-ENV:absent->present` | CONTROL | 30 | 27 | 0 | 0 | 3 | 0.00 [0.00, 0.12] | 0.90 | 1.0000 | — | NO OBSERVED EFFECT | LOW_SENSITIVITY_B_TO_A |
