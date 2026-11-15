# Tablas de la corrida

Generado por `load_analyze.py`. Percentiles agrupados sobre las filas, nunca promediados. Tasas por repetición como media [mín-máx]. Criterios de saturación descriptivos: no son un SLO. Nada aquí aprueba un candidato.

| Configuración y modo | r/s | Ofrecidas | Completas | Útil r/s | 503 | 502 | Timeouts | Errores | Cortadas | P50 | P95 | P99 | Saturadas |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| candidate/CASCADE_ACTIVE | 1 | 96 | 96 | 1.07 [0.93-1.17] | 0 | 0 | 0 | 0 | 0 | 302.3 | 532.5 | 683.5 | 0/3 |
| candidate/CASCADE_ACTIVE | 2 | 171 | 171 | 1.90 [1.57-2.23] | 0 | 0 | 0 | 0 | 0 | 305.9 | 674.6 | 753.5 | 0/3 |
| candidate/CASCADE_ACTIVE | 3 | 249 | 249 | 2.75 [2.53-3.11] | 1 | 0 | 0 | 0 | 0 | 383.3 | 1009.4 | 1287.1 | 0/3 |
| candidate/CASCADE_ACTIVE | 4 | 354 | 354 | 3.86 [3.68-3.99] | 2 | 0 | 0 | 0 | 0 | 643.4 | 1736.5 | 2093.8 | 1/3 |
| candidate/CASCADE_ACTIVE | 6 | 581 | 581 | 4.45 [4.36-4.56] | 133 | 0 | 0 | 0 | 0 | 3387.4 | 4186.8 | 4252.1 | 3/3 |
| candidate/CASCADE_ACTIVE | 8 | 489 | 489 | 4.52 [4.47-4.56] | 185 | 0 | 0 | 0 | 0 | 3771.5 | 4257.4 | 4331.5 | 2/2 |
| candidate/V5_ONLY | 1 | 96 | 96 | 1.07 [0.93-1.17] | 0 | 0 | 0 | 0 | 0 | 303.2 | 538.6 | 686.4 | 0/3 |
| candidate/V5_ONLY | 2 | 171 | 171 | 1.90 [1.57-2.23] | 0 | 0 | 0 | 0 | 0 | 309.6 | 770.6 | 962.8 | 0/3 |
| candidate/V5_ONLY | 3 | 249 | 249 | 2.74 [2.53-3.07] | 2 | 0 | 0 | 0 | 0 | 513.7 | 1243.4 | 1417.3 | 0/3 |
| candidate/V5_ONLY | 4 | 354 | 354 | 3.62 [3.59-3.66] | 3 | 0 | 0 | 0 | 0 | 1962.9 | 3421.2 | 3632.7 | 3/3 |
| candidate/V5_ONLY | 6 | 581 | 581 | 3.64 [3.44-3.76] | 215 | 0 | 0 | 0 | 0 | 3927.8 | 4303.6 | 4458.6 | 3/3 |

| Soak agrupado | Ofrecidas | Completas | Útiles | P50 | P95 | P99 |
|---|---:|---:|---:|---:|---:|---:|
| soak_candidate_CASCADE_ACTIVE | 1041 | 1041 | 1039 | 302.5 | 676.7 | 964.1 |
| soak_candidate_V5_ONLY | 1041 | 1041 | 1037 | 320.3 | 987.1 | 1453.0 |

| Soak por ruta y etapa, agrupado | n | P50 | P95 | P99 |
|---|---:|---:|---:|---:|
| soak_candidate_CASCADE_ACTIVE / model2 / gateway | 197 | 1.5 | 3.2 | 3.5 |
| soak_candidate_CASCADE_ACTIVE / model2 / admission | 197 | 0.0 | 0.0 | 0.1 |
| soak_candidate_CASCADE_ACTIVE / model2 / binding | 197 | 0.1 | 0.2 | 0.7 |
| soak_candidate_CASCADE_ACTIVE / model2 / canonical | 197 | 0.5 | 0.9 | 1.0 |
| soak_candidate_CASCADE_ACTIVE / model2 / canonical_with_wait | 197 | 0.5 | 1.0 | 1.1 |
| soak_candidate_CASCADE_ACTIVE / model2 / fast_path | 197 | 0.0 | 0.1 | 0.1 |
| soak_candidate_CASCADE_ACTIVE / model2 / model2 | 394 | 0.5 | 1.1 | 1.3 |
| soak_candidate_CASCADE_ACTIVE / v5 / gateway | 884 | 298.5 | 698.5 | 1017.3 |
| soak_candidate_CASCADE_ACTIVE / v5 / admission | 884 | 0.0 | 0.0 | 0.0 |
| soak_candidate_CASCADE_ACTIVE / v5 / binding | 884 | 0.1 | 0.2 | 0.2 |
| soak_candidate_CASCADE_ACTIVE / v5 / canonical | 884 | 0.6 | 1.0 | 1.4 |
| soak_candidate_CASCADE_ACTIVE / v5 / canonical_with_wait | 884 | 0.6 | 1.1 | 1.4 |
| soak_candidate_CASCADE_ACTIVE / v5 / fast_path | 884 | 0.0 | 0.1 | 0.1 |
| soak_candidate_CASCADE_ACTIVE / v5 / model2 | 1768 | 0.7 | 1.1 | 1.2 |
| soak_candidate_CASCADE_ACTIVE / v5 / v5 | 884 | 296.0 | 697.4 | 1015.9 |
| soak_candidate_CASCADE_ACTIVE / v5 / v5_hop | 884 | 296.0 | 697.4 | 1015.9 |
| soak_candidate_CASCADE_ACTIVE / v5 / v5_hop_outside_service | 884 | 1.8 | 2.6 | 8.3 |
| soak_candidate_CASCADE_ACTIVE / v5 / v5_inference | 884 | 285.4 | 298.0 | 310.0 |
| soak_candidate_CASCADE_ACTIVE / v5 / v5_queue | 884 | 0.0 | 427.7 | 725.0 |
| soak_candidate_CASCADE_ACTIVE / v5 / v5_service | 884 | 293.8 | 695.8 | 1014.6 |
| soak_candidate_CASCADE_ACTIVE / v5 / decoder native | 884 | 285.4 | 298.0 | 310.0 |
| soak_candidate_V5_ONLY / v5 / gateway | 1081 | 312.0 | 970.8 | 1463.3 |
| soak_candidate_V5_ONLY / v5 / admission | 1081 | 0.0 | 0.0 | 0.1 |
| soak_candidate_V5_ONLY / v5 / binding | 1081 | 0.1 | 0.2 | 0.2 |
| soak_candidate_V5_ONLY / v5 / canonical | 1081 | 0.5 | 0.9 | 1.3 |
| soak_candidate_V5_ONLY / v5 / canonical_with_wait | 1081 | 0.5 | 1.0 | 1.4 |
| soak_candidate_V5_ONLY / v5 / v5 | 1081 | 311.0 | 969.9 | 1462.5 |
| soak_candidate_V5_ONLY / v5 / v5_hop | 1081 | 311.0 | 969.9 | 1462.5 |
| soak_candidate_V5_ONLY / v5 / v5_hop_outside_service | 1081 | 1.7 | 2.6 | 3.3 |
| soak_candidate_V5_ONLY / v5 / v5_inference | 1079 | 281.5 | 295.5 | 325.0 |
| soak_candidate_V5_ONLY / v5 / v5_no_generation | 2 | 1.0 | 1.0 | 1.0 |
| soak_candidate_V5_ONLY / v5 / v5_queue | 1081 | 39.8 | 704.6 | 1195.0 |
| soak_candidate_V5_ONLY / v5 / v5_service | 1081 | 309.6 | 967.5 | 1461.3 |
| soak_candidate_V5_ONLY / v5 / decoder native | 1079 | 281.5 | 295.5 | 325.0 |
| soak_candidate_V5_ONLY / v5 / decoder no_generation | 2 | 1.0 | 1.0 | 1.0 |

| Recuperación | Recuperó | Segundos | Sondas |
|---|---|---:|---:|
| recovery_candidate_CASCADE_ACTIVE_rep1 | True | 4.0 | 15 |
| recovery_candidate_CASCADE_ACTIVE_rep2 | True | 4.0 | 15 |
| recovery_candidate_V5_ONLY_rep1 | True | 5.0 | 15 |
| recovery_candidate_V5_ONLY_rep2 | True | 5.0 | 15 |

Fallos de `failures_candidate_rep1`: canonical_after_kill 2.2 s, gateway_after_restart 1.3 s, guard_after_stop 2.1 s, model2_after_hang 3.6 s, model2_after_kill 2.6 s, sink_after_restart 3.1 s, v5_after_hang_resumed 1.8 s, v5_after_restart 5.3 s

Fallos de `failures_candidate_rep2`: canonical_after_kill 2.7 s, gateway_after_restart 2.7 s, guard_after_stop 3.0 s, model2_after_hang 0.6 s, model2_after_kill 1.5 s, sink_after_restart 0.4 s, v5_after_hang_resumed 3.9 s, v5_after_restart 5.0 s
