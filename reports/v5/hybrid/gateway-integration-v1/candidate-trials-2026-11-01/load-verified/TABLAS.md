# Tablas de la corrida

Generado por `load_analyze.py`. Percentiles agrupados sobre las filas, nunca promediados. Tasas por repetición como media [mín-máx]. Criterios de saturación descriptivos: no son un SLO. Nada aquí aprueba un candidato.

| Configuración y modo | r/s | Ofrecidas | Completas | Útil r/s | 503 | 502 | Timeouts | Errores | Cortadas | P50 | P95 | P99 | Saturadas |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| candidate/CASCADE_ACTIVE | 1 | 96 | 96 | 1.07 [0.93-1.17] | 0 | 0 | 0 | 0 | 0 | 85.6 | 185.6 | 232.5 | 0/3 |
| candidate/CASCADE_ACTIVE | 2 | 171 | 171 | 1.90 [1.57-2.23] | 0 | 0 | 0 | 0 | 0 | 90.9 | 195.4 | 248.9 | 0/3 |
| candidate/CASCADE_ACTIVE | 3 | 249 | 249 | 2.75 [2.53-3.13] | 1 | 0 | 0 | 0 | 0 | 93.8 | 220.2 | 330.5 | 0/3 |
| candidate/CASCADE_ACTIVE | 4 | 354 | 354 | 3.91 [3.83-4.00] | 2 | 0 | 0 | 0 | 0 | 88.9 | 230.0 | 336.1 | 0/3 |
| candidate/CASCADE_ACTIVE | 6 | 581 | 581 | 6.44 [6.13-6.83] | 1 | 0 | 0 | 0 | 0 | 103.9 | 401.9 | 560.2 | 0/3 |
| candidate/CASCADE_ACTIVE | 8 | 767 | 767 | 8.48 [7.70-9.23] | 2 | 0 | 0 | 0 | 0 | 132.2 | 454.5 | 594.0 | 0/3 |
| candidate/CASCADE_ACTIVE | 12 | 1090 | 1090 | 11.81 [11.57-12.17] | 0 | 0 | 0 | 0 | 0 | 266.6 | 1318.6 | 1578.9 | 0/3 |
| candidate/CASCADE_ACTIVE | 16 | 1452 | 1452 | 13.07 [12.75-13.53] | 221 | 0 | 0 | 0 | 0 | 1403.0 | 2068.6 | 2471.4 | 2/3 |
| candidate/CASCADE_ACTIVE | 24 | 2204 | 2204 | 13.29 [12.83-13.69] | 936 | 0 | 0 | 0 | 0 | 1735.9 | 2253.8 | 2525.5 | 3/3 |
| candidate/V5_ONLY | 1 | 96 | 96 | 1.07 [0.93-1.17] | 0 | 0 | 0 | 0 | 0 | 89.0 | 203.0 | 271.2 | 0/3 |
| candidate/V5_ONLY | 2 | 171 | 171 | 1.90 [1.57-2.23] | 0 | 0 | 0 | 0 | 0 | 115.8 | 246.0 | 352.0 | 0/3 |
| candidate/V5_ONLY | 3 | 249 | 249 | 2.74 [2.53-3.09] | 2 | 0 | 0 | 0 | 0 | 124.3 | 219.3 | 289.9 | 0/3 |
| candidate/V5_ONLY | 4 | 354 | 354 | 3.90 [3.83-4.00] | 3 | 0 | 0 | 0 | 0 | 131.6 | 293.7 | 366.9 | 0/3 |
| candidate/V5_ONLY | 6 | 581 | 581 | 6.42 [6.10-6.83] | 2 | 0 | 0 | 0 | 0 | 151.6 | 479.0 | 621.7 | 0/3 |
| candidate/V5_ONLY | 8 | 767 | 767 | 8.33 [7.70-8.86] | 3 | 0 | 0 | 0 | 0 | 262.8 | 1142.4 | 1789.8 | 0/3 |
| candidate/V5_ONLY | 12 | 1090 | 1090 | 9.97 [9.64-10.44] | 132 | 0 | 0 | 0 | 0 | 2005.8 | 2552.0 | 2666.6 | 3/3 |
| candidate/V5_ONLY | 16 | 1452 | 1452 | 10.10 [9.85-10.46] | 486 | 0 | 0 | 0 | 0 | 2180.3 | 2624.3 | 2829.4 | 3/3 |

| Soak agrupado | Ofrecidas | Completas | Útiles | P50 | P95 | P99 |
|---|---:|---:|---:|---:|---:|---:|
| soak_candidate_CASCADE_ACTIVE | 2732 | 2732 | 2727 | 97.4 | 305.9 | 459.4 |
| soak_candidate_V5_ONLY | 2732 | 2732 | 2721 | 142.9 | 429.8 | 610.1 |
| soakhigh_candidate_CASCADE_ACTIVE | 4043 | 4043 | 4035 | 162.2 | 662.6 | 1527.3 |
| soakhigh_candidate_V5_ONLY | 4043 | 4043 | 3864 | 1243.5 | 2845.7 | 3128.6 |

| Soak por ruta y etapa, agrupado | n | P50 | P95 | P99 |
|---|---:|---:|---:|---:|
| soak_candidate_CASCADE_ACTIVE / model2 / gateway | 489 | 1.5 | 3.2 | 3.5 |
| soak_candidate_CASCADE_ACTIVE / model2 / admission | 489 | 0.0 | 0.0 | 0.0 |
| soak_candidate_CASCADE_ACTIVE / model2 / binding | 489 | 0.1 | 0.2 | 0.3 |
| soak_candidate_CASCADE_ACTIVE / model2 / canonical | 489 | 0.4 | 1.0 | 1.3 |
| soak_candidate_CASCADE_ACTIVE / model2 / canonical_with_wait | 489 | 0.5 | 1.1 | 1.4 |
| soak_candidate_CASCADE_ACTIVE / model2 / fast_path | 489 | 0.0 | 0.1 | 0.1 |
| soak_candidate_CASCADE_ACTIVE / model2 / model2 | 978 | 0.5 | 1.1 | 1.2 |
| soak_candidate_CASCADE_ACTIVE / v5 / gateway | 2283 | 124.7 | 325.4 | 464.1 |
| soak_candidate_CASCADE_ACTIVE / v5 / admission | 2283 | 0.0 | 0.0 | 0.0 |
| soak_candidate_CASCADE_ACTIVE / v5 / binding | 2283 | 0.1 | 0.2 | 0.2 |
| soak_candidate_CASCADE_ACTIVE / v5 / canonical | 2283 | 0.5 | 1.0 | 1.5 |
| soak_candidate_CASCADE_ACTIVE / v5 / canonical_with_wait | 2283 | 0.5 | 1.1 | 1.7 |
| soak_candidate_CASCADE_ACTIVE / v5 / fast_path | 2283 | 0.0 | 0.1 | 0.1 |
| soak_candidate_CASCADE_ACTIVE / v5 / model2 | 4566 | 0.5 | 1.1 | 1.3 |
| soak_candidate_CASCADE_ACTIVE / v5 / v5 | 2283 | 122.6 | 324.1 | 463.0 |
| soak_candidate_CASCADE_ACTIVE / v5 / v5_hop | 2283 | 122.6 | 324.1 | 463.0 |
| soak_candidate_CASCADE_ACTIVE / v5 / v5_hop_outside_service | 2283 | 1.8 | 2.6 | 3.2 |
| soak_candidate_CASCADE_ACTIVE / v5 / v5_inference | 2283 | 76.6 | 172.3 | 208.5 |
| soak_candidate_CASCADE_ACTIVE / v5 / v5_queue | 2283 | 0.0 | 208.2 | 379.1 |
| soak_candidate_CASCADE_ACTIVE / v5 / v5_service | 2283 | 120.6 | 321.4 | 461.4 |
| soak_candidate_CASCADE_ACTIVE / v5 / decoder fallback | 5 | 298.4 | 385.1 | 385.1 |
| soak_candidate_CASCADE_ACTIVE / v5 / decoder verified | 2278 | 76.5 | 171.7 | 204.2 |
| soak_candidate_V5_ONLY / v5 / gateway | 2772 | 137.4 | 426.3 | 613.6 |
| soak_candidate_V5_ONLY / v5 / admission | 2772 | 0.0 | 0.0 | 0.0 |
| soak_candidate_V5_ONLY / v5 / binding | 2772 | 0.1 | 0.2 | 0.2 |
| soak_candidate_V5_ONLY / v5 / canonical | 2772 | 0.4 | 0.9 | 1.2 |
| soak_candidate_V5_ONLY / v5 / canonical_with_wait | 2772 | 0.5 | 1.0 | 1.3 |
| soak_candidate_V5_ONLY / v5 / v5 | 2772 | 136.2 | 425.4 | 611.0 |
| soak_candidate_V5_ONLY / v5 / v5_hop | 2772 | 136.2 | 425.4 | 611.0 |
| soak_candidate_V5_ONLY / v5 / v5_hop_outside_service | 2772 | 1.6 | 2.6 | 3.1 |
| soak_candidate_V5_ONLY / v5 / v5_inference | 2766 | 77.2 | 171.3 | 184.3 |
| soak_candidate_V5_ONLY / v5 / v5_no_generation | 6 | 0.8 | 1.8 | 1.8 |
| soak_candidate_V5_ONLY / v5 / v5_queue | 2772 | 21.1 | 319.1 | 503.9 |
| soak_candidate_V5_ONLY / v5 / v5_service | 2772 | 134.1 | 424.2 | 609.5 |
| soak_candidate_V5_ONLY / v5 / decoder fallback | 5 | 311.8 | 341.5 | 341.5 |
| soak_candidate_V5_ONLY / v5 / decoder no_generation | 6 | 0.8 | 1.8 | 1.8 |
| soak_candidate_V5_ONLY / v5 / decoder verified | 2761 | 77.2 | 171.1 | 181.4 |
| soakhigh_candidate_CASCADE_ACTIVE / model2 / gateway | 712 | 1.4 | 3.2 | 884.3 |
| soakhigh_candidate_CASCADE_ACTIVE / model2 / admission | 712 | 0.0 | 0.0 | 883.0 |
| soakhigh_candidate_CASCADE_ACTIVE / model2 / binding | 712 | 0.1 | 0.1 | 0.2 |
| soakhigh_candidate_CASCADE_ACTIVE / model2 / canonical | 712 | 0.4 | 0.9 | 1.1 |
| soakhigh_candidate_CASCADE_ACTIVE / model2 / canonical_with_wait | 712 | 0.4 | 1.0 | 1.2 |
| soakhigh_candidate_CASCADE_ACTIVE / model2 / fast_path | 712 | 0.0 | 0.1 | 0.1 |
| soakhigh_candidate_CASCADE_ACTIVE / model2 / model2 | 1424 | 0.4 | 1.0 | 1.3 |
| soakhigh_candidate_CASCADE_ACTIVE / v5 / gateway | 3371 | 192.0 | 683.6 | 1559.4 |
| soakhigh_candidate_CASCADE_ACTIVE / v5 / admission | 3371 | 0.0 | 0.0 | 738.4 |
| soakhigh_candidate_CASCADE_ACTIVE / v5 / binding | 3371 | 0.1 | 0.1 | 0.2 |
| soakhigh_candidate_CASCADE_ACTIVE / v5 / canonical | 3371 | 0.4 | 0.9 | 1.2 |
| soakhigh_candidate_CASCADE_ACTIVE / v5 / canonical_with_wait | 3371 | 0.4 | 1.0 | 1.3 |
| soakhigh_candidate_CASCADE_ACTIVE / v5 / fast_path | 3371 | 0.0 | 0.1 | 0.1 |
| soakhigh_candidate_CASCADE_ACTIVE / v5 / model2 | 6742 | 0.4 | 1.0 | 1.4 |
| soakhigh_candidate_CASCADE_ACTIVE / v5 / v5 | 3371 | 190.6 | 678.1 | 950.8 |
| soakhigh_candidate_CASCADE_ACTIVE / v5 / v5_hop | 3371 | 190.6 | 678.1 | 950.8 |
| soakhigh_candidate_CASCADE_ACTIVE / v5 / v5_hop_outside_service | 3371 | 1.6 | 2.3 | 3.0 |
| soakhigh_candidate_CASCADE_ACTIVE / v5 / v5_inference | 3371 | 86.5 | 200.3 | 218.4 |
| soakhigh_candidate_CASCADE_ACTIVE / v5 / v5_queue | 3371 | 79.3 | 577.4 | 818.0 |
| soakhigh_candidate_CASCADE_ACTIVE / v5 / v5_service | 3371 | 189.2 | 676.5 | 949.3 |
| soakhigh_candidate_CASCADE_ACTIVE / v5 / decoder fallback | 8 | 335.9 | 423.9 | 423.9 |
| soakhigh_candidate_CASCADE_ACTIVE / v5 / decoder verified | 3363 | 86.5 | 198.7 | 216.6 |
| soakhigh_candidate_V5_ONLY / admission / gateway | 164 | 0.1 | 2001.1 | 2001.3 |
| soakhigh_candidate_V5_ONLY / admission / admission | 164 | 0.0 | 2000.9 | 2001.2 |
| soakhigh_candidate_V5_ONLY / v5 / gateway | 3919 | 1222.0 | 2841.5 | 3122.6 |
| soakhigh_candidate_V5_ONLY / v5 / admission | 3919 | 298.4 | 1804.4 | 1935.0 |
| soakhigh_candidate_V5_ONLY / v5 / binding | 3919 | 0.1 | 0.1 | 0.2 |
| soakhigh_candidate_V5_ONLY / v5 / canonical | 3919 | 0.5 | 0.8 | 1.0 |
| soakhigh_candidate_V5_ONLY / v5 / canonical_with_wait | 3919 | 0.5 | 0.8 | 1.1 |
| soakhigh_candidate_V5_ONLY / v5 / v5 | 3919 | 842.8 | 1215.8 | 1532.1 |
| soakhigh_candidate_V5_ONLY / v5 / v5_hop | 3919 | 842.8 | 1215.8 | 1532.1 |
| soakhigh_candidate_V5_ONLY / v5 / v5_hop_outside_service | 3919 | 1.6 | 2.4 | 3.0 |
| soakhigh_candidate_V5_ONLY / v5 / v5_inference | 3911 | 90.9 | 212.9 | 260.0 |
| soakhigh_candidate_V5_ONLY / v5 / v5_no_generation | 8 | 0.9 | 1.2 | 1.2 |
| soakhigh_candidate_V5_ONLY / v5 / v5_queue | 3919 | 723.0 | 1078.7 | 1368.0 |
| soakhigh_candidate_V5_ONLY / v5 / v5_service | 3919 | 841.3 | 1214.3 | 1530.4 |
| soakhigh_candidate_V5_ONLY / v5 / decoder fallback | 7 | 353.2 | 424.4 | 424.4 |
| soakhigh_candidate_V5_ONLY / v5 / decoder no_generation | 8 | 0.9 | 1.2 | 1.2 |
| soakhigh_candidate_V5_ONLY / v5 / decoder verified | 3904 | 90.8 | 212.0 | 248.8 |

| Recuperación | Recuperó | Segundos | Sondas |
|---|---|---:|---:|
| recovery_candidate_CASCADE_ACTIVE_rep1 | True | 2.0 | 15 |
| recovery_candidate_CASCADE_ACTIVE_rep2 | True | 9.0 | 30 |
| recovery_candidate_V5_ONLY_rep1 | True | 2.0 | 15 |
| recovery_candidate_V5_ONLY_rep2 | True | 9.0 | 30 |

Fallos de `failures_candidate_rep1`: canonical_after_kill 2.1 s, gateway_after_restart 1.3 s, guard_after_stop 0.2 s, model2_after_hang 0.8 s, model2_after_kill 0.0 s, sink_after_restart 3.0 s, v5_after_hang_resumed 1.8 s, v5_after_restart 5.3 s

Fallos de `failures_candidate_rep2`: canonical_after_kill 2.4 s, gateway_after_restart 2.4 s, guard_after_stop 2.7 s, model2_after_hang 3.5 s, model2_after_kill 1.2 s, sink_after_restart 0.1 s, v5_after_hang_resumed 0.3 s, v5_after_restart 5.0 s
