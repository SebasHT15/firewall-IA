# Tablas de la corrida

Generado por `load_analyze.py`. Percentiles agrupados sobre las filas, nunca promediados. Tasas por repetición como media [mín-máx]. Criterios de saturación descriptivos: no son un SLO. Nada aquí aprueba un candidato.

| Configuración y modo | r/s | Ofrecidas | Completas | Útil r/s | 503 | 502 | Timeouts | Errores | Cortadas | P50 | P95 | P99 | Saturadas |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| candidate/CASCADE_ACTIVE | 2 | 10 | 10 | 2.50 [2.50-2.50] | 0 | 0 | 0 | 0 | 0 | 52.6 | 56.6 | 56.6 | 0/1 |
| candidate/CASCADE_ACTIVE | 4 | 14 | 14 | 3.50 [3.50-3.50] | 0 | 0 | 0 | 0 | 0 | 49.3 | 53.7 | 53.7 | 0/1 |
| candidate/V5_ONLY | 2 | 10 | 10 | 2.50 [2.50-2.50] | 0 | 0 | 0 | 0 | 0 | 51.4 | 53.6 | 53.6 | 0/1 |
| candidate/V5_ONLY | 4 | 14 | 14 | 3.50 [3.50-3.50] | 0 | 0 | 0 | 0 | 0 | 51.9 | 85.3 | 85.3 | 0/1 |

| Soak agrupado | Ofrecidas | Completas | Útiles | P50 | P95 | P99 |
|---|---:|---:|---:|---:|---:|---:|
| soak_candidate_CASCADE_ACTIVE | 49 | 49 | 49 | 53.3 | 77.2 | 97.4 |
| soak_candidate_V5_ONLY | 49 | 49 | 49 | 52.9 | 76.8 | 91.4 |
| soakhigh_candidate_CASCADE_ACTIVE | 63 | 63 | 63 | 53.6 | 69.9 | 113.8 |
| soakhigh_candidate_V5_ONLY | 63 | 63 | 63 | 53.2 | 74.4 | 109.6 |

| Soak por ruta y etapa, agrupado | n | P50 | P95 | P99 |
|---|---:|---:|---:|---:|
| soak_candidate_CASCADE_ACTIVE / model2 / gateway | 10 | 2.5 | 2.9 | 2.9 |
| soak_candidate_CASCADE_ACTIVE / model2 / admission | 10 | 0.0 | 0.0 | 0.0 |
| soak_candidate_CASCADE_ACTIVE / model2 / binding | 10 | 0.1 | 0.1 | 0.1 |
| soak_candidate_CASCADE_ACTIVE / model2 / canonical | 10 | 0.7 | 1.0 | 1.0 |
| soak_candidate_CASCADE_ACTIVE / model2 / canonical_with_wait | 10 | 0.8 | 1.1 | 1.1 |
| soak_candidate_CASCADE_ACTIVE / model2 / fast_path | 10 | 0.0 | 0.1 | 0.1 |
| soak_candidate_CASCADE_ACTIVE / model2 / model2 | 20 | 0.8 | 1.0 | 1.0 |
| soak_candidate_CASCADE_ACTIVE / v5 / gateway | 45 | 44.4 | 69.5 | 86.6 |
| soak_candidate_CASCADE_ACTIVE / v5 / admission | 45 | 0.0 | 0.0 | 0.0 |
| soak_candidate_CASCADE_ACTIVE / v5 / binding | 45 | 0.1 | 0.2 | 0.2 |
| soak_candidate_CASCADE_ACTIVE / v5 / canonical | 45 | 0.7 | 1.1 | 1.2 |
| soak_candidate_CASCADE_ACTIVE / v5 / canonical_with_wait | 45 | 0.8 | 1.2 | 1.4 |
| soak_candidate_CASCADE_ACTIVE / v5 / fast_path | 45 | 0.0 | 0.1 | 0.1 |
| soak_candidate_CASCADE_ACTIVE / v5 / model2 | 90 | 0.8 | 1.1 | 1.3 |
| soak_candidate_CASCADE_ACTIVE / v5 / v5 | 45 | 41.9 | 67.4 | 84.1 |
| soak_candidate_CASCADE_ACTIVE / v5 / v5_hop | 45 | 41.9 | 67.4 | 84.1 |
| soak_candidate_CASCADE_ACTIVE / v5 / v5_hop_outside_service | 45 | 1.7 | 2.4 | 2.7 |
| soak_candidate_CASCADE_ACTIVE / v5 / v5_inference | 45 | 40.2 | 40.2 | 40.4 |
| soak_candidate_CASCADE_ACTIVE / v5 / v5_queue | 45 | 0.0 | 25.7 | 41.8 |
| soak_candidate_CASCADE_ACTIVE / v5 / v5_service | 45 | 40.2 | 65.9 | 82.0 |
| soak_candidate_CASCADE_ACTIVE / v5 / decoder native | 45 | 40.2 | 40.2 | 40.4 |
| soak_candidate_V5_ONLY / v5 / gateway | 55 | 43.5 | 68.9 | 83.3 |
| soak_candidate_V5_ONLY / v5 / admission | 55 | 0.0 | 0.0 | 0.0 |
| soak_candidate_V5_ONLY / v5 / binding | 55 | 0.1 | 0.2 | 0.5 |
| soak_candidate_V5_ONLY / v5 / canonical | 55 | 0.7 | 1.3 | 2.5 |
| soak_candidate_V5_ONLY / v5 / canonical_with_wait | 55 | 0.7 | 1.4 | 2.6 |
| soak_candidate_V5_ONLY / v5 / v5 | 55 | 42.0 | 67.9 | 81.5 |
| soak_candidate_V5_ONLY / v5 / v5_hop | 55 | 42.0 | 67.9 | 81.5 |
| soak_candidate_V5_ONLY / v5 / v5_hop_outside_service | 55 | 1.7 | 2.4 | 5.8 |
| soak_candidate_V5_ONLY / v5 / v5_inference | 55 | 40.2 | 40.2 | 40.3 |
| soak_candidate_V5_ONLY / v5 / v5_queue | 55 | 0.0 | 25.7 | 39.8 |
| soak_candidate_V5_ONLY / v5 / v5_service | 55 | 40.2 | 65.9 | 80.0 |
| soak_candidate_V5_ONLY / v5 / decoder native | 55 | 40.2 | 40.2 | 40.3 |
| soakhigh_candidate_CASCADE_ACTIVE / model2 / gateway | 11 | 2.4 | 4.7 | 4.7 |
| soakhigh_candidate_CASCADE_ACTIVE / model2 / admission | 11 | 0.0 | 0.0 | 0.0 |
| soakhigh_candidate_CASCADE_ACTIVE / model2 / binding | 11 | 0.1 | 0.2 | 0.2 |
| soakhigh_candidate_CASCADE_ACTIVE / model2 / canonical | 11 | 0.7 | 2.4 | 2.4 |
| soakhigh_candidate_CASCADE_ACTIVE / model2 / canonical_with_wait | 11 | 0.7 | 2.5 | 2.5 |
| soakhigh_candidate_CASCADE_ACTIVE / model2 / fast_path | 11 | 0.0 | 0.1 | 0.1 |
| soakhigh_candidate_CASCADE_ACTIVE / model2 / model2 | 22 | 0.8 | 1.2 | 1.2 |
| soakhigh_candidate_CASCADE_ACTIVE / v5 / gateway | 58 | 44.4 | 72.3 | 106.3 |
| soakhigh_candidate_CASCADE_ACTIVE / v5 / admission | 58 | 0.0 | 0.0 | 0.0 |
| soakhigh_candidate_CASCADE_ACTIVE / v5 / binding | 58 | 0.1 | 0.1 | 0.2 |
| soakhigh_candidate_CASCADE_ACTIVE / v5 / canonical | 58 | 0.6 | 1.0 | 1.5 |
| soakhigh_candidate_CASCADE_ACTIVE / v5 / canonical_with_wait | 58 | 0.7 | 1.2 | 1.7 |
| soakhigh_candidate_CASCADE_ACTIVE / v5 / fast_path | 58 | 0.0 | 0.1 | 0.1 |
| soakhigh_candidate_CASCADE_ACTIVE / v5 / model2 | 116 | 0.8 | 1.1 | 1.2 |
| soakhigh_candidate_CASCADE_ACTIVE / v5 / v5 | 58 | 41.9 | 69.5 | 103.6 |
| soakhigh_candidate_CASCADE_ACTIVE / v5 / v5_hop | 58 | 41.9 | 69.5 | 103.6 |
| soakhigh_candidate_CASCADE_ACTIVE / v5 / v5_hop_outside_service | 58 | 1.7 | 2.5 | 2.7 |
| soakhigh_candidate_CASCADE_ACTIVE / v5 / v5_inference | 58 | 40.2 | 40.2 | 40.4 |
| soakhigh_candidate_CASCADE_ACTIVE / v5 / v5_queue | 58 | 0.0 | 26.9 | 61.9 |
| soakhigh_candidate_CASCADE_ACTIVE / v5 / v5_service | 58 | 40.2 | 67.2 | 102.1 |
| soakhigh_candidate_CASCADE_ACTIVE / v5 / decoder native | 58 | 40.2 | 40.2 | 40.4 |
| soakhigh_candidate_V5_ONLY / v5 / gateway | 69 | 43.5 | 63.9 | 102.5 |
| soakhigh_candidate_V5_ONLY / v5 / admission | 69 | 0.0 | 0.0 | 0.3 |
| soakhigh_candidate_V5_ONLY / v5 / binding | 69 | 0.1 | 0.2 | 0.3 |
| soakhigh_candidate_V5_ONLY / v5 / canonical | 69 | 0.6 | 1.0 | 2.5 |
| soakhigh_candidate_V5_ONLY / v5 / canonical_with_wait | 69 | 0.7 | 1.1 | 2.6 |
| soakhigh_candidate_V5_ONLY / v5 / v5 | 69 | 41.9 | 62.4 | 101.6 |
| soakhigh_candidate_V5_ONLY / v5 / v5_hop | 69 | 41.9 | 62.4 | 101.6 |
| soakhigh_candidate_V5_ONLY / v5 / v5_hop_outside_service | 69 | 1.6 | 2.2 | 3.6 |
| soakhigh_candidate_V5_ONLY / v5 / v5_inference | 69 | 40.2 | 40.3 | 40.5 |
| soakhigh_candidate_V5_ONLY / v5 / v5_queue | 69 | 0.0 | 20.2 | 60.3 |
| soakhigh_candidate_V5_ONLY / v5 / v5_service | 69 | 40.2 | 60.5 | 100.4 |
| soakhigh_candidate_V5_ONLY / v5 / decoder native | 69 | 40.2 | 40.3 | 40.5 |

| Recuperación | Recuperó | Segundos | Sondas |
|---|---|---:|---:|
| recovery_candidate_CASCADE_ACTIVE_rep1 | True | 0.0 | 15 |
| recovery_candidate_V5_ONLY_rep1 | True | 0.0 | 15 |

Fallos de `failures_candidate_rep1`: canonical_after_kill 10.8 s, gateway_after_restart 1.4 s, guard_after_stop 1.8 s, model2_after_hang 13.8 s, model2_after_kill 0.7 s, sink_after_restart 0.3 s, v5_after_hang_resumed 4.8 s, v5_after_restart 1.0 s
