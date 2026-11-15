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

| Recuperación | Recuperó | Segundos | Sondas |
|---|---|---:|---:|
