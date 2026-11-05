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

| Recuperación | Recuperó | Segundos | Sondas |
|---|---|---:|---:|
