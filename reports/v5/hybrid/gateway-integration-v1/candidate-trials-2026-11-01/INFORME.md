# V5.1 en la cascada real: recorrido, clasificación y carga

1 de noviembre de 2026. Rama `feat/hybrid-cascade-integration`, HEAD `3069fa7`. **Sin staging, sin commit, sin push, sin PR.** V4 no se cargó.

**Resultado.** Los dos candidatos V5.1 pasan el mecanismo completo con pesos reales. El gateway reproduce caso por caso lo que Codex midió por API. El runtime rápido da casi 3 veces la capacidad útil del nativo en esta máquina y con esta mezcla DEV, a cambio de una omisión authored más. Esto no aprueba ningún perfil, umbral ni despliegue, y no acredita D36. Los 200 ms siguen siendo aspiracionales.

**Lo que necesita atención:**

1. **Bloqueo nuevo de rutas benignas, fuera de los censos.** Los dos runtimes bloquean `GET /healthz` y `GET /static/app.css`.
2. **Defecto del gateway, ya corregido.** Reiniciarlo bajo tráfico lo cerraba durante el arranque. Fallaba cerrado, pero no levantaba solo.
3. **Regresiones reales.** Tres casos BLOCK authored que el V5 anterior bloqueaba pasan con los dos runtimes, y uno más pasa solo con el rápido. Se conservan abajo, sin tocar referencias.

| Prueba | Nativo | Rápido |
|---|---|---|
| `candidate_check` sin conexión | `IDENTITY_CONSISTENT` | `IDENTITY_CONSISTENT` |
| Recorrido, mecanismo, código final | 59 de 59 | 59 de 59 |
| Round-trip canónico en `V5_ONLY` | 2.514 de 2.514 | 2.514 de 2.514 |
| Respuestas V5 iguales al censo API, en estado y decisión | 2.514 de 2.514 | 2.514 de 2.514 |
| Escalera, repetición por repetición | Hecha | Hecha |
| Filas de carga | 18.446 | 47.125 |

## 1. Clasificación, acción, estado y recepción

Son 2.514 peticiones reales por el gateway, en secuencia, hacia el sink inerte. Las cuatro capas se cuentan por separado ([COMPARACION_GATEWAY.json](COMPARACION_GATEWAY.json)). Los tiempos de esta pasada no son resultados de carga.

**Clasificación contra la referencia, 434 authored.** Es regresión conocida, y las referencias son expectativas.

| Ejecución | TP | TN | FP | FN | Decide Model 2 | Decide V5 |
|---|---:|---:|---:|---:|---:|---:|
| Nativo, `V5_ONLY` | 194 | 215 | 6 | 19 | 0 | 434 |
| Nativo, `CASCADE_ACTIVE` baseline34 | **195** | 214 | 7 | **18** | 52 | 382 |
| Rápido, `V5_ONLY` | 193 | 215 | 6 | 20 | 0 | 434 |
| Rápido, `CASCADE_ACTIVE` baseline34 | 194 | 214 | 7 | 19 | 52 | 382 |
| Rápido, `CASCADE_ACTIVE` ablación32, control | 194 | 212 | 9 | 19 | 77 | 357 |

**Clasificación, 2.080 URL de validación.** Son datos de selección de checkpoint, de 15 componentes fuente. Las cinco ejecuciones dan TP 1.040, TN 1.036, FP 4, FN 0. Model 2 decide 42 casos con baseline34 y 64 con ablación.

**Las otras tres capas, en las cinco ejecuciones:**

| Comprobación | Resultado |
|---|---|
| La acción sigue a la decisión | 2.514 de 2.514 |
| El estado HTTP sigue a la acción | 2.514 de 2.514 |
| La recepción independiente sigue a la acción, con bytes iguales a los enviados | 2.514 de 2.514 |

**Recorrido wire de los 2.080 URL.** Ahora sí está hecho y verificado. Esos casos solo existían como texto canónico, así que se construyó un wire para cada uno. Un reenviador entre gateway y V5 calculó el hash de lo que V5 recibió: 2.080 de 2.080 iguales al censo. Los 434 authored usan su wire grabado y también coinciden. En `CASCADE_ACTIVE` la comprobación solo alcanza a lo que llega a V5, porque un bloqueo temprano nunca llega.

**Contrafactuales de Codex, ahora observados.** La reconstrucción a 0,9 sin Fast Path coincide con el gateway en 2.514 de 2.514 casos, en decisión y en etapa, para baseline34 y para ablación. Las puntuaciones de Model 2 son idénticas: diferencia máxima 0,0.

**Efecto real de Model 2 a 0,9.** Es un punto de laboratorio, no un umbral elegido.

| Política | Bloqueos tempranos | Casos que cambian frente a V5 solo |
|---|---:|---|
| baseline34 | 94 de 2.514 | `paired-PST-0006` gana un TP; `paired-BPR-0007` añade un FP |
| ablación32 | 141 de 2.514 | `paired-PST-0006` gana un TP; `paired-BPR-0007`, `paired-BEN-0139` y `paired-BPR-0005` añaden FP |

Los mismos dos cambios de baseline34 aparecen en nativo y en rápido. En URL no cambia ningún caso. Sobre estas muestras, Model 2 aporta sobre todo descarga de V5, no más detección.

**Efecto de un ataque: `NOT_MEASURED`.** El sink solo prueba entrega.

## 2. Falsos bloqueos y regresiones

Nada de esto se cambió ni se añadió a entrenamiento. Todo pasó por el gateway con la ruta indicada ([`known_cases`](COMPARACION_GATEWAY.json)).

| Grupo | Casos | Por el gateway |
|---|---|---|
| Falsos bloqueos authored | `paired-BEN-0096`, `0098`, `0110`, `0116`, `0152`, `paired-BPR-0012` | V5 los bloquea en ambos runtimes: 403, nada recibido. Model 2 no los decide |
| Falsos bloqueos URL | `policy-val-00488`, `00860`, `01660`, `01906` | Igual. Solo `01906` ya lo bloqueaba el V5 anterior |
| Omisiones nuevas en ambos runtimes | `paired-ATK-0125`, `0176`, `0189` | ALLOW, 200, recibidos. El anterior los bloqueaba |
| Omisión nueva solo en rápido | `paired-ATK-0067` | Rápido: ALLOW, 200, recibido. Nativo: BLOCK, 403. Model 2 no lo salva en ninguna política |
| Motivo distinto, misma decisión | 8 `policy-val` | BLOCK en ambos runtimes |

`paired-BEN-0098` y `paired-BPR-0012` tienen el mismo texto canónico, así que cuentan como un solo error del modelo con dos filas.

## 3. Bloqueo de rutas benignas, fuera de los censos

La auditoría del Fast Path lo destapó. El fixture de carga mezcla `GET /healthz` y `GET /status?page=N`:

| Regla | Veredicto con V5.1, 2.543 auditorías | V5 anterior, `load-run-1` |
|---|---|---|
| `healthz` | **DISAGREE 1.259 de 1.259** | AGREE en todas |
| `status-with-uint` | AGREE 1.284 de 1.284 | AGREE en todas |

El Fast Path dejó pasar esas peticiones y el desacuerdo quedó registrado sin efecto retroactivo: el mecanismo hizo lo que debía. El problema es del modelo. Luego se preguntó a la API por 24 rutas benignas ([route-probe](route-probe/)), con el mismo resultado en ambos runtimes:

| Ruta | Decisión | Motivo que da V5 |
|---|---|---|
| `GET /healthz` | **BLOCK** | Server-side request forgery |
| `GET /static/app.css` | **BLOCK** | Open redirect |
| Las otras 22, incluidas `/health`, `/readyz`, `/metrics` y `/products` | ALLOW | |

Es un diagnóstico posterior, escrito después de ver el fallo: **no estima ninguna tasa**. Importa porque son peticiones triviales y porque `/healthz` y `/static/` existen en `lab-app`. `paired-BPR-0012`, ya conocido, es de la misma familia que `/static/app.css`. No se tocó `lab-app`. Estos casos no deben pasar a entrenamiento y presentarse luego como evaluación independiente.

## 4. Carga

Llegadas Poisson en lazo abierto, 1.012 casos DEV que incluyen `legacy_dev`, solo como forma de tráfico. Las tasas salen de la escalera de cada candidato ([rates_from_ladder](load-verified/rates_from_ladder.json)). Los percentiles se calculan sobre filas agrupadas. Tablas completas: [nativo](load-native/TABLAS.md), [rápido](load-verified/TABLAS.md). Resúmenes: [nativo](load-native/RESUMEN_CARGA.json), [rápido](load-verified/RESUMEN_CARGA.json).

**Capacidad en esta máquina, no de ningún despliegue:**

| Configuración | Sostenible por repetición | Primera tasa saturada | Útil máxima, media |
|---|---:|---:|---:|
| Nativo, `V5_ONLY` | 3, 3, 3 r/s | 4, 4, 4 | 3,64 r/s |
| Nativo, `CASCADE_ACTIVE` | 4, 3, 4 r/s | 6, 4, 6 | 4,52 r/s |
| Rápido, `V5_ONLY` | 8, 8, 8 r/s | 12, 12, 12 | 10,10 r/s |
| Rápido, `CASCADE_ACTIVE` | 16, 12, 12 r/s | 24, 16, 16 | 13,29 r/s |

Son tasas de este candidato, medidas de nuevo: ninguna viene del modelo anterior.

**Soak, 240 s por repetición, 2 repeticiones agrupadas. Latencia de extremo a extremo en ms:**

| Configuración | r/s | Ofrecidas | Completas | Útiles | P50 | P95 | P99 |
|---|---:|---:|---:|---:|---:|---:|---:|
| Nativo, `V5_ONLY` | 2,1 | 1.041 | 1.041 | 1.037 | 320 | 987 | 1.453 |
| Nativo, `CASCADE_ACTIVE` | 2,1 | 1.041 | 1.041 | 1.039 | 303 | 677 | 964 |
| Rápido, `V5_ONLY` | 5,6 | 2.732 | 2.732 | 2.721 | 143 | 430 | 610 |
| Rápido, `CASCADE_ACTIVE` | 5,6 | 2.732 | 2.732 | 2.727 | 97 | 306 | 459 |
| Rápido, `V5_ONLY` | 8,4 | 4.043 | 4.043 | 3.864 | 1.244 | 2.846 | 3.129 |
| Rápido, `CASCADE_ACTIVE` | 8,4 | 4.043 | 4.043 | 4.035 | 162 | 663 | 1.527 |

La fila de `V5_ONLY` a 8,4 r/s está por encima de su tasa sostenible, a propósito. La de cascada a 8,4 solo existe en el rápido, porque en el nativo coincidiría con la de soak.

**Por etapa, soak de `CASCADE_ACTIVE`. Ruta V5 en ms:**

| Etapa | Nativo 2,1 r/s, P50 / P95 / P99 | Rápido 5,6 r/s, P50 / P95 / P99 |
|---|---:|---:|
| Canónico | 0,6 / 1,0 / 1,4 | 0,5 / 1,0 / 1,5 |
| Model 2 | 0,7 / 1,1 / 1,2 | 0,5 / 1,1 / 1,3 |
| Cola de V5 | 0,0 / 428 / 725 | 0,0 / 208 / 379 |
| Inferencia V5 | 285 / 298 / 310 | 77 / 172 / 209 |
| Gateway completo | 299 / 699 / 1.017 | 125 / 325 / 464 |
| Bloqueo temprano de Model 2, gateway completo | 1,5 / 3,2 / 3,5 | 1,5 / 3,2 / 3,5 |

**Lectura.**

- **Inferencia.** A 5,6 r/s, el P95 de inferencia del rápido fue 172 ms, pero de extremo a extremo fue 306 ms: la cola pesa tanto como el modelo. Sube a 200 ms a 8,4 r/s. No se acredita D36.
- **Por qué la cascada aguanta más.** Model 2 retira cerca del 18 % de las peticiones antes de V5. El coste medio de inferencia casi no cambia: 96 frente a 100 ms en el rápido. Durante la corrida dije que se llevaba sobre todo las caras: los datos no lo sostienen.
- **Decodificador.** Hubo entre 5 y 8 vueltas a generación nativa por celda de soak agrupada, con P50 de 300 a 350 ms.
- **Admisión.** Va antes que Model 2, así que a 8,4 r/s un bloqueo temprano que tarda 3 ms puede esperar hasta 883 ms (P99) detrás de peticiones V5. No lo cambié. Es una observación de diseño.
- **Deriva.** La memoria de V5 subió hasta 62 MiB sobre la inicial en cada soak, y 240 s son pocos para hablar de una fuga. El P95 del último tercio fue mayor en unas celdas y menor en otras, así que no se concluye tendencia.

**Recuperación tras sobrecarga, con la tasa propia de cada runtime:**

| Configuración | Tasa | Repetición 1 | Repetición 2 |
|---|---:|---:|---:|
| Nativo, `CASCADE_ACTIVE` | 6 r/s | 4 s | 4 s |
| Nativo, `V5_ONLY` | 6 r/s | 5 s | 5 s |
| Rápido, `CASCADE_ACTIVE` | 18 r/s | 2 s | **9 s** |
| Rápido, `V5_ONLY` | 18 r/s | 2 s | **9 s** |

Los 9 s no son un drenaje lento. Las latencias ya eran normales antes del cuarto segundo. En el segundo 8 tocó un caso que V5 no sabe responder (`no_eos`), dio 503 y reinició la cuenta de 10 sondas limpias. La definición es correcta, pero aquí exagera.

**Fallos inyectados con carga, 2 r/s, 2 repeticiones por runtime:** V5 matado y colgado, Model 2 matado y colgado, workers canónicos matados, guard detenido, sink matado y gateway matado. Todos se recuperaron en 5,3 s o menos. El más lento fue siempre el reinicio de V5, entre 5,0 y 5,3 s. En las líneas de fallos aparecieron 502, errores de conexión y conexiones cerradas sin respuesta, con los componentes caídos.

**Totales, 60 corridas y 211 pasos:**

| Cuenta | Nativo | Rápido |
|---|---:|---:|
| Ofrecidas | 18.446 | 47.125 |
| Completas | 18.424 | 47.108 |
| Útiles, 200 o 403 | 16.359 | 39.748 |
| Rechazos 503 | 2.035 | 7.331 |
| 502, solo en líneas de fallos | 30 | 29 |
| Errores de conexión, solo en líneas de fallos | 18 | 15 |
| Cerradas sin respuesta, solo en líneas de fallos | 4 | 2 |
| Timeouts del cliente | 0 | 0 |
| Cuerpos cortados | 0 | 0 |
| Pasos con recepción no conforme | 0 | 0 |

Picos: 8 en vuelo y 16 en espera, los límites configurados. La cola de auditoría llegó a su límite de 64 solo en el nativo sin presupuesto. Memoria de GPU usada en total, incluido el escritorio: 3,1 GiB nativo y 3,4 GiB rápido. 69 °C como máximo, proceso V5 1,6 GiB, gateway 81 MiB.

**V5 sin decisión.** Los censos daban cero inválidos, y siguen correctos: estos casos son de `legacy_dev`, fuera de esos censos, con familias fuera del vocabulario. El gateway los denegó con 503 todas las veces.

| Caso | Motivo | Nativo | Rápido |
|---|---|---:|---:|
| `dev-00369` | `no_eos` | 13 veces | 34 veces |
| `dev-00236` | `not_in_vocabulary` | 0 | 31 veces |
| `dev-00372` | `content_rejected` | 3 | 15 |
| `dev-00518` | `content_rejected` | 3 | 14 |

`dev-00236` solo falla en el rápido. No diagnostiqué por qué.

## 5. Auditoría Fast Path real

1,5 r/s de DEV más 5 r/s de permisos del fixture, 90 s, 2 repeticiones agrupadas. Los P99 son de baja confianza, con n = 262.

| Runtime | Muestreo | Presupuesto | DEV P50 / P95 / P99 ms | Solicitadas | Completadas | Descartadas | Fallidas |
|---|---:|---|---:|---:|---:|---:|---:|
| Nativo | 0 | Sin auditoría | 301 / 601 / 999 | 0 | 0 | 0 | 0 |
| Nativo | 0,1 | Sin presupuesto | 306 / 853 / 1.015 | 94 | 94 | 0 | 0 |
| Nativo | 0,1 | Con presupuesto | 306 / 715 / 1.140 | 89 | 86 | 3 | 0 |
| Nativo | 1 | Sin presupuesto | **505 / 1.223 / 1.488** | 911 | 550 | 361 | 0 |
| Nativo | 1 | Con presupuesto | **394 / 768 / 1.010** | 911 | 354 | 557 | 0 |
| Rápido | 0 | Sin auditoría | 86 / 181 / 244 | 0 | 0 | 0 | 0 |
| Rápido | 0,1 | Sin presupuesto | 86 / 184 / 248 | 88 | 88 | 0 | 0 |
| Rápido | 0,1 | Con presupuesto | 86 / 190 / 331 | 96 | 96 | 0 | 0 |
| Rápido | 1 | Sin presupuesto | **122 / 296 / 343** | 911 | 911 | 0 | 0 |
| Rápido | 1 | Con presupuesto | **89 / 250 / 319** | 911 | 364 | 547 | 0 |

`solicitadas = completadas + descartadas + fallidas` se cumple en las 24 celdas. El permiso del Fast Path no cambia: P95 cerca de 14 ms, o 7 ms donde la cola de auditoría ya estaba saturada.

El presupuesto reduce el coste real sobre el tráfico a cambio de auditar menos. A muestreo 0,1 no se ve una ventaja clara: las diferencias caen dentro del ruido entre repeticiones. Los valores 2/s, ráfaga 4, ceder 1 y edad 2 s siguen siendo de partida, no dimensionados. Sin contrato de aplicación, el Fast Path sigue siendo un fixture.

## 6. Defectos encontrados en estas pruebas

| Defecto | Efecto | Corrección | Comprobación |
|---|---|---|---|
| Un 503 de «no listo» se registraba como error. mitmdump escucha antes de acabar de arrancar y sale ante cualquier error registrado en esa ventana | Una petición en ese instante cerraba el gateway recién reiniciado. Falla cerrada, sin relanzarse. Cortó la línea de fallos del rápido | `cascade_gateway.py`: esa denegación pasa a aviso. Sigue siendo 503 | Con V5 doble y tráfico continuo: **12 de 12 salidas antes, 12 de 12 listos después** ([restart-under-traffic](restart-under-traffic/)). Prueba unitaria añadida |
| El control de procesos ajenos en GPU trataba ventanas del escritorio como un modelo | Habría parado la carga | `load_check.py`: solo cuenta desde 300 MiB | 3 pruebas |
| Mi comparador comparaba el motivo, que el gateway no guarda | `summary-*.json` del nativo dicen `census_same=0`, y es falso | Compara estado y decisión. Filas sin motivo | **Usar [COMPARACION_GATEWAY.json](COMPARACION_GATEWAY.json)**, recalculado de las filas. Da 2.514 de 2.514 |
| `load_analyze.py` leía sus propios análisis como corridas | Habría fallado en el segundo análisis | Los ignora | 1 prueba |

**Procedencia frente a la corrección del gateway.** Solo cambia un nivel de registro, no ninguna decisión ni acción. Se midieron antes del cambio las escaleras, los soaks, la recuperación, los fallos de la repetición 1 de ambos, la repetición 2 del nativo y la auditoría del nativo. Se midieron después los fallos de la repetición 2 del rápido, su auditoría y los dos recorridos finales. La corrida interrumpida se conserva fuera de Git como `failed-attempt-failures_candidate_rep2`. La comprobación del reinicio usó dobles, porque el fallo ocurre antes de consultar ningún modelo. La línea de fallos real repitió ese reinicio con V5 real y recuperó en 2,4 s.

Otros cambios: `candidate_compare.py`, `candidate_compare_report.py`, `candidate_load_summary.py`, `restart_under_traffic.py` y `v5_route_probe.py`, nuevos; `fault_proxy.py` calcula el hash de lo que recibe V5; [cascade_candidate_handoff.md](../../../../../docs/cascade_candidate_handoff.md) actualizado.

## 7. Pruebas

| Prueba | Resultado |
|---|---|
| Suite afectada, código final | **677 de 677**, 0 omitidas ([at-end](at-end/unit_tests.json)) |
| Recorridos reales, código final | 59 de 59 en ambos |
| Fuentes inmutables | 0 de 70 cambiadas |
| Fuentes de medición cambiadas | Solo las 2 de V5 de Codex, sin tocarlas yo |
| Staging | Nada |

## 8. Lo que no se ha medido

- **Rutas, no explotación.** Ningún resultado dice si un ataque habría funcionado.
- **Datos no independientes.** Los authored son regresión conocida y los URL seleccionaron el checkpoint. No se abrió ningún conjunto protegido ni reserva.
- **Aplicación real.** No se usó `lab-app`. Falta acordar aislamiento y oráculos.
- **Abiertos sin cambios:** Fast Path productivo, D70, P9/R3, TLS/HTTP2 y contexto JWT/CSRF.
- **Causa de los bloqueos de la sección 3.** Solo se describe el alcance observado.
- **Doble cuantización.** El nativo de estas pruebas usa la de la receta. El benchmark de Codex usó nativo sin ella, así que sus tiempos no se comparan directamente.

## 9. Elección de runtime

Sigue abierta, y los dos manifiestos se conservan como candidatos experimentales.

| | Nativo | Rápido |
|---|---|---|
| Capacidad de cascada en esta máquina | 3 a 4 r/s | 12 a 16 r/s |
| P95 de extremo a extremo en soak | 677 ms a 2,1 r/s | 306 ms a 5,6 r/s |
| Omisiones authored en cascada | 18 | 19, por `paired-ATK-0067` |
| Falsos bloqueos | Los mismos | Los mismos |
| Bloqueos de `/healthz` y `/static/app.css` | Sí | Sí |

Los bloqueos benignos de la sección 3 pesan más que la elección de runtime: afectan a los dos y deberían revisarse antes de cualquier prueba con aplicación real.
