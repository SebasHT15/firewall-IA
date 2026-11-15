# Firewall-IA: carga sostenida y recuperación con servicios reales

Ejecutado el 31 de octubre de 2026 con V4, V5 y Model 2 reales sobre mitmproxy real. Rama `feat/hybrid-cascade-integration`, HEAD `499c8b2`. **Sin staging, sin commit, sin push, sin PR.**

**Resultado.** La cascada aguanta carga y fallos mejor que V4, y el eslabón débil es V4.

- **Capacidad.** `CASCADE_ACTIVE` con `verified-suffix` sostuvo 16 r/s y mantuvo unas 19 r/s útiles en sobrecarga. Con la referencia sostuvo 4 r/s. V4 sostuvo 4 r/s.
- **Defecto principal, sin corregir.** V4 no tiene control de admisión. Por encima de su capacidad el trabajo útil cae a casi cero y sigue así 113-157 s después de retirar la carga. Afecta a `V4_ONLY`, a `CASCADE_OBSERVE` y a **cualquier retorno a V4**: con 8 r/s, el retorno dejó de 0,6 a 1,0 r/s útiles.
- **V5 y la cascada** rechazan con rapidez, conservan su trabajo útil y se recuperan en 2-5 s.
- **OBSERVE** encarece el P95 de V4 entre un 10 % y un 19 % a tasas sostenibles. El coste es cola, no generación.
- **La auditoría Fast Path no retrasa la respuesta.** Con muestreo total y la referencia sí retrasa al resto del tráfico.
- **L2:** 280 de 280 pasos conformes, incluidos todos los fallos.

**Esto no aprueba nada.** Alcance: reverse proxy HTTP/1.1 en claro, en loopback, contra un sink inerte, con tráfico DEV. Son capacidades de esta máquina y esta mezcla, no una promesa de despliegue. Siguen sin aprobar el despliegue reverse, D70, P9/R3, una política productiva de Fast Path, el umbral 0,9 y los perfiles experimentales. No se seleccionó umbral ni se leyó ningún conjunto protegido.

Qué hace falta del propietario para probar contra una aplicación real: [REQUISITOS_APLICACION_REAL.md](REQUISITOS_APLICACION_REAL.md).

## 1. Método

| Elemento | Valor |
|---|---|
| Tráfico | 1012 casos DEV `wire_ok` (authored 221 ALLOW y 213 BLOCK, legacy 300 y 278), barajados con semilla y cíclicos. Las etiquetas solo documentan la mezcla |
| Llegadas | Lazo abierto, Poisson con semilla. Latencia desde la llegada programada, sin omisión coordinada |
| Trabajo útil | Respuestas 200 o 403. **Un 503 nunca cuenta como capacidad** |
| Servicios | Frescos por corrida y solo los que el modo necesita. V4 no se carga en `V5_ONLY` ni `ACTIVE` salvo en los fallos |
| Calentamiento | 20 peticiones, registradas aparte y fuera de todo paso |
| Configuraciones | `reference`: NF4 con doble cuantización, sin perfil. `verified`: perfil v2 **EXPERIMENTAL** `verified_suffix/v1` |
| Límites de operación | Timeouts V4 y V5 3 s, plazo 5 s, 8 en curso, 16 en espera. Son valores de esta prueba |
| Saturación | Útil < 95 % o P95 útil > 2000 ms. Criterio descriptivo, **no un SLO** |
| Recuperación | 10 sondas seguidas útiles, a 1 r/s, dentro de 2× el P95 de referencia |
| Máquina | Una GPU compartida. Sin proceso de cómputo ajeno: el arnés para si aparece alguno |

| Fase | Contenido | Repeticiones |
|---|---|---:|
| Barrido | 7 corridas, de 1 a 24 r/s, 30 s por nivel, para tras 2 niveles saturados; sobrecarga 45 s; sondas 45 s | 3 |
| Soak | Los 4 modos con cada configuración, 240 s, a 2,1 r/s (referencia) y 2,8 r/s (`verified`) | 2 |
| Soak alto | `verified`, `V5_ONLY` y `ACTIVE`, 240 s a 8,4 r/s | 2 |
| Recuperación profunda | 90 s a 9 r/s y sondas hasta recuperar, máximo 420 s | 2 |
| Retorno bajo carga | `verified`, 8 r/s: `ACTIVE`, 50 s de retorno a V4, vuelta de autoridad | 2 |
| Auditoría | 1,5 r/s DEV + 5 r/s del fixture, 90 s, muestreo 0, 0,1 y 1 | 2 |
| Fallos | Línea temporal con carga de 2 r/s, más otra en OBSERVE a 1 r/s | 2 `verified`, 1 referencia |

Las tasas del soak salen del barrido: 0,7 × el menor nivel sostenible de la familia, V4_ONLY incluido. Mezcla, orden y semillas están en [protocol.json](protocol.json).

**Cambio de protocolo.** La recuperación profunda, el retorno bajo carga y el soak alto se añadieron **después** de leer el barrido: las sondas de 45 s no bastaban para V4, y la tasa común la limitaba V4. El protocolo original no se tocó; el añadido y sus motivos están en [protocol_addendum.json](protocol_addendum.json).

## 2. Saturación

Tres repeticiones. El nivel sostenible es el último antes de 2 niveles saturados. Los niveles son discretos: «16» significa entre 16 y 24.

| Configuración y modo | Sostenible | Primer saturado | P95 útil en el sostenible | Útil en sobrecarga | Recuperación tras sobrecarga |
|---|---:|---:|---:|---:|---:|
| V4 `V4_ONLY` | 4, 4, 4 | 6 | 1210 ms | **0,00 r/s** a 9 r/s | **No en 45 s** |
| Referencia `V5_ONLY` | 3, 3, 3 | 4 | 1245 ms | 3,52-3,71 r/s a 6 r/s | 5 s |
| Referencia `CASCADE_ACTIVE` | 4, 4, 4 | 6 | 1641 ms | 3,93-4,30 r/s a 9 r/s | 3-4 s |
| Referencia `CASCADE_OBSERVE` | 4, 4, 3 | 6, 6, 4 | 1993 ms a 4 r/s | **0,00 r/s** | **No en 45 s** |
| `verified` `V5_ONLY` | 16, 12, 12 | 24, 16, 16 | 539 ms a 12 r/s | 14,50-14,93 r/s a 24-36 r/s | 2 s |
| `verified` `CASCADE_ACTIVE` | 16, 16, 16 | 24 | 541 ms | 19,22-20,03 r/s a 36 r/s | 2 s |
| `verified` `CASCADE_OBSERVE` | 4, 4, 4 | 6 | 1403 ms | **0,00 r/s** | **No en 45 s** |

Con sondas de 1 r/s, «2 s» significa «en cuanto pudimos medirlo». En todo el barrido hubo 0 timeouts de cliente, y el generador nunca se retrasó: P99 de retraso inferior a 5 ms.

Lo que hay detrás:

- **Cola, no modelo.** Con `verified` a 16 r/s el P95 de inferencia sigue en 100-104 ms, y la cola de V5 sube a 369-478 ms.
- **Model 2 da capacidad real.** Resuelve el 17,6 % de esta mezcla sin GPU, y por eso `ACTIVE` supera a `V5_ONLY`. La cifra depende de la mezcla, que aquí tiene mucho más ataque que un tráfico normal.
- **El límite de 4 r/s de V4 es optimista.** Sale de pasos de 30 s. En 4 minutos a 2,8 r/s su P95 llegó a 1312 ms, por rachas de peticiones largas.

## 3. Defecto: V4 colapsa y tarda minutos en volver

**Mecanismo.** El servicio V4 serializa la inferencia con un candado y no limita lo que acepta. El gateway abandona cada petición a los 3 s, pero V4 **la sigue procesando**. Una vez que la cola supera los 3 s, todo se calcula para nadie: cada respuesta llega cuando el gateway ya contestó 503. En una corrida, V4 recibió 1158 peticiones y procesó al menos 1154, y la cola quedó fija en unas 42 desde la saturación, compatible con los 40 hilos por defecto del servidor (no lo verifiqué).

| Corrida | Útil durante 9 r/s | 503 en 90 s | Recuperación | Sondas 503 |
|---|---:|---:|---:|---:|
| `V4_ONLY` | 0,32-0,36 r/s | 785-850 | **113 y 128 s** | 98-111 |
| OBSERVE con referencia | 0,27-0,30 r/s | 790-855 | **138 y 157 s** | 120-136 |
| OBSERVE con `verified` | 0,26-0,29 r/s | 791-856 | **132 y 152 s** | 116-132 |

El colapso es **fail-closed**: nada se entregó de más y L2 fue conforme. Pero es denegación de servicio autoinfligida: una ráfaga de 90 s deja el sistema inservible otros 2 minutos.

**Retorno a V4 bajo carga, a 8 r/s:**

| Fase de 50 s | Peticiones | Útiles | 503 | P95 útil |
|---|---:|---:|---:|---:|
| `ACTIVE` con `verified` | 412 y 410 | 409 y 409 | 3 y 1 | 198 y 163 ms |
| **Retorno a V4** | 374 y 401 | **51 y 28** | **323 y 373** | 2584 y 2841 ms |
| Vuelta de autoridad | 458 y 422 | 457 y 421 | 1 y 1 | 213 y 208 ms |

La cascada volvió de inmediato, porque no espera la cola que V4 aún arrastra.

**Consecuencia para la operación.** Hoy el retorno a V4 solo funciona por debajo de unas 4 r/s en esta máquina, y ya a 2,8 r/s el P95 superó 1 s en una repetición. Es un dato clave para decidir si V4 sigue siendo el plan de retirada de una cascada que soporta 16.

**Por qué no lo corregí.** `control_plane/classifier_api.py` forma parte de V4 congelado y `data_plane.py` está ligado a la evidencia. Cambiar cómo V4 falla bajo carga es una decisión del propietario, no un ajuste de arnés. Opciones: un límite de peticiones en curso hacia V4 en una subclase del gateway, sin tocar esos archivos, o control de admisión en el servicio.

## 4. Latencia por ruta y etapa

Soak, 2 repeticiones agrupadas, en ms. `P50 / P95 / P99`. Sin saturación. Los datos de cada paso, también del barrido, están en cada `<corrida>.json` y en [analysis.json](analysis.json).

| Etapa | Referencia ACTIVE 2,1 r/s | `verified` ACTIVE 2,8 r/s | `verified` ACTIVE 8,4 r/s | `verified` V5_ONLY 8,4 r/s |
|---|---:|---:|---:|---:|
| **Ruta Model 2, gateway** | 1,5 / 3,0 / 3,6 | 2,4 / 3,0 / 3,3 | 1,8 / 3,1 / 3,9 | no aplica |
| **Ruta V5, gateway** | 296 / 680 / 984 | 60 / 128 / 187 | 71 / 190 / 336 | 103 / 274 / 405 |
| Canonicalización | 0,6 / 0,9 / 1,0 | 0,6 / 0,9 / 1,2 | 0,5 / 0,9 / 1,3 | 0,4 / 0,9 / 1,3 |
| Model 2 | 0,7 / 1,0 / 1,1 | 0,7 / 1,0 / 1,1 | 0,6 / 1,0 / 1,7 | no aplica |
| Cola de V5 | 0 / 396 / 704 | 0 / 54 / 102 | 0 / 120 / 251 | 13 / 200 / 330 |
| Inferencia de V5 | 280 / 297 / 304 | 54 / 107 / 115 | 52 / 103 / 111 | 52 / 104 / 110 |
| Salto a V5 fuera del servicio | 1,7 / 2,4 / 2,9 | 1,8 / 2,4 / 2,9 | 1,6 / 2,4 / 3,0 | 1,6 / 2,5 / 3,1 |

El coste propio del gateway sigue siendo pequeño. La inferencia apenas cambia con la carga: la latencia que crece es la de la cola.

**200 ms.** El P95 de inferencia de la referencia es 297 ms: D36 sigue sin cumplirse, y la aclaración del propietario no lo reescribe. El de `verified` es 103-107 ms sobre esta población DEV, por debajo de ese objetivo aspiracional, pero `verified` es experimental y esto no lo aprueba. La latencia de extremo a extremo depende además de la cola.

**Verificado frente a fallback nativo** (soak de `verified`, todos los modos):

| Camino | Peticiones | P50 | P95 |
|---|---:|---:|---:|
| Verificado | 11 240 (99,6 %) | 52-55 ms | 103-108 ms |
| Fallback nativo | 33 (0,3 %) | 234-312 ms | 322-423 ms, muestra pequeña |
| Rechazo de contenido, sin inferencia | 10 (0,1 %) | no aplica | no aplica |

El candidato se mide aparte de la referencia, que se conservó en todas las fases.

**Los pocos 503 a tasa baja no son saturación.** Son salidas inválidas del modelo con fail-closed (`v5_invalid`, o `status=invalid` en V4) y rechazos de contenido, concentrados en 4 casos DEV. En el soak el 100 % de los 503 tiene ese origen, con 0 rechazos de admisión.

## 5. Soak

Cada casilla da las 2 repeticiones. En todas: 0 timeouts, útil igual a lo ofrecido salvo esos 503, L2 conforme.

| Corrida | r/s | Ofrecidas | 503 | P50 ms | P95 ms | P99 ms |
|---|---:|---:|---:|---:|---:|---:|
| `V4_ONLY` | 2,1 | 1041 | 3 | 259, 257 | 575, 578 | 701, 802 |
| Referencia OBSERVE | 2,1 | 1041 | 3 | 263, 264 | 666, 654 | 890, 847 |
| Referencia `V5_ONLY` | 2,1 | 1041 | 5 | 346, 310 | 981, 940 | 1381, 1349 |
| Referencia ACTIVE | 2,1 | 1041 | 3 | 299, 297 | 631, 666 | 974, 959 |
| `V4_ONLY` | 2,8 | 1411 | 4 | 322, 292 | 1312, 831 | 1858, 1077 |
| `verified` OBSERVE | 2,8 | 1411 | 4 | 354, 320 | 1565, 910 | 2232, 1172 |
| `verified` `V5_ONLY` | 2,8 | 1411 | 5 | 71, 73 | 157, 148 | 227, 199 |
| `verified` ACTIVE | 2,8 | 1411 | 3 | 65, 65 | 123, 126 | 164, 158 |
| `verified` `V5_ONLY` | 8,4 | 4043 | 20 | 109, 106 | 289, 267 | 476, 345 |
| `verified` ACTIVE | 8,4 | 4043 | 12 | 66, 65 | 186, 170 | 414, 241 |

**Deriva.** El P95 del primer tercio y el del último cambian, pero el cambio sigue al orden: en la repetición 1 sube y en la 2 baja, igual en todos los modos con ese orden. Lo atribuyo a la mezcla, no a acumulación.

**Recursos**, por proceso:

| Recurso | Valor |
|---|---|
| Gateway | 76-90 MiB, 1,5-5 % de una CPU de media |
| Workers canónicos / Model 2 | 46 MiB / 108 MiB, menos del 0,3 % de una CPU |
| V5 o V4 | Cerca de 1,5 GiB; V5 crece 15-65 MiB entre primera y máxima muestra |
| Memoria GPU | 1,9-2,0 GiB con un modelo, 3,4-3,5 GiB con los dos |
| Uso de GPU medio | 12-32 % con un modelo, 36-45 % con los dos |
| Temperatura máxima | 79 °C, sin caída de reloj por debajo de 1455 MHz |

Cuatro minutos no descartan una fuga lenta.

## 6. Cuánto cuesta OBSERVE a V4

Soak con la misma semilla, orden y calendario, repetición contra repetición. V4 solo frente a V4 con la cascada calculándose al lado, GPU compartida.

| Tasa y configuración | P50 | P95 | P99 |
|---|---:|---:|---:|
| 2,1 r/s, referencia | +1,4 % y +2,4 % | **+15,8 % y +13,1 %** | +27,0 % y +5,6 % |
| 2,8 r/s, `verified` | +9,7 % y +9,8 % | **+19,4 % y +9,5 %** | +20,1 % y +8,9 % |

En el barrido, cerca del límite, el coste crece. El P95 de 1210 ms a 4 r/s sube a 1403 ms con `verified` (+16 %) y a **1993 ms con la referencia (+65 %)**.

| Otro efecto | Medida |
|---|---|
| Generación de V4, P95 | 244-247 ms → 254-257 ms: solo +3-5 %. El coste es sobre todo cola |
| Punto de saturación de V4 | No cambia con `verified` (6 r/s). Con la referencia, una repetición saturó a 4 |
| Recuperación tras sobrecarga | 19-29 s más que `V4_ONLY` |
| Peticiones respondidas por V4 | Ninguna perdida por OBSERVE en el soak |

**Descartes de observación.** La cola de observación descartó muy poco: entre 0 y 1 por corrida de sobrecarga. Pero `computed` **no significa que V5 contestara**: con la referencia en sobrecarga, V5 devolvió 503 a 821 observaciones en el barrido y 822 en la recuperación profunda. Con `verified`, 0. Esa pérdida se ve en `firewall_v5_client_errors_total{detail="http_503"}`, no en el contador de observaciones.

## 7. Auditoría Fast Path

Peticiones del fixture experimental, no tráfico DEV. Fast Path no tiene política productiva. Los `AGREE` no dicen nada de calidad. P50 / P95 / P99 de la respuesta Fast Path, 2 repeticiones:

| Muestreo | `verified` | Referencia |
|---|---:|---:|
| 0 | 10,1 / 13,2 / 14,7 y 10,1 / 13,2 / 15,5 | 9,7 / 12,5 / 15,1 y 9,5 / 12,8 / 14,4 |
| 0,1 | 10,2 / 13,7 / 15,6 y 10,2 / 13,1 / 16,3 | 7,0 / 12,8 / 14,5 y 7,8 / 12,9 / 15,1 |
| 1 | 10,3 / 14,0 / 16,9 y 9,7 / 13,9 / 15,2 | 5,6 / 7,1 / 7,9 y 5,7 / 7,4 / 11,5 |

**La auditoría no retrasa la respuesta.** No hay aumento apreciable, y con la referencia el valor incluso baja a muestreo 1, en las dos repeticiones; no determiné por qué.

**Sí afecta a otros cuando satura V5:**

| Muestreo total | `verified` | Referencia |
|---|---:|---:|
| Auditorías perdidas por `SATURATED` | 0 | **177 de 456 y 188 de 455, en torno al 40 %** |
| P50 del tráfico DEV frente a muestreo 0 | 65 → 65 ms | **302-306 → 471-531 ms** |
| P95 del tráfico DEV frente a muestreo 0 | 116-122 → 123-131 ms | **549-804 → 1111-1327 ms** |

La auditoría comparte V5 con el tráfico que espera decisión, y no tiene prioridad inferior. Quien quiera auditar debe dimensionar esa carga. `SATURATED` significa que su cola acotada estaba llena: la petición ya había salido y solo se pierde la auditoría, que queda contada. Ninguna terminó en `TIMEOUT` ni `ERROR`.

## 8. Fallos y recuperación

Línea temporal con carga constante, en orden. Tres corridas: `verified` dos veces y referencia una. Recuperación: desde el evento hasta 10 respuestas útiles seguidas dentro de 2× el P95 inicial.

| Fallo | Lo que vio el cliente | Causa registrada | Recuperación |
|---|---|---|---:|
| V5 muerto | Todo 503 | `not_ready`; `v5_error` en las que iban en curso | 5,3-5,6 s tras reiniciarlo |
| Model 2 muerto | **0 503**, deriva a V5 | Sin denegación | 0-1,1 s |
| Model 2 colgado | **0 503**; P95 de `verified` sube a 625-630 ms | Espera el timeout y deriva | 1,9-3,6 s |
| Workers canónicos muertos | 4 503 | `not_ready` | 2,3-2,5 s |
| V5 colgado | Casi todo 503, 1 Model 2 BLOCK | `v5_error` por timeout, luego `not_ready` | 0,2-1,8 s tras reanudarlo |
| Guard detenido | 2-4 503 | `not_ready`; reinicio automático | 2,5-2,7 s |
| Sink muerto | 12-18 502, los BLOCK siguen como 403 | `REJECTED:upstream_unreachable` | 0-3 s tras reiniciarlo |
| Retorno a V4 con V5 caído | **0 503**, V4 responde | Sin denegación | Inmediato, ver nota |
| Vuelta de autoridad | 0 503 | Sin denegación | 0-1,9 s |
| Gateway muerto | 8-13 errores de conexión | Proceso caído | 0,9-1,0 s tras arrancar |

**Coherencia L2.** Conforme en las 3 líneas y en los 2 retornos bajo carga: ningún 200 sin recepción, ninguna denegación recibida y ninguna recepción sin petición. Un fallo nunca dejó pasar nada que debiera bloquearse.

**OBSERVE con V5 y Model 2 muertos.** 117-118 peticiones por línea, todas contestadas por V4, 0 503, L2 conforme. La observación se perdió mientras tanto (26-36 `not_ready`) y volvió sola.

**Todo lo anómalo quedó explicado.** Son peticiones en curso en el instante del fallo, comprobado con sus marcas de tiempo:

- Los dos 502 fuera de la caída del sink terminan 0,13-0,15 s después de detener el guard y el sink.
- Los `v5_error` de la fase `sink_restarted` terminan al matar V5 en la fase siguiente.
- Las dos conexiones cerradas sin respuesta acaban exactamente al matar el gateway. Una de ellas sí llegó al sink: entrega sin respuesta, inevitable cuando el proceso muere justo después de reenviar, y queda contada en `received_after_client_gave_up`.

**Dos límites de la medición:**

- `v4_after_return` marca 0,3-24 s, pero es un artefacto: el límite sale del P95 de la cascada, más rápida que V4. La fase real tuvo 0 503.
- Los contadores del gateway de las líneas ACTIVE se pierden al matarlo. Para esas líneas usé los registros de decisión, que sí sobreviven.

## 9. Defectos

**Corregidos durante este trabajo:**

| Defecto | Cómo apareció | Corrección |
|---|---|---|
| Los workers canónicos nunca se recuperaban: sin ready se deniega antes del pool y nadie los reiniciaba | Ensayo con dobles | `revive()` y `heal()` desde la sonda de readiness |
| El guard caído en caliente no se reiniciaba | Diseño de la línea de fallos | `_restart_guard` en la sonda, con métrica `firewall_guard_restarts_total` |
| Model 2 solo detectaba su muerte con tráfico, y `heal` podía bloquear el bucle de eventos | Diseño de la línea de fallos | Candado no bloqueante en `start` y `heal` |
| El cliente V5 descartaba cola, inferencia, fallback y detalle de error | Preparación de la medición | `V5ServiceClient`, con pruebas de paridad frente a `V5HttpClient` |
| El arnés dejaba procesos huérfanos al cortarlo | Prueba de corte | Manejador de SIGTERM |
| Mi arnés intentó escribir el protocolo sobre el manifiesto de Codex | Ensayo. El modo `x` lo impidió; hash intacto `4042d8c7…` | Variable renombrada |

**Pendientes:**

| # | Pendiente | Importancia |
|---|---|---|
| 1 | **V4 sin control de admisión**, ver sección 3 | Alta. Decide si el retorno a V4 es un plan de retirada real |
| 2 | La auditoría compite con el tráfico en V5, ver sección 7 | Media, solo si se usa Fast Path con muestreo alto |
| 3 | `computed` en OBSERVE no distingue si V5 contestó | Media. La comparación en sombra pierde datos sin que se note en ese contador |
| 4 | Con Model 2 colgado, las peticiones de los primeros segundos esperan su timeout antes de derivar a V5 | Baja |
| 5 | Sin ensayo largo: 4 minutos no descartan fugas lentas | Media antes de cualquier despliegue |
| 6 | Mezcla DEV con mucho ataque: la capacidad con tráfico real será distinta | Alta para cualquier cifra de capacidad |
| 7 | Aplicación real: el sink solo demuestra entrega | Bloquea todo lo demás, ver [requisitos](REQUISITOS_APLICACION_REAL.md) |

**Decisiones que necesita el propietario:** las 8 de los requisitos, y qué hacer con V4: dejarlo como está, limitar su admisión o dejar de considerarlo plan de retirada.

## 10. Código, hashes y reproducción

| Elemento | Valor |
|---|---|
| Pruebas al inicio y al final | **560 de 560**, 0 omitidas: [at-start](at-start/unit_tests.json), [at-end](at-end/unit_tests.json) |
| Fuentes inmutables | 0 de 70 cambiadas |
| Fuentes servidas y artefactos | 17, idénticos al inicio y al final |
| Fuentes de medición cambiadas | 2 de 114: `control_plane/v5_classifier_api.py` y `v5_inference_core.py`, de Codex, igual al inicio y al final |
| Manifiesto de la referencia | `4b703f7e…6f1637d` |
| Manifiesto de `verified` | `4042d8c7…d81311b79` |
| Perfil de `verified` | `e81d70f3…c62ada91f` |
| Entradas DEV | `3118bf66…`, fuera de Git |

Durante la medición no cambió ningún archivo del gateway ni de los servicios. Solo cambiaron `load_check.py` (fases nuevas), `load_analyze.py`, `collect_evidence.py` y `docs/cascade_gateway.md`. `load_analyze.py` y `run_load.sh` aparecen nuevos en el manifiesto final porque no estaban en esa lista. Los hashes y grupos de pruebas están en [at-end/code_manifest.json](at-end/code_manifest.json).

Las filas por petición no llevan payload ni hash, solo el identificador del caso. Los logs con datos DEV y las decisiones quedan fuera de Git, en `/home/sebas/Documents/Codex/2026-10-26/ta/work/gateway-real-2026-10-30/load-run-1/`.

Reserva la GPU en `GPU_STATUS.json` y lanza:

```bash
scripts/gateway_ops/run_load.sh --phase ladder
```

```bash
scripts/gateway_ops/run_load.sh --phase failures --phase recovery --phase audit --phase soak --soak-rates reference=2.1,verified=2.8 --phase soakhigh --soak-high-rate 8.4
```

Recalcula las tablas sin GPU:

```bash
.venv-dataplane/bin/python scripts/gateway_ops/load_analyze.py --run reports/v5/hybrid/gateway-integration-v1/load-run-1 --work /home/sebas/Documents/Codex/2026-10-26/ta/work/gateway-real-2026-10-30/load-run-1
```

| Archivo | Contenido |
|---|---|
| [analysis.json](analysis.json) | Tablas de todas las fases |
| `<corrida>.json` | Pasos, etapas, L2, métricas y recursos de cada corrida |
| `rows/` | Una fila por petición |
| `configs/` | Configuración efectiva del gateway por corrida |
| `functional/` | Verificación funcional de `verified`: 44 de 44, L2 434 de 434 por modo |
| `console_ladder.log`, `console_rest.log` | Salida de las fases |
