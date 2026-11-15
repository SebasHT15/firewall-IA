# Campaña del candidato `fastv5-public-v3-headerguard-v2` — resultados

Fecha de ejecución: 13 de noviembre de 2026. Autor: Claude. Candidato congelado `fastv5-public-v3-headerguard-v2-20261111` (modo `FAST_PATH_V5`, V5.1 y `canonical-request/v1` sin cambios, **sin Model2** en el camino activo). Protocolo prefijado: `coordination/architecture-2026-11-11/TEST_PROTOCOL.md`. Población sellada: `POPULATION_MANIFEST.json` contra `SOURCE_FREEZE.json` (`ae1cf86f…`). Una sola campaña sobre el candidato congelado. Tráfico de laboratorio generado por agente, **no** humano ni orgánico.

Raw privado (filas, sellos, logs): `/home/sebas/Documents/Codex/2026-11-02/fwlab-architecture-private/2026-11-11/test/`. Métricas: `METRICS.json` (primario h1), `METRICS.h2.json` (subset h2). Scorer y runners privados fijados en `RUNNER_MANIFEST.json`; cierres de agregación en `SCORER_CLOSURE_CLAUDE.md`.

## Veredicto

Con la **puerta de integridad** satisfecha (6 apps, corridas COMPLETE/limpias/sin drift, hashes de filas/freeze/casos/runner verificados, `step_id` pareados en todas las poblaciones, contabilidad V5 cerrada), el candidato **cumple los cinco criterios de aceptación prefijados** → `result: PROMOTE` en el test sellado. La promoción final la decide el dueño; aquí se entrega la evidencia.

Esto **no** es una afirmación de ausencia universal de vulnerabilidades ni de superioridad global sobre CRS. Los ceros son muestrales (ver intervalos de Wilson en `METRICS.json`); el alcance es seis apps de laboratorio y un espacio de clientes declarado.

## Transporte principal (h1_tls_new) — 985 peticiones benignas, 65 sesiones de ataque elegibles, 584 sondas de límite

| Brazo | FP benigno (FPR) | Sesiones benignas completas | Ataque TP/FN (recall) | Inyección impedida | Efecto persistió | Σ gateway_ms benigno | V5 ms/sesión p50 |
|---|---|---|---|---|---|---|---|
| directa (control) | 0 (0) | 172/172 | 0/68 (0) — no es detector | 0/65 | 65 | — | — |
| **v5only (referencia)** | **211 (0,214)** | 21/172 | 51/17 (0,75) | 48/65 | 17 | 69 600 | 394,6 |
| fastv5 (ablación, sin guardia) | 3 (0,003) | 169/172 | 51/17 (0,75) | 48/65 | 17 | 14 975 | 59,4 |
| **fastv5_guard (candidato)** | **3 (0,003)** | **169/172** | **66/2 (0,971)** | **63/65** | **2** | **14 870** | **59,3** |
| crs (comparador) | 0 (0) | 172/172 | 53/15 (0,779) | 50/65 | 15 | — | — |

Matriz TP/TN/FP/FN conservadora (salida V5 inválida contaría como FN/FP; en esta campaña **0 inválidas** y **0 denegaciones de infraestructura** en todos los brazos — contabilidad V5 cerrada, sin llamadas en vuelo). La fila directa no es un detector: su «recall 0» es el control positivo (reenvía todo; 65/65 efectos observados), base de elegibilidad.

### C1 — sin Model2
0 procesos Model2 al inicio y al final, 0 invocaciones, `/status.model2_worker = null` (presente y explícito) en las 12 corridas `fastv5`/`fastv5_guard`. **Cumple.**

### C2 — utilidad de Fast Path (objetivo ≥ 20 %)
Atribución **pareada por `step_id`**: entre las peticiones benignas donde `v5only` llamó a V5, el candidato las resolvió por Fast Path **789** veces, por `request_guard` 0, otra causa 0, y 196 siguieron a V5. Ahorro atribuible a Fast Path, neto de auditoría real (audit=0, rate0): **0,801** de las llamadas V5 benignas evitadas. Aciertos de Fast Path en las seis apps: An0nB0ard 153, CatP1cs 147, D33pTh0ught 97, Inf3ct 103, ObC00ki3s 179, ag3ncy 110. **Cumple** (≥0,20 y cobertura en las 6 apps). Lo evitado por la guardia de cabeceras **no** se cuenta aquí (es 0 en benigno).

### C3 — menos tiempo de V5 por tarea
Σ `gateway_ms` benigno: candidato **14 870 ms** vs referencia **69 600 ms**. V5 ms por sesión (p50): **59,3** vs **394,6**. La canonización/Fast Path/guardia añadidas quedan contabilizadas dentro de `gateway_ms`. **Cumple.** (No se exige que baje el P95 global dominado por rutas dinámicas; se publican percentiles por ruta en `METRICS.json`.)

### C4 — seguridad de Fast Path
0 pasos de inyección resueltos por `fast_path`; 0 `FAST_ALLOW` donde el contrato dice `CONTINUE` (584 sondas de límite); 0 respuestas de Fast Path que difieran de la directa en status o SHA-256 (130 respuestas Fast Path en las sondas de límite + las benignas, todas idénticas a directo). **Cumple.**

### C5 — sin daño benigno nuevo
FP benigno del candidato **3** ≤ referencia **211**; 0 pasos benignos nuevos fallidos frente a `v5only`; 0 peticiones benignas denegadas por `request_guard`. **Cumple.** 208 pasos recuperados respecto de la referencia (peticiones que `v5only` bloqueaba y el candidato sirve por Fast Path).

## Hallazgos de mecanismo (atribución correcta)

**Reducción de FP benigno (211 → 3): es Fast Path sirviendo recursos públicos, no un arreglo de V5.** Por app, v5only → candidato: An0nB0ard 33→0, CatP1cs 47→0, D33pTh0ught 21→0, Inf3ct 28→2, ObC00ki3s 62→1, ag3ncy 20→0. V5.1 sigue teniendo esos FP en las rutas que llegan a él; Fast Path solo evita que los recursos públicos exactos pasen por V5. **Los 3 FP que quedan en el candidato llegan a V5 y V5 los bloquea** (no los oculta Fast Path): 1 página de error dinámica de ObC00ki3s («Open redirect») y 2 mensajes benignos de usuario en `POST /` de Inf3ct que V5 marca como SQLi/SSTI. Se informan como límite de V5 conservado, no resuelto.

**SSTI de cabecera (eval/rce/split/stmt, 15 sesiones): la guardia determinista cierra una brecha que fallan TANTO V5-solo COMO CRS.** Inyección impedida por familia (v5only / candidato / crs):

| Familia | v5only | candidato | crs |
|---|---|---|---|
| SQLi (union/boolean/chain/row/stored_exfil/time, 26) | 26/26 | 26/26 | 26/26 |
| path_traversal (16) | 16/16 | 16/16 | 16/16 |
| ssti_ctype_param (2, `Content-Type` sí está en la vista v1) | 2/2 | 2/2 | 2/2 |
| **ssti_header_eval/rce/split/stmt (15)** | **0/15** | **15/15** | **0/15** |
| stored_html_body (4, cuerpo visible) | 4/4 | 4/4 | 4/4 |
| stored_html_header (2) | 0/2 | **0/2** | 2/2 |

La guardia `request-header-sink-guard/v2` detiene los 15 vectores SSTI por cabecera (openings Jinja `{{ {% {#` en cualquier valor de cabecera de un POST, normalizando el método para que `post`/`PoSt` no evadan). V5.1 no los ve (v1 solo expone `Content-Type`) y CRS PL1 tampoco los detiene. **La prevención se atribuye al control determinista, nunca al modelo.** Las 2 sesiones que persisten en el candidato son `stored_html_header` (HTML almacenado vía cabecera): **fuera del alcance declarado de la guardia** (que mira aperturas de plantilla, no HTML/XSS almacenado); CRS sí las detiene con sus reglas XSS genéricas. Se informa como límite conocido, no como fallo oculto.

## Transporte adicional (h2_tls_keepalive) — subset An0nB0ard, Inf3ct, ObC00ki3s

566 peticiones benignas, 49 sesiones de ataque elegibles. Decisiones invariantes al transporte: candidato FP benigno **3** (vs v5only 123), inyección impedida **47/49**, 2 persistidas (mismas `stored_html_header`), **0** ataques por Fast Path, ahorro Fast Path **0,769**. Nombres de cabecera en minúsculas y `te: trailers` de Firefox (que el front descarta) no cambian ninguna decisión. Detalle en `METRICS.h2.json`.

## Carga y fiabilidad (operativo; fuera de C1–C5)

Perfil fijo: 32 workers, `h1_tls_keepalive`, bucle abierto, 20 s/punto, SLO 1000 ms de extremo a extremo (incluye cola del cliente), 3 repeticiones por punto en todos los brazos, escalera 4→8→16→32→64 peticiones/s, techo 64. Punto superado = útiles-bajo-SLO/ofrecidas ≥ 0,95. Capacidad informada = mayor tasa con ≥2/3 repeticiones superadas. Ciclos de solo lectura (ObC00ki3s: `/`+`cks.js`+`asking.js`+imagen; An0nB0ard: `/`+`/messages`+2 css+`/post?id=1`).

**Capacidad (peticiones/s con SLO sostenido):**

| App | directa | v5only | fastv5_guard (candidato) | crs |
|---|---|---|---|---|
| An0nB0ard | ≥64 | **16** | **32** | ≥64 |
| ObC00ki3s | ≥64 | — (ver nota) | ≥64 | ≥64 |

- **An0nB0ard es la comparación limpia de capacidad** (sin FP basal). El candidato **duplica** la capacidad bajo SLO de la ruta V5 (16→32 rps) al servir por Fast Path los subrecursos estáticos (CSS), dejando solo las rutas dinámicas (`/`, `/messages`, `/post`) a V5. Sigue por debajo de directa/CRS (≥64) porque esas rutas dinámicas siguen usando V5. p95 por punto (mediana de repeticiones): directa ~34 ms plano; v5only 73–89 ms hasta 16 rps y **colapsa a 32 rps** (p95 1140 ms, fracción útil 0,08); candidato 82–94 ms hasta 32 rps y se degrada a 64 rps (p95 ~709–743 ms, fracción útil por repetición **0,846 / 0,814 / 0,841**, no un único 0,81); CRS ~42 ms plano. El colapso es **limitado por la cola del cliente y los deadlines del generador con este SLO**, no la capacidad intrínseca de V5: se informa como tal, publicando las tres repeticiones sin promediar P95.
- **ObC00ki3s v5only no tiene punto de capacidad**: su baseline a 4 rps ya incumple el criterio de utilidad por el **FP conocido de `cks.js`** (contenido incorrecto), no por latencia (p95 ~115 ms). Se marca FP-bound, no saturación. El candidato sirve el ciclo por Fast Path (0 llamadas V5) y llega a ≥64 rps como directa/CRS.
- Las respuestas tardías no cuentan como rendimiento bajo SLO; se separan cola del cliente, etapas del gateway y V5 (en `test/ops/load/*/SUMMARY.json`). Las peticiones de carga repetidas no son etiquetas de calidad independientes.

**Fiabilidad (un stack nuevo por escenario; una observación por celda; reinicio fijado manual, no autónomo):**

| Escenario | Estado durante el fallo | Recuperación tras reinicio |
|---|---|---|
| V5 caído (`v5_down`) | 503 fail-closed en etapa `readiness` (cierra también el control Fast Path: la readiness gobierna todo el gateway) | ~12,5 s |
| gateway caído | 502 | ~12,5 s |
| app caída | sin respuesta (decisión tomada: `fast_path`/`v5`, sin entrega) | ~12,5 s |
| front caído | sin respuesta | ~12,6–13,2 s |
| `model2_down` | **N/A** (el perfil no tiene Model2) | — |

Mecanismos de error/invalid/timeout de V5 cubiertos por unidad y por `failure_check.py` con el doble (citados como mecanismo, no medición con V5 real). Recuperación autónoma y saturación sostenida: N/A.

**Reinicio del front bajo carga (ciclo An0nB0ard, 8 rps):** v5only recupera 5 respuestas útiles consecutivas bajo SLO en 0,69 s / 5 peticiones (158/160 útiles); candidato en 0,52 s / 5 peticiones (159/160). Baseline sano comparable en ambos brazos (por eso el ciclo An0nB0ard y no ObC00ki3s).

## Regresiones DEV conocidas (no son test; informadas aparte)

Los 41 pasos DEVREG de 2026-11-07 (benignos de CatP1cs, `cks.js`/estáticos de ObC00ki3s con sus cabeceras legacy, y el SSTI de cabecera en dos pasos) se ejecutaron con sus cabeceras originales. Resultado medido (crudos + `METRICS.json` `arms.*.devreg`): en los 41 benignos DEVREG, **v5only 8 FP; fastv5 y el candidato 0 FP**, con **36 aciertos de Fast Path** y 5 peticiones que siguen a V5. Es decir, los recursos públicos legacy **también** entran por Fast Path y el candidato **elimina** esos 8 FP de regresión (no los conserva). El SSTI de cabecera DEVREG persiste sin guardia y se impide con la guardia. No se ocultan ni se incorporan al test.

*(Corrección de informe sobre una redacción previa que decía que las cabeceras legacy «conservan el FP» en el candidato: lo correcto es 0 FP / 36 Fast Path, confirmado por la auditoría independiente de Codex. Crudos sin cambios.)*

## Explicación del modelo V5 (M06) — coincidencia de motivo con la familia

Gold por familia fijado antes del test. De los 49 pasos de inyección correctamente bloqueados por V5 en el candidato, 45 tienen familia adjudicada: **30 con motivo exacto correcto y 15 que no coinciden con la familia fijada** (coincidencia literal 30/45 = 66,7 %); 4 casos HTML quedan sin adjudicar. Los 15 desajustes son 4 SQLi etiquetados «command injection» y 11 traversal etiquetados «file inclusion»/«open redirect» — proximidad semántica, no coincidencia literal; el gold **no** se cambia tras el test. Los otros 17 bloqueos del candidato son de la guardia determinista, fuera del denominador de explicación de V5. (Métrica estricta; detalle en `METRICS.json`.)

## Límites declarados

- Seis apps de laboratorio (servidor de desarrollo Flask); tráfico de agente en un espacio de clientes declarado. La cobertura de Fast Path vale para ese espacio.
- Fast Path es específico por app y finito; lo que no encaja va a V5.1, que bajo v1 no ve cabeceras salvo `Content-Type`. El sistema completo **no** es zero-shot: las políticas se configuraron tras auditar estas apps.
- La guardia es un control determinista ligado a Inf3ct; no es una mejora del modelo y no cubre HTML almacenado.
- La contraseña de admin de ag3ncy no se midió (no disponible); ObC00ki3s solo admite entrega/clasificación.
- Los ceros son muestrales (N = 65 sesiones de ataque en 3 apps detectables; intervalos de Wilson **descriptivos, condicionados al generador**, en `METRICS.json`). Las 985 benignas tienen 934 identidades HTTP distintas pero solo 151 textos canónicos benignos en h1: no son 985 entradas independientes para V5. Sin población orgánica/humana, atacante adaptativo, ni generalización a apps nuevas.
- El muestreo de CPU/RAM/GPU es **diagnóstico**: la GPU incluye uso del escritorio y otros procesos, los ticks de CPU son acumulados (no porcentaje), no se aisló energía, no se descompusieron todos los tiempos internos de TLS/app, y no hubo prueba de resistencia prolongada (soak). Estos componentes quedan parciales o no medidos en la tabla M01–M35.
- Verificación cruzada: la auditoría independiente de Codex (`AUDIT_FINAL.md`, 1640 comprobaciones de evidencia, 0 discrepancias) recontó C1–C5 = PASS y aportó las correcciones de informe ya incorporadas aquí; mi revisión recíproca de sus políticas está en `CROSS_REVIEW_CLAUDE.md`.
