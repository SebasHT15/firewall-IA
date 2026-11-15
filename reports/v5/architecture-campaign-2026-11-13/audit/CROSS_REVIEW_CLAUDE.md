# Revisión cruzada de Claude sobre el runtime/políticas de Codex (recepción, semántica, efectos)

Complementa la auditoría de Codex sobre mis agregados. Evidencia: `fwlab-architecture-private/2026-11-11/` (DEV `real-v3`, `wire-guard-2`, `guard-v2-probe`; TEST `test/`). Candidato congelado `headerguard-v2`, V5.1 real.

1. **Sin Model2 en el camino activo (atribución).** 0 procesos/invocaciones Model2 y `/status.model2_worker=null` (clave presente) en las 24 corridas con cascada (DEV+TEST). Cada decisión lleva `deciding_stage` explícito. Confirmado.

2. **Fast Path = bytes públicos exactos, sin deriva semántica.** De **1041** respuestas decididas por Fast Path en TEST (benignas + sondas de límite), **0** difieren de la aplicación directa en status o SHA-256 (incluye condicionales 304 y archivos grandes). La política entrega lo que entrega la app, no una versión distinta. Confirmado.

3. **Límites del contrato respetados.** 584 sondas de límite: **0** `FAST_ALLOW` donde el contrato dice `CONTINUE` y **0** pérdidas donde dice `FAST_ALLOW`. Dot-segments, `%`-encoding, query, cuerpo, cabeceras desconocidas, duplicados, `Range`, `If-Match`, overrides, métodos no-GET → todos `CONTINUE`. CL+TE, forma absoluta, HTTP/1.0, `Host` duplicado/ausente/ajeno, obs-fold → rechazados en `framing`, nunca fast-allowed. `GET /favicon.ico` (regla I1b) sirve el 404 público constante, ligado a fuente+imagen. Confirmado.

4. **La vista de V5 no cambia.** Las familias que llegan a V5 dan el mismo resultado en `v5only` y `fastv5` (sin guardia): SQLi 26/26, traversal 16/16, `ssti_ctype_param` 2/2, `stored_html_body` 4/4 idénticos. El candidato no altera `canonical-request/v1` ni los pesos; solo evita o adelanta decisiones. Confirmado.

5. **Guardia de cabeceras (semántica y efecto).** `request-header-sink-guard/v2` MATCH sobre aperturas Jinja `{{ {% {#` en cualquier valor de cabecera de un POST (incl. `Host`, `Content-Type`, `Cookie`, `User-Agent`, `Referer`, `X-*`), **normaliza el método** (`post`/`PoSt` no evaden), decide en etapa `request_guard` antes de V5, responde 403 y **la app no recibe** la petición (verificado por observador OOB en `/log`). Controles benignos con llaves sueltas / JSON en cookie / `%` → CLEAR (no MATCH). Fuera de alcance declarado: HTML almacenado (`stored_html_header`), que persiste en los tres brazos de cascada y sí detiene CRS. La prevención se atribuye al control determinista, nunca a V5. Confirmado y medido por ablación `fastv5 → fastv5_guard`.

6. **Fail-closed y entrega.** Con V5 caído el gateway responde 503 en `readiness` (cierra también el control Fast Path: la readiness gobierna todo el gateway); gateway caído 502; recuperación ~12,5 s por reinicio fijado. El guard de entrega/egress-framing se conserva.

**Conclusión:** la recepción, la semántica y los efectos de las políticas de Codex coinciden con lo que la app consume; no observo FAST_ALLOW indebido, deriva de bytes, cambio de la vista de V5 ni atribución incorrecta de la guardia. Los límites conocidos (stored-HTML fuera de la guardia; FP de V5 en rutas dinámicas que llegan a él) quedan informados, no ocultos.
