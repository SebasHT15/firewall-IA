# Preparación de la cascada para el V5 sucesor

1 de noviembre de 2026. Rama `feat/hybrid-cascade-integration`, HEAD `499c8b2`. **Sin staging, sin commit, sin push, sin PR.**

**Resultado.** La cascada Fast Path → C1 → Model 2 → V5 queda lista para recibir el candidato y medirlo en cuanto lleguen los pesos. **Todo se probó con simulaciones: ningún modelo se cargó y la GPU no se usó.** Esto no aprueba el candidato, ningún umbral, ningún perfil ni un despliegue, y no acredita D36. Los 200 ms siguen siendo aspiracionales.

| Punto | Estado | Evidencia |
|---|---|---|
| 1. Manifiestos de candidato | Hecho. El perfil rápido viejo se rechaza | 43 pruebas; receta real del sucesor comprobada |
| 2. Coste de la auditoría | Hecho, medido con dobles | 16 pruebas nuevas; [comparison.json](doubles-audit-budget/comparison.json) |
| 3. Medidor | Corregido. **Ningún resultado conservado cambia** | [CORRECCIONES.md](../load-run-1-corrections/CORRECCIONES.md) |
| 4. Recorrido del candidato | Preparado, con dobles 57/57 | [walkthrough.json](walkthrough-doubles/walkthrough.json) |
| 5. Ensayos de tráfico y operación | Preparados, arnés ensayado de punta a punta | [TABLAS.md](doubles-dry-run/TABLAS.md) |
| 6. Aplicación | Inventariada, sin tráfico | [INVENTARIO_APLICACION.md](INVENTARIO_APLICACION.md) |

## 1. Entrega de candidatos

Un candidato es ahora un `firewall-cascade-model-manifest/v2`, y v1 sigue legible para lo que ya lo usa. Añade rutas de adaptador y receta, modelo base, contrato de tokens completo y un `runtime` obligatorio.

- **El perfil de ejecución no tiene valor por defecto.** Hay que elegir `--native-runtime` o un perfil de esos pesos.
- **El perfil rápido actual queda fuera.** Se probó con el archivo real: `profile is bound to another adapter`. Lo decide el propio perfil, no lo que afirme el manifiesto.
- **Un decodificador verificado exige evidencia** que nombre ese perfil, porque coincidir con la generación nativa es un resultado empírico de esos pesos.
- **Se rechaza en tres momentos:** al leer el manifiesto, sin conexión contra los archivos, y en readiness contra el servicio.

Con dobles, el candidato correcto pasa y cada servicio distinto se rechaza con su motivo: adaptador, receta, vocabulario, B, contrato de tokens, plantilla, revisión base y runtime. Con la receta real del sucesor (`8a831ad2…`, 12 salidas, B 415, presupuesto de etiqueta 13) el manifiesto se genera y `candidate_check.py` da `IDENTITY_CONSISTENT`. El adaptador de esa prueba era un fixture.

También se quitó el último valor fijo del arnés: el límite de cuerpo ahora sale del manifiesto, no de 19 920.

## 2. Coste de la auditoría Fast Path

La carga mostró que la auditoría competía con el tráfico por V5. Ahora tiene presupuesto:

| Control | Efecto |
|---|---|
| Cubo de tokens | Limita cuántas auditorías pueden empezar (`RATE_LIMITED`) |
| Ceder el paso | Una auditoría en cola solo arranca si el tráfico no ocupa V5 |
| Edad máxima | La que no encuentra hueco caduca (`EXPIRED`), sin llamar a V5 |
| Cola acotada | En elementos y en bytes (`SATURATED`) |

`solicitadas = completadas + descartadas + fallidas + en curso`, en cualquier instante. Está en `/metrics` y en `/status`, con una prueba de concurrencia que lo comprueba mientras cambia.

**Medición con doble.** V5 simulado que tarda 150 ms y atiende de uno en uno, 3 r/s de tráfico DEV y 8 r/s de permisos del fixture, 40 s, 2 repeticiones agrupadas:

| Muestreo y presupuesto | Tráfico P50 / P95 / P99 | Auditorías completadas | Descartadas |
|---|---:|---:|---:|
| 0, sin auditoría | 164 / 386 / 545 ms | 0 | 0 |
| 1, sin presupuesto | **272 / 732 / 861 ms** | 469 de 644 | 175 |
| 1, con presupuesto | **170 / 419 / 576 ms** | 166 de 644 | 478 |

La respuesta Fast Path no varía: P95 cerca de 14 ms en las cuatro combinaciones.

**Lectura.** El presupuesto devuelve casi toda la latencia, a cambio de auditar mucho menos. Sigue habiendo un coste, porque V5 no admite interrupción: una auditoría ya empezada retrasa hasta una inferencia. Los tiempos son los que se le dieron al doble, así que esto prueba el mecanismo, no una capacidad. Los valores del presupuesto son de partida, no están dimensionados. Bajo presupuesto se auditan las primeras que caben, de modo que el muestreo deja de ser uniforme.

## 3. Medidor

Resumen del detalle en [CORRECCIONES.md](../load-run-1-corrections/CORRECCIONES.md):

- **Cuerpo truncado.** Corregido en `load_lib.py`, y también en `live_stack.py`, que tenía el mismo defecto. Candidatas en `load-run-1`: **0 filas**. Es una cota, no una observación, porque las filas antiguas no guardan bytes.
- **`decoder_fallback=false`.** Corregido. 27 de 35 133 peticiones estaban mal en `verified`. Cambian 3 de 242 P95 por paso, como mucho 0,70 ms. Ninguna celda del informe cambia al redondear.

`INFORME_CARGA.md`, `analysis.json` y todos los datos de `load-run-1` quedaron intactos. No se afirma que los ensayos anteriores estuvieran afectados: lo medido es que sus cifras no cambian.

## 4. Recorrido del candidato

`candidate_walkthrough.py` separa tres capas que nunca se suman:

| Capa | Qué comprueba | Con dobles |
|---|---|---|
| Mecanismo | Identidad y readiness, rutas reales, Model 2 caído o colgado → DEFER, 11 fallos de V5 → denegación, recepción independiente, recuperación, privacidad | 57 de 57 |
| Clasificación | Decisiones sobre DEV de autores frente a referencias, que no son verdad de terreno | `NOT_MEANINGFUL_WITH_DOUBLES` |
| Efecto del ataque | Nada: el sink solo prueba entrega | `NOT_MEASURED` |

Una ruta V5 no asume qué decidirá el candidato: comprueba que la acción sigue a su decisión. Los fallos los inyecta un reenviador entre gateway y V5, así un servicio real falla de todas las formas sin tocar sus pesos.

## 5. Ensayos posteriores al entrenamiento

`run_candidate_load.sh` mide el candidato sin depender de V4, con identidad tomada solo del manifiesto. Las tasas salen de la escalera de ese candidato: `--recovery-rate` es obligatorio y nunca hereda el valor de V4.

Quedan cubiertos tiempos por etapa y de extremo a extremo, P50/P95/P99, carga ofrecida, respuestas completas, capacidad útil, rechazos, errores, cuerpos cortados, colas muestreadas cada segundo, recursos y recuperación. Los percentiles entre repeticiones se calculan sobre las filas agrupadas, con una prueba que lo exige. `load_analyze.py --markdown` genera las tablas. Los comandos exactos están en [cascade_candidate_handoff.md](../../../../../docs/cascade_candidate_handoff.md).

## 6. Aplicación

Existe `lab-app`, y su imagen coincide byte a byte con el repositorio. Sirve para tráfico benigno y entrega real. **No sirve para medir efecto de ataques, porque es inerte a propósito.** No se le envió nada y no se arrancó ningún contenedor. No se inventó ningún contrato. El [inventario](INVENTARIO_APLICACION.md) detalla lo que falta para Fast Path productivo, TLS/HTTP2 y contexto JWT/CSRF, ninguno resuelto.

## Pruebas ejecutadas

| Prueba | Resultado |
|---|---|
| Suite afectada, código final | **659 de 659**, 0 omitidas ([at-end](at-end/unit_tests.json)); antes 560 |
| Matriz viva con dobles | **96 de 96** ([live_check.json](live-doubles/live_check.json)) |
| Recorrido con dobles | **57 de 57** |
| Ensayo del arnés, todas las fases con `--quick` | Terminó sin error ([doubles-dry-run](doubles-dry-run/)) |
| Fuentes inmutables | 0 de 70 cambiadas |
| Fuentes de medición cambiadas | Solo las 2 de V5 de Codex, igual que antes |

**No verificado:**

- Nada se ejecutó con pesos reales. El arranque real del servicio del candidato en el recorrido y en la carga no se ha ejercitado.
- `--with-v4` solo tiene pruebas de configuración, sin ensayo.
- La capa de clasificación se ejecutó una vez con dobles sobre 6 casos, solo para ver que no falla.
- El ensayo del arnés usa duraciones mínimas y una repetición: prueba que funciona, no una capacidad.

## Al llegar los pesos

**Se puede ejecutar de inmediato,** con la GPU reservada:

1. `make_candidate_manifest.py`
2. `candidate_check.py`
3. `candidate_walkthrough.py`
4. `run_candidate_load.sh`

Los scripts que cargan un modelo se niegan a arrancar salvo con `AVAILABLE_FOR_CLAUDE` o `IN_USE_BY_CLAUDE`. El estado actual es `AVAILABLE`, sin relevo, y también se rechaza.

**Debe aportar Codex:** adaptador, receta, medición de tokens con sección `measured` y decisión de runtime. Si quiere el decodificador verificado: perfil nuevo para esos pesos y evidencia que incluya `profile_sha256`.

**Requiere aplicación real:** efecto de ataques, Fast Path productivo, TLS/HTTP2, JWT/CSRF, capacidad con tráfico real y umbrales con presupuesto de falsos bloqueos.

## Decisiones que siguen abiertas

| Decisión | Motivo |
|---|---|
| ¿Autorizar `lab-app` para tráfico benigno, y con qué aislamiento? | Su red tiene salida a Internet y no está conectada a la cascada |
| V4 sin control de admisión | Sigue sin corregir, fuera de este trabajo. Solo importa si V4 sigue siendo el plan de retirada |
| D70, P9/R3, umbral de Model 2, perfil de V5 | Ninguna se resuelve con esta preparación |

## Archivos

**Nuevos:** `docs/cascade_candidate_handoff.md`; en `scripts/gateway_ops/`: `make_candidate_manifest.py`, `candidate_check.py`, `candidate_walkthrough.py`, `fault_proxy.py`, `gpu_gate.py`, `load_corrections.py`, `upstream_cut_probe.py`, `run_candidate_load.sh`, `fixtures/faulty_upstream.py`; `tests/test_cascade_candidate.py`, `tests/test_candidate_trials.py`.

**Modificados, ya sin commit antes de hoy:** `data_plane/cascade_manifest.py`, `fast_path_audit.py`, `cascade_gateway.py`; `config.cascade.example.yaml`, ahora esquema v2; `docs/cascade_gateway.md`; en `scripts/gateway_ops/`: `load_lib.py`, `load_check.py`, `load_analyze.py`, `live_stack.py`, `service_doubles.py`, `launch.py`, `real_perf.py`, `collect_evidence.py`; `tests/test_load_lib.py`, `test_cascade_ops.py`, `test_cascade_manifest.py`, `test_data_plane_cascade.py`.

**Sin tocar:** `data_plane/cascade.py`, `cascade_runtime.py`, `data_plane.py`, `fast_path.py`, todo `control_plane/`, las 70 fuentes inmutables y `load-run-1`.

**Compatibilidad.** La configuración del gateway pasa a `firewall-cascade-gateway-config/v2` porque el presupuesto de auditoría es obligatorio. Una configuración v1 se rechaza con un mensaje claro. `load_analyze.py` ya no sobrescribe un análisis.

Los registros privados de estos ensayos están fuera de Git, en `/home/sebas/Documents/Codex/2026-10-26/ta/work/gateway-real-2026-10-30/preparation-2026-11-01/`.
