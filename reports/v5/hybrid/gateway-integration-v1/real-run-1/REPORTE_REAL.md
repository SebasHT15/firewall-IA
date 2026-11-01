# Firewall-IA: verificación con V4 y V5 reales

Ejecutado el 30 de octubre de 2026 en hora local, con relevo explícito de GPU. Rama `feat/hybrid-cascade-integration`, HEAD `499c8b2`. **Sin staging, sin commit, sin push, sin PR.**

**Resultado.** Los cuatro modos, las rutas y el retorno a V4 funcionan con V4, V5 y Model 2 reales sobre mitmproxy real. En 434 casos por modo, cada decisión coincidió con lo observado: el estado HTTP y la recepción independiente nunca se contradijeron. **D36 sigue sin cumplirse:** P95 de inferencia de 299 ms con la referencia y 259 ms con NF4, frente al objetivo de 200 ms. El gateway añade alrededor de 1 ms de P95.

**Esto no aprueba nada.** Alcance: reverse proxy, HTTP/1.1 en claro. Quedan sin aprobar el despliegue reverse, D70, P9/R3, una política productiva de Fast Path y el umbral 0,9, que sigue siendo `LAB_EXPERIMENTAL`.

## 1. Corridas

Todo en el código final salvo lo indicado. El detalle de cada corrida está en su archivo.

| Corrida | Configuración de V5 | Contenido | Resultado | Archivo |
|---|---|---:|---|---|
| Final | Referencia (NF4 con doble cuantización) | Rutas, contrato, modos y 434 casos × 4 modos | **43 de 43** | `reference-final_real_check.json` |
| NF4 | `nf4.EXPERIMENTAL.json`, con hash y opt-in | Rutas, contrato, V5_ONLY y ACTIVE | **30 de 30** | `nf4_real_check.json` |
| Medición aislada | Referencia y NF4, 3 procesos frescos de cada una | 95 entradas, V4 sin cargar | Completa | `perf/layers.json`, `perf/pooled.json` |
| Pruebas unitarias | Sin GPU | Nuevas y regresión | **520 de 520**, 0 omitidas | `unit_tests.json` |
| Verificación en vivo con doubles | Sin GPU | Mecanismos | **96 de 96** | `../live-doubles-run-2/live_check.json` |

Corridas conservadas de código anterior, ver sección 7: `reference_*` (43 de 43, antes de dos correcciones), `reference-fix1_*` (8 de 12, intento fallido) y `reference-fix2_*` (12 de 12).

## 2. Verificación funcional

| Comprobación | Evidencia con servicios reales |
|---|---|
| `V4_ONLY` | V4 decide, V5 recibe 0 llamadas, no existe runtime de cascada |
| `V5_ONLY` | V5 decide, 0 llamadas a V4, sin Model 2 ni Fast Path |
| `CASCADE_OBSERVE` | V4 decide; acción idéntica a `V4_ONLY` en 434 de 434; la cascada registrada es idéntica a `CASCADE_ACTIVE` en 434 de 434 |
| `CASCADE_ACTIVE` | 0 llamadas a V4; llamadas a V5 exactamente en los casos derivados: 382 |
| Ruta V5 ALLOW y BLOCK | Reenvía y deniega según el V5 real, con hash decidido igual al recibido |
| Ruta Model 2 | Early BLOCK sin llamada a V5, confirmado en el log del propio servicio |
| Ruta Fast Path | Solo el fixture experimental, sin llamada síncrona a modelos; V5 real audita después y sin efecto retroactivo |
| Rutas de protocolo | Rechazo canónico, HTTP/1.0 y CL duplicado: sin llamada a ningún modelo y nada entregado |
| Fallo de Model 2 | Worker muerto: deriva a V5. Al reiniciarse vuelve el early BLOCK |
| Timeout real de V5 | ACTIVE deniega. En OBSERVE la acción de V4 no cambia y el DENY solo queda registrado |
| Retorno a V4 sin reinicio | V4 real decide, V5 no recibe llamadas, la readiness sigue a V4 y la autoridad vuelve al retirar el centinela |
| Contrato | Otra receta, adaptador, vocabulario o perfil: no-ready y 503, nada entregado |

Las llamadas se contaron en los logs de los servicios, no en lo que dice el gateway.

## 3. L1/L2/L3 con recepción independiente

Población: los 434 casos `authored_paired_dev`, en orden, una petición cada vez. Recepción: sink en proceso propio que no importa nada del repositorio.

**Cómo leer esto.** La referencia es una expectativa construida, no un ataque confirmado. Los casos JWT y CSRF requieren estado para poder concluir nada. L1 mide concordancia con esa referencia. L3 dice si la petición llegó a un sink inerte, nunca si algo se explotó. No se usó el `eval.jsonl` histórico: según `reports/v5/successor-2026-10-30/coverage/`, sus referencias son débiles.

| Modo | L2 conforme | L1 concuerda | Referencia ALLOW entregada | Referencia ALLOW no entregada | Referencia BLOCK no entregada | Referencia BLOCK entregada |
|---|---:|---:|---:|---:|---:|---:|
| `V4_ONLY` | 434/434 | 359 | 153 | 68 | 206 | 7 |
| `V5_ONLY` | 434/434 | 394 | 221 | 0 | 173 | 40 |
| `CASCADE_OBSERVE` (actúa V4) | 434/434 | 359 | 153 | 68 | 206 | 7 |
| `CASCADE_ACTIVE` | 434/434 | 394 | 220 | 1 | 174 | 39 |

Referencias BLOCK entregadas en `CASCADE_ACTIVE`, por familia: ssrf 24, jwt 6, csrf 4, sql_injection 2, open_redirect 2, command_injection 1. De las 39, 10 son JWT o CSRF, que dependen de contexto, y 26 son ssrf u open_redirect, fuera del vocabulario entrenado.

Otras observaciones:

- **Model 2:** 52 early BLOCK, que evitan 52 llamadas a V5 de 434. 51 sobre intentos construidos y 1 sobre un benigno (`paired-BPR-0007`, p=0,913). Con ese umbral experimental, esto no estima ninguna tasa.
- **Salida inválida:** 1 caso (`paired-ATK-0144`, ssrf, `not_in_vocabulary`) se deniega con 503. Es un error de salida del modelo aunque el gateway no lo entregue.
- **Desacuerdos en OBSERVE:** 99 casos en que V4 bloquea y la cascada dejaría pasar. 67 con referencia benigna, 29 de intentos construidos y 3 dependientes de contexto.
- **Reproducibilidad:** las decisiones de V4 y V5 coinciden en 434 de 434 con la evidencia del 30 de octubre, y las probabilidades de Model 2 no cambian entre modos.

## 4. NF4 sin doble cuantización

Funciona con los mismos mecanismos: 30 de 30, L2 conforme en 434 de 434 en `V5_ONLY` y `CASCADE_ACTIVE`. V5 cambia una decisión de 434: `paired-ATK-0130` (ssrf) pasa de ALLOW a BLOCK. La cuantización no es exactamente equivalente en decisiones; un caso no permite decir más.

BF16 no se ejecutó en este trabajo y no se promueve. Queda protegido: un manifiesto que no nombra perfil se niega a un servicio con cualquier perfil, y esto se comprobó contra el servicio NF4 real.

## 5. Medición aislada por capas

Una configuración por proceso, V5 fresco en cada corrida, V4 sin cargar, orden equilibrado (`reference`, `nf4`, `nf4`, `reference`, `reference`, `nf4`), concurrencia 1, 95 entradas por corrida, cuatro calentamientos separados. Percentil por rango más próximo, sin eliminar atípicos. Las entradas son las de `reports/v5/successor-2026-10-30/runtime/protocol.json`, usadas solo para tiempos.

**P95 por corrida de la inferencia estable (D36, objetivo ≤ 200 ms):**

| Configuración | Corrida 1 | Corrida 2 | Corrida 3 | Agrupado (n=285) |
|---|---:|---:|---:|---:|
| Referencia | 289,08 ms | 298,50 ms | 300,80 ms | **299,35 ms** |
| NF4 sin doble cuantización | 255,53 ms | 250,48 ms | 262,78 ms | **258,68 ms** |

**Capas agrupadas, concurrencia 1, en ms (P50 / P95):**

| Capa | Referencia | NF4 |
|---|---:|---:|
| Inferencia (`pipeline_ms`) | 271,02 / 299,35 | 230,86 / 258,68 |
| Generación | 270,31 / 298,76 | 230,16 / 258,06 |
| Cola (espera de GPU) | 0,00 / 0,01 | 0,00 / 0,00 |
| Servicio | 271,12 / 299,43 | 230,97 / 258,77 |
| Cliente directo a la API | 271,92 / 300,42 | 232,06 / 259,70 |
| Salto a V5 desde el router | 277,10 / 312,01 | 231,04 / 257,70 |
| Gateway, ruta V5 | 277,91 / 312,65 | 231,85 / 258,41 |
| **Coste propio del gateway, por petición** | **0,77 / 1,06** | **0,77 / 1,03** |
| Cliente a través del gateway | 280,23 / 316,08 | 234,05 / 261,90 |

Dentro del coste propio, en `CASCADE_ACTIVE` y también en ms P50 / P95: enlace 0,05 / 0,09, canonicalización 0,33 / 0,55, Model 2 0,34 / 0,52 (referencia).

**Por ruta en `CASCADE_ACTIVE`, cliente, ms P50 / P95:**

| Ruta | n | Referencia | NF4 |
|---|---:|---:|---:|
| Model 2 early BLOCK | 102 | 2,92 / 5,61 | 2,95 / 4,69 |
| V5 | 183 | 296,15 / 318,44 | 246,50 / 268,14 |

**Concurrencia 4, 144 peticiones por configuración. No es capacidad:** la inferencia apenas cambia (P95 306 y 256 ms) y lo que crece es la cola de GPU (P50 730 y 628 ms; P95 861 y 721 ms), porque V5 sirve una generación a la vez. Cliente directo a la API, P95: 1.102 y 916 ms.

**Límites de esta medición:**

- Las capas se miden por separado y sus percentiles no se suman. El coste propio sí se calcula por petición.
- El salto a V5 y el cliente directo vienen de pasadas distintas. La diferencia de unos 12 ms de P95 en referencia no aparece en NF4 y no la atribuyo a nada.
- No se limitó la actividad gráfica del escritorio, que antes de cargar modelos ocupaba unos 1,5 GiB. Temperatura de 63 a 78 °C. Telemetría por corrida en `perf/*_gpu.jsonl`.
- Los valores de NF4 son unos 10 ms superiores a los medidos por Codex (239–254 ms) en otro arnés. No son condiciones idénticas y no concluyo nada de esa diferencia.
- BF16 bajó el P95 a 167–187 ms en la medición de Codex, con pérdida de detecciones. No lo medí.
- Son 285 observaciones por configuración, no carga sostenida.
- Los tiempos de `real_check` no son comparables: ahí V4 y V5 comparten GPU.

## 6. Hallazgo operativo

`CASCADE_OBSERVE` tardó 223 s frente a 106 s de `V4_ONLY` con los mismos 434 casos, porque aquí cada petición espera a su observación para evitar acumulación. Con tráfico real V5 y V4 competirían por la misma GPU. El gateway acota esa cola y descarta observaciones contándolas, pero **no medí** el efecto sobre la latencia de V4 ni la tasa de descarte en esa situación.

## 7. Defectos que encontró la prueba real

| Hallazgo | Efecto | Corrección |
|---|---|---|
| En OBSERVE, la readiness no esperaba al primer handshake de Model 2 | La primera observación (`paired-ATK-0001`) no era la cascada configurada. V4 no se vio afectado | La cascada espera ese handshake también en OBSERVE |
| Un manifiesto sin perfil aceptaba un servicio con perfil experimental | Promoción silenciosa posible, por ejemplo de BF16 | El perfil se compara en ambos sentidos |
| El arnés no esperaba a la cascada en OBSERVE y contaba como fallo L2 una observación omitida | 4 fallos en `reference-fix1`, conservada como intento fallido | `require_cascade` y L2 atribuido a la acción de V4 |
| Mi caso «V5 bloquea» lo bloqueaba antes Model 2 | No ejercitaba esa ruta | Otro caso sintético propio, elegido sin datos DEV |

`reference-final` repite la matriz completa sobre el código final. Frente a la primera pasada: 0 diferencias de estado HTTP y de ruta en los cuatro modos; en OBSERVE cambia solo `paired-ATK-0001`, por la corrección.

## 8. Integridad y privacidad

- `code_manifest.json` registra los hashes nuevos: 29 archivos míos, más fuentes servidas, adaptador, artefacto, políticas, perfil y manifiestos.
- 70 de 70 archivos inmutables sin cambios. De las 114 fuentes medidas el 30 de octubre, difieren solo las dos de Codex esperadas (`control_plane/v5_classifier_api.py`, `v5_inference_core.py`).
- La evidencia del 30 de octubre no se modificó. No ejecuté su `verify.py`.
- Sin conjuntos protegidos, sin entrenar, sin calibrar y sin seleccionar candidatos.
- Versiones: torch 2.6.0+cu124, transformers 5.8.0, peft 0.19.1, bitsandbytes 0.49.2, accelerate 1.13.0, mitmproxy 12.2.3, RTX 4090 Laptop, driver 595.99.02.
- Los logs de gateway y servicios pueden contener paths de datos DEV y están fuera del repositorio, en `/home/sebas/Documents/Codex/2026-10-26/ta/work/gateway-real-2026-10-30/`, porque `reports/**/*.log` se versiona. Aquí solo hay ids, códigos cerrados, booleanos y números.
- GPU libre al terminar, sin procesos míos. No edité `GPU_STATUS.json`.

## 9. Pendiente

| Pendiente | Quién |
|---|---|
| Aprobar o no reverse, D70, P9/R3 | Propietario |
| Presupuesto de falsos bloqueos y política de Model 2 con validación independiente | Propietario y Codex |
| D36: ninguna configuración aprobada lo cumple | Codex |
| Cobertura por familia, sobre todo ssrf, sin imitar referencias débiles | Codex |
| Contrato de una aplicación real para Fast Path, y una versión no-shadow de `fast_path.py` | Propietario |
| Prueba con una aplicación real como destino: aquí fue un sink inerte | Arquitectura |
| Carga sostenida; efecto de OBSERVE sobre V4 con GPU compartida | Arquitectura |
| TLS, HTTP/2 y Docker: siguen fuera del alcance | Decisión del propietario |

## 10. Reproducción

Con V4 y V5 levantados en terminales visibles (`docs/cascade_gateway.md`):

```bash
scripts/gateway_ops/run_real.sh reference-final v5_final.log v4_final.log reports/v5/hybrid/gateway-integration-v1/manifests/dev_fixture_baseline34.json
```

Antes de repetir, usa una etiqueta nueva: `real_check.py` rechaza sobrescribir evidencia. Para NF4, levanta el servicio con el perfil y su hash, y usa `manifests/dev_fixture_baseline34_nf4_profile.json`.

Medición aislada, sin ningún servicio levantado:

```bash
.venv-dataplane/bin/python scripts/gateway_ops/real_perf.py --out <directorio nuevo> --work <directorio privado> --manifest reports/v5/hybrid/gateway-integration-v1/manifests/dev_fixture_baseline34.json --inputs /home/sebas/Documents/Codex/2026-10-26/ta/work/metrics-2026-10-30/inputs.private.jsonl --benchmark-ids reports/v5/successor-2026-10-30/runtime/protocol.json
```

## 11. Archivos cambiados desde la entrega con doubles

Sigue sin modificarse ningún archivo existente del repositorio; todos estos son nuevos en este trabajo.

- **Código:** `data_plane/cascade_gateway.py` (tiempos por etapa, readiness en OBSERVE), `data_plane/cascade_manifest.py` (perfil en ambos sentidos).
- **Utilidades nuevas:** `scripts/gateway_ops/real_check.py`, `real_perf.py`, `run_real.sh`.
- **Utilidades ajustadas:** `live_check.py`, `live_stack.py`, `make_dev_manifest.py`, `collect_evidence.py`.
- **Pruebas:** `tests/test_cascade_manifest.py`, `tests/test_data_plane_cascade.py`.
- **Documentación:** `docs/cascade_gateway.md`; nota de actualización en `../REPORTE.md`.
- **Evidencia:** este directorio, `../live-doubles-run-2/` y `../manifests/dev_fixture_baseline34_nf4_profile.json`.
