# Firewall-IA: integración de la cascada en el gateway

> **Actualización.** Este reporte describe la entrega con doubles. La verificación con V4 y V5 reales está en [`real-run-1/REPORTE_REAL.md`](real-run-1/REPORTE_REAL.md). Dos correcciones de lectura: una referencia no es un ataque confirmado, y `attack_delivered` / `L1_correct` de `live-doubles-run-1` significan solo «entregado a un sink inerte con referencia BLOCK» y «coincide con la referencia»; el arnés ya usa nombres neutros. El grupo `real_models` y el comando de la sección 10 se sustituyeron por `real_check.py` y `run_real.sh`.

Fecha: 30 de octubre de 2026. Rama `feat/hybrid-cascade-integration`, HEAD `499c8b2`. **Sin staging, sin commit, sin push, sin PR.** Pendiente de revisión de Sebas.

**Resultado.** La cascada corre dentro de mitmproxy real en los cuatro modos, con retorno a V4, y el framing queda ligado a los bytes que recibe el destino. **Esto no acredita despliegue.** V5 y V4 reales no se ejecutaron: durante todo el trabajo la GPU fue de Codex y no hubo relevo. Toda decisión de V5 y V4 en esta evidencia viene de un double con una regla fija, así que aquí no hay ninguna métrica de calidad ni de latencia.

## 1. Estado por nivel de evidencia

| Componente | Implementado | Probado con doubles | Probado con modelo real | Pendiente |
|---|---|---|---|---|
| Orquestador en mitmproxy (4 modos, retorno a V4) | Sí | Sí, con mitmdump real | Parcial: solo Model 2 | V5 y V4 reales |
| Framing `gateway-framing/v1` y guard de egreso | Sí | Sí, con sockets y mitmdump reales | No depende de modelo | Decisión del propietario; TLS y HTTP/2 rechazados |
| Canonicalización en workers (`canonical-request/v1`) | Sí | Sí, con workers reales | No depende de modelo | Regla P9 para uso activo |
| Model 2: worker y cliente | Sí | Sí, con worker falso para fallos | **Sí**: artefacto baseline34 real, en CPU | Política operativa: 0,9 sigue siendo `LAB_EXPERIMENTAL` |
| V5: cliente y readiness por contrato | Sí | Sí, con double | **No** | Prueba real tras relevo de GPU |
| V4: camino de autoridad | Sin cambios, es `data_plane.py` | Sí, con double | **No** | Prueba real tras relevo de GPU |
| Fast Path: activación explícita | Sí | Sí, solo con fixture experimental | No aplica | Contrato de una aplicación real |
| Auditoría asíncrona de Fast Path | Sí | Sí | No: el auditor fue el double de V5 | Tasa de muestreo real |
| Manifiesto, configuración, readiness, métricas, registros | Sí | Sí | Manifiesto validado con artefactos reales | Valores operativos reales |
| Pruebas L1/L2/L3 con recepción independiente | Preparadas y ejecutadas | Sí, 9 casos | No | Población y protocolo propios |

## 2. Por qué la garantía del laboratorio no se transfiere

El laboratorio HTTP/1.1 reenvía los mismos bytes que recibe. mitmproxy no hace eso:

- Interpreta el mensaje del cliente, tolera formas que el parser del proyecto rechaza y **serializa un mensaje nuevo** hacia el destino.
- Addons internos que corren **después** del hook del script (`modify_headers`, `map_remote`, `sticky*`, `upstream_auth`) todavía pueden cambiar la petición.

Lo inspeccionado y lo que parsea el destino son secuencias de bytes distintas. `PROFILE_MATCHED` (D70) no dice nada sobre la segunda, sigue siendo solo observación y no se usa aquí.

El control nuevo es del proyecto y vive en el único salto que el proyecto controla:

```
cliente -> mitmproxy -> EgressGuard (loopback) -> aplicación
```

1. Antes de decidir, `bind_delivery` serializa con el ensamblador de mitmproxy, parsea con el parser estricto y exige un solo mensaje completo, sin ambigüedad e igual al objeto petición. Se decide sobre esas partes.
2. Un FORWARD emite un ticket de un solo uso para el hash de esos bytes.
3. El guard recibe lo que mitmproxy serializó de verdad, lo enmarca, canjea el ticket por esos bytes exactos y reenvía **esos** bytes. Cualquier otra cosa no se entrega.

**Qué atestigua `EGRESS_BOUND`:** que se decidió sobre un mensaje estrictamente enmarcado, y que ese mensaje es lo único que puede llegar al destino por esa decisión.

**Qué no atestigua:**

- Los bytes de entrada del cliente: un bare-LF sigue saliendo normalizado.
- TLS, HTTP/2 o HTTP/3.
- Cómo se comporta un parser no conforme del destino.

Alcance versionado en `gateway_framing.SCOPE`. Se rechazan de forma explícita HTTP/1.0, HTTP/2, HTTP/3, TLS de entrada, las formas absolute, authority y asterisk, cuerpos en streaming, trailers, upgrades, WebSocket y un número de `Host` distinto de uno.

`Upgrade: h2c` es un caso aparte: mitmproxy lo elimina antes del hook, y se entrega sin él como petición normal. Decidido y entregado coinciden.

`FramingEvidence(VERIFIED)` sale de este enlace por petición, nunca de un perfil ni de una constante. Solo se produce con `verified_evidence: true`, y fuera del perfil `lab` exige `owner_ruling_ref`. El ejemplo de configuración lo deja en `false`.

## 3. Modos

| Modo | Decide | Guard en el camino | Si falla un componente de la cascada |
|---|---|---|---|
| `V4_ONLY` | V4 | No | No existe cascada |
| `CASCADE_OBSERVE` | V4, primero; la cascada se calcula después | No | Se pierde la observación, V4 no cambia |
| `V5_ONLY` | V5 | Sí | Deniega |
| `CASCADE_ACTIVE` | Fast Path, Model 2, V5 | Sí | Model 2 deriva a V5; lo demás deniega |

- En OBSERVE el guard queda fuera a propósito: si estuviera, su caída cambiaría la entrega de V4.
- Model 2 solo produce BLOCK o DEFER. Una excepción o un estado no-OK deriva a V5, y un ALLOW en esa frontera es violación de protocolo.
- V5 inválido, con error o con timeout deniega.
- `data_plane.py` no se modificó: `cascade_addon.py` lo subclasifica, de modo que el camino V4 es ese mismo código.

**Despliegue elegido:** modo reverse, porque el guard debe ser el destino de mitmproxy. `compose.yaml` y el modo `regular` siguen siendo el gateway V4 habitual, sin cambios. Es una elección de ingeniería pendiente de tu confirmación (sección 8).

## 4. Fast Path y auditoría

No hay contrato de una aplicación real, así que el Fast Path queda `disabled` y su política productiva deshabilitada. `experimental_fixture` solo corre en perfil `lab`, con el hash fijado y `fast_path_lab_app.json` (estado `PROPOSED`) como fixture sintético. `production` exige política `APPROVED` y `application_contract_ref`. No se inventó ningún endpoint seguro.

La auditoría `fast-path-audit/v1` corre tras aplicar la acción, con cola acotada en elementos y en bytes:

- Muestreo determinista y recomputable: `sha256(salt|correlation_id)`, con bucket e id de sal en cada registro.
- Saturación, timeout, errores y apagado terminan cada uno en un registro: cada permiso elegible deja exactamente uno.
- `retroactive_effect: none`. Un BLOCK del auditor es un registro y un contador. El módulo no referencia el flow, el ticket ni la política, y el permiso aplicado no cambia.

## 5. Evidencia nueva

Todo bajo `reports/v5/hybrid/gateway-integration-v1/`. Se ejecutó en CPU, en una pestaña visible, con los logs persistidos.

**Pruebas unitarias (`unit_tests.json`): 518 de 518, 0 omitidas.**

| Grupo | Pruebas |
|---|---:|
| Nuevas: manifiesto 28, operación y auditoría 22, framing 44, workers 22, modos en addon 44 | 160 |
| Regresión en data plane | 286 |
| Regresión en analyzer, incluye las 72 del informe del 30 de octubre | 72 |

**Verificación en vivo (`live-doubles-run-1/live_check.json`): 96 de 96, en 21 s.** Usa mitmdump, workers canónicos, guard y Model 2 reales en CPU, un sink independiente en proceso propio que no importa nada del repositorio, y doubles de V4 y V5.

| Grupo | Checks | Qué demuestra |
|---|---:|---|
| `framing` | 33 | Segmentación, TE+CL, CL duplicado, obs-fold, bare-LF, pipelining, alcance, tamaño, acceso directo al guard, privacidad |
| `observe` | 22 | Acción de V4 sin cambios con V5 caído, colgado o inválido, y con el worker de Model 2 muerto; manifiesto inservible |
| `failures` | 12 | V5 inválido, 500, 503, JSON malo y timeout deniegan; caída y regreso de Model 2; deriva de contrato detiene la readiness |
| `fast_path_audit` | 8 | Coincidencia, desacuerdo sin efecto retroactivo, timeout, un registro por permiso |
| `return_to_v4` | 7 | Retorno con y sin reinicio, V4 fallando en el retorno, recuperación |
| `v5_only` | 5 | Sin Model 2 ni Fast Path; inválido deniega |
| `shutdown` | 4 | Salida limpia, sin workers huérfanos, arranque rechazado con manifiesto inservible |
| `saturation` | 3 | Ráfaga sobre límites pequeños y recuperación. No mide capacidad |
| `after_hook_mutation` | 2 | Un addon posterior cambia la petición: 502 y nada entregado |

En cada FORWARD del grupo `framing`, el hash decidido se compara con el que registró el sink.

**L1/L2/L3 (9 casos, D41).** L2 conforme en 9 de 9. L1 correcta en 8 de 9. El caso incorrecto es esperado y útil: en `V5_ONLY` el double no bloquea el traversal, se entrega y L3 lo marca `attack_delivered`, lo que confirma que la contabilidad distingue las capas. **No son métricas de calidad:** L1 compara una etiqueta con una regla fija. `attack_delivered` significa recibido por un sink inerte, no explotación.

**Integridad (`code_manifest.json`).** 70 de 70 archivos inmutables sin cambios. De las 114 fuentes medidas el 30 de octubre, ninguna cambió por este trabajo. Dos sí difieren del registro, `control_plane/v5_classifier_api.py` y `v5_inference_core.py`, por el trabajo paralelo de Codex; por eso `verify.py` de aquel informe ya falla en esas dos comprobaciones si se vuelve a ejecutar. No se editó ningún archivo de aquella evidencia.

No hay ninguna medición de latencia en este informe, y nada aquí dice nada sobre D36.

## 6. Defectos encontrados y corregidos durante el trabajo

| Defecto | Efecto | Corrección |
|---|---|---|
| El guard registraba `DELIVERED` antes de escribir al destino | Un destino caído quedaba registrado como entregado; mi prueba solo miraba el último evento | Se registra tras escribir; la prueba exige cero `DELIVERED` |
| mitmdump imprime cada URL con su query | Fuga de payload al log; mi prueba de privacidad no leía ese log | `flow_detail=0` forzado por el perfil; la prueba lee el log, también con peticiones malformadas |
| Readiness verde antes del handshake de Model 2 | Las primeras peticiones iban a V5 sin early block | `CASCADE_ACTIVE` exige un primer handshake válido |
| mitmdump sale si hay un ERROR durante el arranque | Un manifiesto malo en OBSERVE tumbaba también a V4 | Se registra como WARNING en esos caminos |
| El double de una prueba no tenía el campo `runtime_profile_sha256` | Falló la primera recolección | Usa el tipo real. Intento conservado en `attempts/collect-1-stale-test-double/` |

## 7. Limitaciones conocidas

- El guard corre en el proceso de mitmdump: no aísla fallos de ese proceso y un mensaje grande parseado por segmentos cuesta CPU en el event loop, acotado por `max_message_bytes`. No se midió.
- El salto del guard al destino es texto claro, pensado para loopback o red privada.
- En OBSERVE con modelos reales, la cascada consume la misma GPU que V4. Hay que comprobarlo antes de usarlo con tráfico.
- `fast_path.py` sigue siendo `fast-path/v1-shadow` con `enforced=False`, aunque el router aplica el FAST_ALLOW del fixture. No se cambió porque está ligado a la evidencia. Un uso productivo necesita una versión nueva del contrato.
- `max_bytes_per_token=48` procede de V4 según `canonical_request.py`. El fixture lo usa sin reverificar.
- La ráfaga de saturación no es una prueba de carga. No hay carga sostenida ni medición de sobrecoste del gateway.
- Los valores de `config.cascade.example.yaml` son de arranque, no medidos ni ratificados.

## 8. Bloqueos concretos y decisiones pendientes del propietario

No se registró ninguna decisión ni aprobación en `DECISIONS.md`.

| Bloqueo | Qué falta | Referencia |
|---|---|---|
| Prueba con V5 y V4 reales | Relevo explícito de GPU. `GPU_STATUS.json` dice `SERVICE_PROFILE_STAGE_FINISHED`, que no es un relevo | Sección 10 |
| Usar `FRAMING_VERIFIED` fuera del laboratorio | Decisión tuya sobre `gateway-framing/v1` y el salto atestiguado | D70, «not approved / still pending» |
| Confirmar mitmproxy reverse como despliegue | Decisión tuya | Sección 3 |
| Fast Path productivo | Contrato de la aplicación real, política `APPROVED` y contrato no-shadow | D57; `cascade_manifest.py` |
| Política operativa de Model 2 | Presupuesto de falsos bloqueos y calibración sobre validación independiente; revalidar si el Fast Path cambia la población | Plan; informe del 30 de octubre, §7 |
| Candidato sucesor | Manifiesto de Codex | `docs/cascade_gateway.md` |
| Canonicalización activa | Elegir P9 superset o R3, y fijar br/zstd con hashes de wheel | D63, D69, D70 |
| D36 | Sigue sin cumplirse en lo medido el 30 de octubre | Informe del 30 de octubre, §5 |
| TLS y HTTP/2 | Decidir si entran en alcance; necesitarían contrato y evidencia propios | `gateway_framing.SCOPE` |
| Docker | `compose.yaml` no integra el gateway de cascada | `docker/data-plane/Dockerfile` |

## 9. Archivos

Solo archivos nuevos. **Ningún archivo existente fue modificado por este trabajo.** `.gitignore` ya aparecía modificado al empezar.

**Gateway y operación (`data_plane/`):**

- `cascade_addon.py`: punto de entrada de mitmproxy.
- `cascade_gateway.py`: orquestación, readiness, retorno a V4.
- `cascade_manifest.py`: manifiesto y configuración estrictos.
- `cascade_ops.py`: métricas, cola acotada, JSONL rotado, puerto de administración.
- `cascade_canonical.py`, `cascade_canonical_worker.py`: canonicalización en worker.
- `gateway_framing.py`: alcance, perfil, enlace, tickets y guard.
- `fast_path_audit.py`: auditoría asíncrona.
- `model2_client.py`, `model2_worker.py`: Model 2 en proceso aparte.

**Utilidades (`scripts/gateway_ops/`):** `__init__.py`, `launch.py`, `make_dev_manifest.py`, `live_stack.py`, `live_check.py`, `service_doubles.py`, `independent_sink.py`, `collect_evidence.py`, `fixtures/after_hook_mutation_addon.py`.

**Pruebas (`tests/`):** `test_cascade_manifest.py`, `test_cascade_ops.py`, `test_cascade_workers.py`, `test_data_plane_cascade.py`, `test_gateway_framing.py`.

**Configuración y documentación:** `config.cascade.example.yaml`, `docs/cascade_gateway.md`.

**Evidencia (`reports/v5/hybrid/gateway-integration-v1/`):** este reporte, `unit_tests.json`, `code_manifest.json`, `manifests/`, `live-doubles-run-1/`, `attempts/`.

Los hashes de los 26 archivos de código, configuración y documentación están en `code_manifest.json`, generado antes de escribir este reporte.

## 10. Arranque, prueba y retorno

Referencia completa: [`docs/cascade_gateway.md`](../../../../docs/cascade_gateway.md). Comandos desde la raíz del repositorio.

Validar sin modelo ni GPU:

```bash
.venv-dataplane/bin/python scripts/gateway_ops/launch.py --config config.cascade.example.yaml --check
```

Arrancar:

```bash
.venv-dataplane/bin/python scripts/gateway_ops/launch.py --config config.cascade.example.yaml
```

Readiness, con el puerto de `admin_port`:

```bash
curl -s http://127.0.0.1:8090/readyz
```

Reproducir la evidencia en un directorio nuevo (CPU, sin modelos):

```bash
.venv-dataplane/bin/python scripts/gateway_ops/live_check.py --out reports/v5/hybrid/gateway-integration-v1/live-doubles-run-2
```

Retorno a V4 sin reiniciar, con el servicio V4 activo:

```bash
touch reports/v5/hybrid/gateway-integration-v1/runtime/RETURN_TO_V4
```

Devolver la autoridad a la cascada:

```bash
rm reports/v5/hybrid/gateway-integration-v1/runtime/RETURN_TO_V4
```

Retorno permanente: poner `mode: V4_ONLY` y reiniciar, o usar el gateway V4 habitual.

Prueba real, **solo tras el relevo de GPU**, con ambos servicios levantados:

```bash
.venv-dataplane/bin/python scripts/gateway_ops/live_check.py --out reports/v5/hybrid/gateway-integration-v1/real-run-1 --manifest reports/v5/hybrid/gateway-integration-v1/manifests/dev_fixture_baseline34.json --v5-url http://127.0.0.1:8001 --v4-url http://127.0.0.1:8000 --group real_models
```

Esa prueba valida el cableado con modelos reales. Si Codex entrega un candidato nuevo, se usa su manifiesto. Sus tres casos no son una evaluación.
