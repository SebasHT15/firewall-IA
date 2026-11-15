# Correcciones al medidor de carga: impacto en `load-run-1`

1 de noviembre de 2026. Revisión de los dos hallazgos de `REVISION_PENDIENTE_CLAUDE.json`. **Sin staging, sin commit, sin push.**

**Resultado.** Los dos defectos eran reales y están corregidos. **Ninguna capacidad, ningún P50/P95/P99 ni ninguna conclusión de [INFORME_CARGA.md](../load-run-1/INFORME_CARGA.md) cambia.** La evidencia histórica no se tocó. Esto no aprueba nada.

| Pregunta | Respuesta | Certeza |
|---|---|---|
| ¿Se contó alguna respuesta truncada como útil en `load-run-1`? | No se encontró ninguna candidata: 0 filas | **Cota, no observación directa**, porque las filas no guardan bytes de cuerpo |
| ¿Cuántas peticiones estaban mal clasificadas como `verified`? | 27 de 35 133 | Exacto, recalculado de los registros |
| ¿Cambia algún percentil de inferencia? | 3 de 242 P95 por paso, como mucho 0,70 ms | Exacto |

## Hallazgo 1: una respuesta cortada contaba como completa

**Defecto.** `_read_status` devolvía el estado aunque la conexión terminara dentro del cuerpo. Era cierto: con 3 de 10 bytes declarados devolvía 200, y esa fila contaba como útil. La misma copia del defecto estaba en `_read_response` de `live_stack.py`, que usan las comprobaciones funcionales.

**Corrección.** `load_lib._read_response` lee el mensaje entero, con `Content-Length`, `chunked` o cierre de conexión. Una respuesta cortada queda con `status: null`, `partial_status` y `outcome: incomplete_body`. No es útil, no cuenta como completa y no demuestra entrega. Una denegación cortada sigue contando como denegación para L2. Un cuerpo delimitado por el cierre se marca `close_delimited`, porque ahí un corte es invisible.

### Impacto en los resultados conservados

Las filas de la corrida no guardan cuántos bytes llegaron, así que **no se puede contar directamente**. Lo que sí se puede establecer es de dónde podría salir un corte.

**1. Mientras el gateway está vivo, un fallo del destino no corta nada.** Prueba nueva con mitmdump real ([upstream_cut_probe.json](upstream_cut_probe.json)): un destino que entrega 3 de 10 bytes.

| Fallo inyectado | 12 peticiones | Cuerpos cortados |
|---|---|---:|
| Destino cierra, `CASCADE_ACTIVE` | 502 completo | **0** |
| Destino hace reset, `CASCADE_ACTIVE` | 502 completo | **0** |
| Destino cierra, `V4_ONLY` | 502 completo | **0** |
| Destino se cuelga y se mata el gateway, `CASCADE_ACTIVE` | Conexión cerrada sin respuesta | **0** |
| Destino se cuelga y se mata el gateway, `V4_ONLY` | Conexión cerrada sin respuesta | **0** |

Coincide con el código: el perfil exige `stream_large_bodies` vacío, así que mitmproxy retiene la respuesta entera y el cliente no recibe nada hasta tenerla.

**2. Queda un único origen: matar el gateway justo entre la cabecera y el cuerpo.** Mitmproxy los escribe por separado. Eso solo ocurrió en las 3 líneas de fallos ([response_completeness.json](response_completeness.json)):

| Línea | Filas con estado que terminan en el segundo posterior | Última con estado antes | Primera con estado después |
|---|---:|---:|---:|
| `failures_reference_rep1` | **0** | −0,285 s | +6,8 s |
| `failures_verified_rep1` | **0** | −0,249 s | +6,8 s |
| `failures_verified_rep2` | **0** | −0,089 s | +7,0 s |

Una fila cortada por esa muerte tendría que terminar justo después de ella. No hay ninguna. Las 7 filas de esos instantes ya estaban contadas sin estado.

**3. El resto de la corrida no tuvo cierres anómalos.** De 75 950 filas, 71 167 son de corridas sin procesos matados y todas terminaron en respuesta. Las 33 sin respuesta están todas en las líneas de fallos. Eso no prueba por sí solo que cada cuerpo llegara entero: la prueba son los puntos 1 y 2.

**Conclusión.** Candidatas a cuerpo cortado: **0 filas**. Las capacidades, los 503, L2 y los tiempos de recuperación no cambian. No tuve que recalcular ninguno.

**Límite.** Es un razonamiento sobre el mecanismo más una cota temporal, no una medición del cuerpo. Las corridas nuevas sí registran `framing`, `body_bytes` y `declared_body_bytes` por fila. Tampoco repasé las comprobaciones funcionales de `real-run-1` por fila: ahí el cliente era secuencial y no se mataba el gateway durante una petición, así que no hay razón para esperar efecto, pero no lo medí.

## Hallazgo 2: `decoder_fallback=false` no demuestra `decoder_verified=true`

**Defecto.** `decision_accounting` metía en `verified` todo lo que no era fallback. Un rechazo de contenido, que no genera nada, tiene los dos en falso y caía ahí. Lo mismo arrastraba al paso `v5_inference`, con muestras de menos de 1 ms.

**Corrección.** `decoder_path` usa las dos marcas y los tokens generados, y separa `verified`, `fallback`, `native`, `no_generation` e `inconsistent`. `v5_inference` solo lleva peticiones que generaron; el resto va a `v5_no_generation`.

### Impacto, exacto

Los registros de decisión conservan los tres campos, así que esto es un recálculo completo. Cada cifra es la versión medida de la biblioteca frente a la corregida, sobre los mismos registros ([decoder_accounting.json](decoder_accounting.json)).

| Marcas guardadas | Peticiones | Antes | Ahora |
|---|---:|---|---|
| `verified=true`, `fallback=false` | 35 106 | `verified` | `verified` |
| `verified=false`, `fallback=true` | 118 | `fallback` | `fallback` |
| `verified=false`, `fallback=false`, 0 tokens | **27** | **`verified`, mal** | `no_generation` |
| Ambas nulas, con tokens | 10 860 | Sin grupo | `native` |
| Ambas nulas, 0 tokens | 5 | Sin grupo, pero dentro de `v5_inference` | `no_generation` |

Las 32 sin generación son todas `content_rejected`. Ninguna petición quedó `inconsistent`.

| Efecto en la inferencia de V5 | Valor |
|---|---|
| Por corrida, P95 y P99 | 0,00 ms |
| Por corrida, P50 | Como mucho 0,06 ms |
| P95 por paso que cambian | 3 de 242 |
| Mayor cambio de P95 por paso | 0,70 ms, de 101,99 a 102,69 ms, `ladder_verified_V5_ONLY_rep2` a 12 r/s |
| Mayor cambio de P50 y P99 por paso | 0,77 y 0,93 ms |

### Tablas del informe

| Tabla de [INFORME_CARGA.md](../load-run-1/INFORME_CARGA.md) | Ahora | ¿Cambia? |
|---|---|---|
| §4, referencia `ACTIVE`, 280 / 297 / 304 ms | Igual, 0 muestras retiradas | No |
| §4, `verified` `ACTIVE` 2,8 r/s, 54 / 107 / 115 ms | Igual, 0 muestras retiradas | No |
| §4, `verified` `ACTIVE` 8,4 r/s, 52 / 103 / 111 ms | Igual, 0 muestras retiradas | No |
| §4, `verified` `V5_ONLY` 8,4 r/s, 52 / 104 / 110 ms | 52,15 / 103,90 / 110,33 ms, 8 retiradas | No, al redondear |
| §4, verificado frente a fallback: 11 240, 33, 10 | Mismas cuentas | No |
| §4, verificado, P50 52-55 y P95 103-108 ms | Mismo rango al redondear | No |

El informe ya separaba esos 10 rechazos a mano. Lo que estaba mal era `analysis.json`, cuyo grupo `verified` los incluía. **No se reescribió.** Sigue tal como lo produjo el código medido; este documento y `decoder_accounting.json` son la corrección.

## Reproducir

Las fuentes exactas de la corrida están en [executed_sources/](executed_sources/INDEX.json), con su hash, que coincide con `at-end/code_manifest.json` en los 21 archivos. Se copiaron antes de editar porque no están en Git.

```bash
.venv-dataplane/bin/python -B scripts/gateway_ops/load_corrections.py --run reports/v5/hybrid/gateway-integration-v1/load-run-1 --work /home/sebas/Documents/Codex/2026-10-26/ta/work/gateway-real-2026-10-30/load-run-1 --executed reports/v5/hybrid/gateway-integration-v1/load-run-1-corrections/executed_sources/scripts/gateway_ops/load_lib.py --out <directorio nuevo>
```

```bash
.venv-dataplane/bin/python -B scripts/gateway_ops/upstream_cut_probe.py --manifest reports/v5/hybrid/gateway-integration-v1/manifests/dev_fixture_baseline34.json --work <directorio privado> --out <archivo nuevo>
```

**Cambio de uso.** `load_analyze.py` ya no sustituye un análisis: exige `--out` nuevo. El comando de la sección 10 del informe ahora se niega a sobrescribir `analysis.json`, que es lo correcto.
