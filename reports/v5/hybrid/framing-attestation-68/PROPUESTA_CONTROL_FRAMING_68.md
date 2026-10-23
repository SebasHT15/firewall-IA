# #68 — Control de framing: delta real sobre D70 (slice acotado)

**Fecha:** 2026-10-23 · **Autor:** Claude (frente gateway/datos, en paralelo con Codex) ·
**Rama:** `feat/hybrid-training-integration`, base reconciliada con `develop`/D70
`7ee8570830f6e9bfaa3edfa381ca430693e911f4`. **Cierre editorial:** Codex, por encargo
del owner, 2026-10-23. D70 entró mediante fast-forward, sin commit nuevo y preservando
los archivos locales. Las observaciones sobre su código se contrastaron con `b433505`
y con la base ya reconciliada; no se copió su implementación a mano.
**Alcance:** reporte propio de especificación del *delta*. **No re-propone construir el observador** (ya
existe en D70) y **no toca runtime compartido**. V4 → `/classify` sigue siendo la única autoridad.

> *implementado* = ya corre (D69/D70) · *probado* = con test/lab · *propuesto* = delta que requiere
> aprobación del owner antes de tocar código compartido.

---

## 0. Corrección respecto a la revisión anterior

La revisión previa de este reporte (1) proponía **construir** un observador que **ya existe** (D70), y
(2) afirmaba que `validate_inbound_headers` tiene default **False**. Ambas cosas eran incorrectas:

- **D70 ya implementa el slice observacional `PROFILE_MATCHED`** (`data_plane/framing_evidence.py`,
  457 líneas; wiring en `data_plane.py`/`canonical_observer.py`; `config.yaml`;
  `reports/v5/hybrid/framing-attestation/README.md` + `acceptance-review.md`; evidencia de lab
  `wire-evidence-v2/`). Por tanto este reporte especifica el **delta**, no el observador.
- **`validate_inbound_headers` tiene default `True`.** Lo registra el addon
  `mitmproxy/addons/proxyserver.py:209–217` (`loader.add_option("validate_inbound_headers", bool, True,
  …"Disabling this option makes mitmproxy vulnerable to HTTP smuggling attacks.")`). Mi comprobación
  anterior usó `options.Options()` **sin cargar el addon**, que simplemente **no registra** esa opción
  del addon (verificado: tras `Proxyserver().load(o)` la opción existe con default `True`). **El default
  no sustituye la atestación efectiva:** D70 lee el valor **efectivo** de `ctx.options` en runtime y
  exige `validate_inbound_headers is True` para `PROFILE_MATCHED`; con `False` emite `UNATTESTABLE`
  (`VALIDATE_INBOUND_HEADERS_OFF`).

---

## 1. Qué ya está implementado en D70 / delta necesario / evidencia

| Pieza | Ya implementado en D70 | Delta necesario para `FRAMING_VERIFIED` por petición | Evidencia |
|---|---|---|---|
| Lectura de **perfil efectivo** (versión, `validate_inbound_headers`, `http2`, `stream_large_bodies`, `body_size_limit`, `mode`, `connection_strategy`) | `sample_profile(ctx.options, version)`; campo no legible → `UNAVAILABLE_FIELD` (nunca "tested") | — (suficiente para el eje de perfil) | `framing_evidence.py` `FramingProfile`, `sample_profile` |
| **Perfil probado** como clase (mode = loopback dynamic port, marker cerrado; no el puerto literal) | `is_tested_profile()` + `_canon_mode` (literal loopback, sin DNS) | — | idem |
| **Snapshot coherente** (captura síncrona perfil+snapshot sin await intermedio) | `capture()`/`run_captured()`/`release_captured()` | — | README §Design |
| **Deriva A→B→A** entre captura y respuesta | `RelevantProfileGeneration.observe` (contador monótono) + `GENERATION_DRIFT` | *extender* la ventana: la deriva solo cubre captura→respuesta, **no** recepción→captura | `framing_evidence.evaluate` |
| **Razones cerradas** + vocabulario de log sin bytes | `STATUS`/`REASON`, `format_record` (solo códigos/números) | — | idem |
| **Default-off, V4 intacto** | `GatewayEvidence.canonical=None`, `.framing=UNAVAILABLE`, Fast Path inelegible | — | README §Default-off |
| **bare-LF / obs-fold** | bare-LF **puede** llegar a `PROFILE_MATCHED` (hecho wire que canonicalize no ve); obs-fold R4 → `UNATTESTABLE/CANONICAL_REJECT` | **decidir tolerancias**: ¿bare-LF se acepta o excluye para VERIFIED? Hoy `PROFILE_MATCHED` no atesta el wire | docstring `framing_evidence.py` |
| **Verificación wire real** | **NO existe**: `PROFILE_MATCHED` ≠ wire verificado; sin equivalencia con lo que el upstream parsea | **control pre-parser y vínculo al reenvío por definir**; la comparación de hops aporta diagnóstico (§3) | README (encabezado) |
| **Vínculo al reenvío** (qué recibió el upstream) | **NO**: D70 es un solo punto (snapshot del addon) | **correlación de dos puntas** o instrumentación pre-parser | — |

**Resumen del delta:** D70 resuelve el eje *perfil efectivo + snapshot coherente + deriva captura↔
respuesta + semántica conservadora*. Falta todo el eje *wire*: (a) un punto que vea bytes **antes** de
que el parser pierda información; una comparación de hops puede aportar evidencia
diagnóstica complementaria, pero no sustituye ese control; (b) el **vínculo con el request
reenviado**; (c) la ventana temporal **recepción→captura**; (d) la **decisión de tolerancias**
bare-LF/obs-fold. Nada de esto lo da un snapshot residual.

---

## 2. Límite temporal y alcance de la afirmación técnica

- **Límite temporal (lo reconoce D70 explícitamente):** «un perfil muestreado en el momento del snapshot
  es evidencia del estado de runtime en ese límite, **no** prueba histórica de la configuración del
  parser cuando los bytes fueron parseados; los cambios previos a la captura son inobservables». Los
  bytes se **reciben y parsean antes** de que corra el hook `request`; por eso el perfil-en-captura no
  prueba cómo estaba configurado el parser al recibir esos bytes. La deriva A→B→A cubre captura→respuesta,
  no recepción→captura.
- **Alcance de mi afirmación sobre "no hay bytes wire":** inspeccioné `mitmproxy.http.Request` (expone
  solo `raw_content` —de-chunked, aún codificado— y `stream`) y el hook `request` (post-parse). Eso
  prueba que **en ese objeto y en ese hook no hay octetos wire**; **no** prueba la inexistencia de todo
  punto de extensión posible en mitmproxy (p. ej. capas `next_layer`, una capa HTTP/1 personalizada, o
  hooks de más bajo nivel). Acoto la afirmación al código inspeccionado: *dentro del hook `request` y de
  `http.Request` no hay acceso a los bytes wire previos al parser*; un punto de más bajo nivel podría
  existir, con coste, y queda por verificar (§3).

---

## 3. Recomendación concreta para el siguiente incremento de control

**Recomendación principal (acotada y revisable):** el siguiente incremento NO es reconstruir el
observador, sino añadir un **eje wire** mínimo sobre D70. Dos caminos; recomiendo **evaluar (A) en un
laboratorio aislado primero**. **(B) es un diagnóstico complementario** de divergencia
y correlación; no establece por sí solo enforcement ni `FRAMING_VERIFIED` por petición.

**(A) Verificar un punto de extensión pre-parser en lab aislado (lo que el lab puede probar).**
- *Punto que debe resolver el experimento:* una capa/hook de mitmproxy anterior al parseo HTTP/1
  (candidatos a verificar: `next_layer`, una capa de tee sobre el buffer HTTP/1 en
  `proxy.layers.http._http1`, o un front raw-socket). Hay que **verificar la API instalada**: si existe
  un punto estable que entregue los octetos de la línea de petición/cabeceras **antes** de la
  normalización y correlacionable con el flujo.
- *Qué puede probar un lab aislado:* si ese punto existe y entrega bytes pre-parser correlacionables, y
  con qué coste/estabilidad entre versiones de mitmproxy. **Pendiente de decidir/integrar:** si no es
  API estable, el coste de acoplarse a internals (se rompe entre versiones) frente al beneficio.
- *Alcance:* HTTP/1.1 origin/asterisk (igual que D70). *Tolerancias:* decidir bare-LF (hoy aceptable por
  canonicalize; para VERIFIED hay que **excluirla o atestarla explícitamente**) y obs-fold (ya R4).
- *Límites:* el punto pre-parser deberá tener cotas propias de bytes/buffering,
  tiempo y conexiones antes de ejecutarse; los caps post-parser del adaptador no
  bastan para acotar esa captura anterior. En el futuro lab se fijarán valores de
  ingeniería explícitos, sin presentarlos como límites de producción. Sin hash de
  contenido ni bytes en logs.
- *Fallo/drift:* extender la ventana de generación a **recepción→captura→respuesta**; cualquier hueco →
  `UNATTESTABLE`.

**(B) Comparación diagnóstica de ingreso y upstream instrumentado.**
- *Hop cubierto:* comparar los bytes observados en el ingreso con lo que un
  **upstream instrumentado** recibe y parsea, con correlación explícita de conexión
  y petición. Esto puede revelar divergencias en los vectores del laboratorio.
  La ausencia de divergencia en esos vectores no demuestra ausencia general de
  smuggling. No se ha demostrado que esta sea la única instrumentación posible
  para vincular inspección y reenvío.
- *Coste:* control de ambas puntas, nueva infraestructura de correlación, latencia.
- *Límite:* **una comparación de dos hops, por sí sola, no es enforcement ni `FRAMING_VERIFIED` por
  petición** — es evidencia de divergencia; la semántica de VERIFIED (qué garantiza el parser fijado,
  qué tolerancias) sigue siendo **decisión posterior**.

En ambos casos: el laboratorio aislado puede **probar comportamiento del perfil y existencia/coste del
punto**; **queda pendiente de decidir/integrar** la semántica de `FRAMING_VERIFIED`, las tolerancias y
el vínculo al reenvío.

---

## 4. Separación de ejes (verificación wire · B/Limits · activación Fast Path)

Tres ejes **independientes**; ninguno habilita a otro por sí solo:

1. **Control wire** (§3): se investigará el punto de inspección y el contrato de
   rechazo/tolerancias/correlación. Solo un control implementado y validado contra
   ese contrato podría producir `FRAMING_VERIFIED`; el lab exploratorio no lo produce.
2. **B/Limits** (§11.2): `token_budget` B sigue PENDIENTE → canonical size UNCHECKED → Fast Path
   inelegible aun con framing verificado. **No se inventa B aquí.**
3. **Activación Fast Path:** requiere además **P9** (superset residual) para uso activo y una **política
   positiva de aplicación** (`fast-path-policy/v1`, contexto de aplicación declarado por el owner). **No
   se inventa contexto ni política deployable.**

**`PROFILE_MATCHED` nunca habilita `FAST_ALLOW` por sí solo.** La futura integración
al gateway (`GatewayEvidence.framing()`) partirá de la base D70 ya reconciliada. Esa dependencia de base quedó resuelta en este lote.
El control wire sigue siendo una tarea futura con alcance propio; no se implementa
ni se activa por esta corrección documental.

---

## 5. Casos, drift, correlación, fallos y preservación V4 (requisito → resultado esperado → evidencia)

Sobre lo ya cubierto por D70, el delta añade:

| Requisito (delta) | Resultado esperado | Evidencia de aceptación |
|---|---|---|
| Punto pre-parser entrega bytes correlacionables | o bien existe (lab lo demuestra) o se documenta su ausencia/coste | prueba de lab aislado + razón cerrada |
| Ventana temporal recepción→captura | hueco no observable → `UNATTESTABLE`, nunca `VERIFIED` | test de drift extendido |
| bare-LF | para VERIFIED: excluida o atestada explícitamente (no silenciosamente aceptada) | test positivo/negativo de bare-LF |
| Divergencia de hop (si se adopta B) | divergencia registrada; **no** se traduce a enforcement | test de dos puntas |
| Vínculo al reenvío | atestación atada a lo que el upstream parsea; sin correlación → `no-atestable` | test negativo de correlación |
| Preservación V4 | D1, `/classify`, conteo, forwarding y 403/503 preservados; medir latencia/coste añadido por separado | pruebas funcionales on/off y medición de captura/round-trip; criterio de coste por fijar antes de integrar |
| Logs | vocabulario cerrado, sin target/cuerpo/valores/hashes | revisión de líneas |

Pruebas seleccionadas, **sin datasets protegidos**; excluir la regresión que abre `eval.jsonl`. No R3,
no split/freeze/train real, no FINAL, no SSRF, no Q4_K_M.

---

## 6. Archivos y propiedad

| Archivo (propuesto, futuro) | Rol | Propiedad |
|---|---|---|
| extensión de `data_plane/framing_evidence.py` **(base D70 ya reconciliada)** | eje wire (punto pre-parser o divergencia de hop) | Claude (integrador gateway) |
| `scripts/wire_evidence/` (extender) | vectores raw socket + contrapartes para el delta | Claude |
| `tests/test_framing_attestation*.py` (futuro) | positivos/negativos/drift/correlación del delta | Claude |
| `reports/v5/hybrid/framing-attestation-68/` | este reporte | Claude |

**Base:** reconciliación D70 completada por fast-forward. Este documento queda como
propuesta del siguiente experimento wire, con incertidumbres y criterios explícitos.
No hay implementación wire nueva, modificación de runtime respecto de D70 ni aprobación
de `FRAMING_VERIFIED` en este lote.

---

## 7. Una recomendación principal

Como próxima tarea de framing sobre la base D70, verificar en un **lab aislado**,
con alcance y cotas de ingeniería fijados, si existe un punto de
extensión **pre-parser** estable (camino A) para HTTP/1.1 origin/asterisk, con decisión explícita de
tolerancias bare-LF/obs-fold y extensión de la ventana de deriva a recepción→captura. Dejar la
**divergencia de hop** (camino B) y la semántica de `FRAMING_VERIFIED` como decisión posterior costeada.
No re-proponer construir el observador (existe en D70); no prometer VERIFIED desde el snapshot residual;
no inventar B/Limits ni política deployable; `PROFILE_MATCHED` nunca habilita `FAST_ALLOW` por sí solo.
