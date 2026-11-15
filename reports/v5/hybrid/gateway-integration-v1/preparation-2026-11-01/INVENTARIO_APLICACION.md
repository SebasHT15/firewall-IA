# Aplicación de prueba: qué hay y qué falta

Inventario del 1 de noviembre de 2026, solo por lectura. **No se dirigió ninguna petición a la aplicación y no se arrancó ningún contenedor.** Complementa a [REQUISITOS_APLICACION_REAL.md](../load-run-1/REQUISITOS_APLICACION_REAL.md), que sigue vigente.

**Conclusión.** Existe una aplicación aislable, `lab-app`, útil para probar **tráfico benigno y entrega real**. **No sirve para medir el efecto de un ataque**, porque es inerte a propósito. Para ese efecto no hay ninguna aplicación disponible.

## Lo que existe: `lab-app`

| Elemento | Valor | Procedencia |
|---|---|---|
| Código | `docker/lab-app/app.py`, SHA-256 `2970a001…3824af` | Leído en el repositorio |
| Imagen | `firewall-ia/lab-app:lab`, `sha256:7e7f96b9…`, del 21 de septiembre, 48 MB | `docker image inspect` |
| Código dentro de la imagen | Idéntico al del repositorio, mismo SHA-256 | Copiado sin ejecutar, con `docker create` y `docker cp` |
| Servidor | Flask 3.1.0 con su servidor de desarrollo, multihilo, puerto 9100 | `requirements.txt`, `Dockerfile` |
| Definición | Perfil `extv1` de `compose.yaml`, sin publicar puertos | `compose.yaml` |
| Recepción propia | JSONL de solo anexar, escrito antes de atender. Registra ruta con query, `Host`, `User-Agent`, longitud e IP, **no los bytes** | `receipt()` |
| Estado actual | Sin contenedor creado, sin red `firewall-lab` | `docker ps -a`, `docker network ls` |

### Superficie observada en el código

Es una descripción del código, **no un contrato de aplicación**. Nadie la ha aprobado como política y no habilita Fast Path.

| Ruta | Método | Entradas | Efecto |
|---|---|---|---|
| `/` | GET | Ninguna | Página fija |
| `/products` | GET | `category`, `page`, `sort`, `limit` | Refleja los valores, escapados |
| `/products/<pid>` | GET | `pid` | Página o 404 |
| `/search` | GET | `q` | Filtra el catálogo fijo, refleja escapado |
| `/login` | GET, POST | `username`, `password` | Sin comprobar credenciales. Pone la cookie `fwlab_session=u=<usuario>` |
| `/profile` | GET | Cookie | Redirige sin cookie; refleja la sesión escapada |
| `/cart` | GET, POST | `product_id`, `quantity`, cookie | Guarda en cookie `fwlab_cart` |
| `/checkout` | POST | Formulario | Devuelve solo los nombres de los campos |
| `/static/<path:asset>` | GET | Cualquier ruta | Texto fijo con la ruta |
| `/api/products`, `/api/products/<pid>` | GET | Query, `pid` | JSON del catálogo |
| `/api/orders` | POST | JSON | 201 con las claves recibidas, sin guardar nada |
| `/api/me` | GET | Cookie | Devuelve la cookie |
| `/healthz` | GET | Ninguna | `{"status":"ok"}` |

No hay base de datos, ficheros de usuario, plantillas con datos de entrada, llamadas salientes ni subprocesos. El catálogo son 8 productos en memoria.

## Para qué sirve y para qué no

| Uso | ¿Sirve? | Motivo |
|---|---|---|
| Comprobar que el gateway entrega a una aplicación real, con formularios, cookies y JSON | **Sí** | Recepción propia, independiente del gateway |
| Generar tráfico benigno propio y sellado | **Sí, con autorización** | Es lo que hizo External v1 con navegadores y clientes API |
| Medir latencia de una aplicación real | **Con cuidado** | Servidor de desarrollo de Flask: su rendimiento no representa un despliegue |
| Medir si un ataque tuvo efecto | **No** | Inerte a propósito: nada llega a una consulta, un shell, una ruta o una plantilla. Un ataque entregado no puede tener efecto ni dejar rastro distinto de una petición normal |
| Probar diferencias de parser con el destino | **Parcial** | Solo con Werkzeug. No es el servidor de ninguna aplicación real |
| Fast Path productivo | **No** | No hay contrato, responsable ni aprobación |
| JWT y CSRF | **No** | No valida tokens ni tiene protección CSRF, así que no hay estado que proteger |

## Antes de usarla, aunque sea solo con tráfico benigno

| Requisito | Estado |
|---|---|
| Autorización del propietario para esta prueba | **Falta** |
| Red sin salida | **No cumplido.** La red `firewall-lab` es un puente normal, sin `internal: true`. El contenedor tendría salida a Internet |
| Conexión con la cascada | **Sin resolver.** El gateway de la cascada y V5 corren en el host y `lab-app` no publica puertos. `compose.yaml` levanta el gateway V4 antiguo, no la cascada. Una red interna tampoco permite publicar puertos |
| Direcciones `Host` | `compose.yaml` le da los alias `shop.fwlab.test` y `api.fwlab.test`. Hay que decidir con cuál se prueba |
| Conjuntos protegidos | **No reutilizar los casos de External v1.** Son un conjunto congelado y ya ejecutado; repetirlos con el candidato los consumiría como selección |
| Registro de recepción | Guarda rutas con query, cookies no. Debe quedar fuera de Git si lleva tráfico autorizado |
| Tiempos | Falta una decisión sobre si se mide con este servidor o con uno de producción |

Hay dos formas técnicas de conectarla. Ninguna está aprobada ni se ha probado aquí:

1. Publicar `127.0.0.1:<puerto>:9100` en una red propia y bloquear la salida por otro medio.
2. Ejecutar `app.py` en el host. Su `app.run` escucha en `0.0.0.0`, así que haría falta limitarlo a loopback sin cambiar la aplicación medida.

## Lo que falta y nadie puede suplir con código

### Aplicación con efecto medible

No existe. Para pasar de «entregado» a «explotado o no» hace falta, por familia y con autorización escrita:

| Pieza | Qué debe aportar |
|---|---|
| Aplicación deliberadamente vulnerable o copia aislada de una real | Instancia desechable, sin salida, restaurable, sin datos reales |
| Oráculo de efecto | Señal independiente del gateway: fila insertada, archivo leído, callback recibido, sesión cambiada |
| Casos autorizados | Construidos para esa aplicación, con el efecto esperado definido antes de ejecutar |
| Control sin firewall | Comprobar que cada caso **sí tiene efecto** sin gateway. Sin eso, «bloqueado» no demuestra nada |

### Fast Path productivo

| Falta | Detalle |
|---|---|
| Contrato de la aplicación | La lista está en los requisitos: inventario versionado, gramática cerrada por endpoint, ausencia de efectos laterales, `Host` exactos |
| Política `APPROVED` | Con `approved_by`, fecha y referencia. `resolve_fast_path_policy` rechaza cualquier otra en producción |
| Versión del contrato | `fast_path.py` sigue siendo `fast-path/v1-shadow` |
| Resolución D70 | `activation: production` exige `framing.verified_evidence`, y esa evidencia exige `owner_ruling_ref` |
| Presupuesto de auditoría | Los valores de `config.cascade.example.yaml` son de partida, no están dimensionados |

Hoy `fast_path.activation` sigue en `disabled` en el ejemplo. El fixture solo corre en perfil `lab`.

### TLS y HTTP/2

`gateway-framing/v1` los rechaza de forma explícita (`scope_tls_inbound`, `http2: false`) y no atestigua nada sobre ellos. Si la aplicación los necesita hace falta:

- Decidir dónde termina TLS y quién gestiona los certificados.
- Un contrato de framing nuevo y versionado. La vinculación actual es por mensaje HTTP/1.1 y no se traslada a flujos multiplexados.
- Evidencia propia: traducción h2→h1, cabeceras pseudo, flujos cancelados, y qué bytes recibe de verdad el destino.

### Contexto JWT y CSRF

`canonical-request/v1` contiene método, destino y `Content-Type`: no lleva cookies, `Authorization` ni tokens. En el DEV de autores hay **2 grupos de textos canónicos idénticos con etiquetas opuestas y 10 errores inevitables** ([canonical_label_collisions.json](/home/sebas/Documents/Codex/2026-10-26/ta/outputs/V5_sucesor/canonical_label_collisions.json)). Más datos no lo resuelven. Hace falta:

- Decidir qué contexto se autoriza a llevar a un modelo, porque contiene credenciales.
- Una interfaz versionada aparte. `canonical_request.py` es una de las 70 fuentes inmutables y `canonical-request/v1` no se amplía.
- Definir cómo se minimiza y se protege ese contexto en registros.
- Reentrenar sobre esa interfaz, porque cambia la entrada del modelo.

## Orden propuesto

1. Sebas decide si autoriza `lab-app` para tráfico benigno, y con qué aislamiento.
2. Con esa decisión se conecta y se prueba `CASCADE_OBSERVE` o `CASCADE_ACTIVE` con tráfico benigno nuevo, sin casos de ataque.
3. El efecto de ataques espera a una aplicación con oráculo y autorización escrita.
