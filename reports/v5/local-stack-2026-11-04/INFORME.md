# Stack local: frente TLS/HTTP2, gateway y aplicación independiente — 4 de noviembre de 2026

**Tipo: comprobación de mecanismos con DOBLE de V5. No mide detección, latencia ni capacidad.** El doble
bloquea todo texto canónico con `evil` y deja pasar todo lo demás. Sin GPU, sin pesos, sin V4, sin Fast
Path, sin conjuntos protegidos. Nada se seleccionó ni aprobó. Sin acciones de Git.

Operación: [`docs/local_stack.md`](../../../docs/local_stack.md). Código: `scripts/local_stack/`.
Evidencia vigente: `checks-2/`, que añade el comparador CRS y corre con el código final. `checks-1/` se
conserva: es la misma batería sin CRS, anterior a los ajustes de atribución, y también pasó. Los directorios privados (semilla, clave de la CA de laboratorio, bytes crudos, logs y
auditoría de ModSecurity) están en `/home/sebas/Documents/Codex/2026-10-26/ta/work/local-stack-2026-11-04/`.

## Qué se construyó

- `stack.py up/down/status/check-clean/pin`: arranque y parada reproducibles. Por defecto `V5_ONLY`, doble,
  Fast Path apagado, V4 sin arrancar. Fija el SHA-256 del manifiesto y los IDs de imagen. `down` solo para
  lo que el propio stack registró y que todavía coincide (pid + tiempo de arranque del kernel).
- Frente nginx 1.25.5 (`nginx:1.25-alpine`, `sha256:516475cc…`) con TLS 1.2/1.3 y HTTP/2 por ALPN. Lo
  convierte a un mensaje HTTP/1.1 por petición hacia el gateway, por loopback. El gateway no cambia: sigue
  con `gateway-framing/v1` y sigue rechazando TLS y HTTP/2 entrantes.
- `fwlab-notes`: aplicación independiente (Flask más la biblioteca estándar; no importa nada del repositorio).
  Sesiones de servidor, CSRF con token sincronizador más comprobación de Origin/Referer, JWT HS256 con
  `kid`/`iss`/`aud`/`exp`/`nbf`/`sub`/`jti`/`scope` y revocación. Corre en una red Docker `--internal` sin
  ruta de salida. Tiene rutas de efecto opcionales y vulnerables a propósito: SQLi, traversal, redirect y
  XSS, cada una con su oráculo.

## Resultados (`checks-2`)

| Comprobación | Resultado |
|---|---|
| Pruebas unitarias (`unit-tests.txt`) | 24/24 |
| Transporte: 18 casos × plano/h1-TLS/h2-TLS + 2 comparaciones de re-encuadre (`TRANSPORT.json`) | 20/20 veredictos sin problemas |
| Transporte: casos especiales | 17/17 cumplen su propiedad |
| Aplicación: 63 peticiones × directo/h1-TLS/h2-TLS (`APP_CHECK.json`) | 189/189 |
| Fallos (`FAILURES.json`) | 8/8 |
| Comparador CRS: 63 peticiones × 3 vías (`CRS_CHECK.json`) | atribución completa y coherente; misma respuesta de la aplicación que en directo en todo lo que CRS reenvía |
| Limpieza después de cada comprobación | `clean: true` en las cuatro |

- **Transporte.** En los tres caminos coinciden método, destino, `Host`, cabeceras relevantes, cuerpo,
  **texto canónico que llega a V5**, decisión y recepción. Las normalizaciones del frente son las
  declaradas y quedan comprobadas: `Content-Length` en lugar de chunked o de un cuerpo h2 sin longitud
  (el texto canónico no cambia), cookies h2 unidas y cabeceras con `_` descartadas. No se añade ninguna
  cabecera.
- **Diferencias de comportamiento que hay que informar aparte:**
  - El frente responde **400 por sí mismo** cuando la ruta escapa de la raíz (`/../../etc/passwd`,
    `/notes/..%2F..%2Fetc%2Fpasswd`). El gateway en plano sí la reenvía. Ese rechazo no es una decisión
    del modelo. El traversal en la query, como los FN del Docker del 2 de noviembre, pasa sin cambios.
  - Un destino en forma absoluta se convierte en forma de origen; en plano, el gateway responde 501.
  - CL+TE juntos y una discrepancia `Host`/`:authority` reciben 400 del frente.
  - Un flujo h2 cancelado a mitad del cuerpo nunca se clasifica ni se entrega.
  - La reanudación TLS 1.2 y 1.3 se observa en el log del frente (`tls_reused`).
- **Aplicación.** Cada vía tiene 35 rechazos propios de la aplicación, con control/razón cerrados: CSRF ×5,
  JWT ×19, sesión ×3, autorización ×2, login ×2, validación ×3 y ruta ×1. Son iguales con y sin firewall.
  Solo las 3 peticiones con `evil` las rechaza el firewall, y nunca llegan a la aplicación. La sesión
  rota al iniciar sesión y muere al cerrarla. Los cuatro oráculos de efecto disparan en su ataque y no en
  su control benigno. Eso prueba el oráculo, no un detector.
- **Fallos.** Un error, una respuesta inválida o un cuelgue de V5 dan 503 del firewall; el cuelgue tarda
  unos 3 s, el timeout. Con la aplicación parada: FORWARD y luego 502, atribuido a destino inalcanzable.
  Con el gateway muerto: 502 del frente. Al levantar la aplicación de nuevo se recupera, y `down` limpia
  también lo que ya había muerto.

## Comparador ModSecurity + CRS

- Imagen `owasp/modsecurity-crs:4.25.2-nginx-alpine-202610180210-lts`, fijada en
  `sha256:57fd215e…` (38 MB comprimida). Se descargó el 4 de noviembre con la aprobación de Sebas. Lleva
  ModSecurity 3.0.17 y CRS 4.25.2, con la configuración de la imagen sin cambios: paranoia 1 y umbrales
  de anomalía 5 de entrada y 4 de salida. Esos valores se leen del contenedor y quedan en la identidad.
- `stack.py up --firewall crs` usa el mismo frente y la misma aplicación que la cascada. Solo cambia la
  capa de firewall.
- Cambios respecto a la imagen:
  - Escucha solo en loopback, sin TLS propio.
  - Se quitan su `/healthz` y su `/metrics`: tapaban rutas de la aplicación.
  - Se desactiva su HEALTHCHECK. En red de host sondeaba **nuestro** frente TLS y metía peticiones ajenas
    en los logs. Se detectó porque una fila de la vía h2 quedó mal atribuida.
- En estas peticiones de mecanismo, CRS bloquea en h1 y h2 por igual:
  - Los tres ataques de efecto SQLi (regla 942100), traversal (930110) y XSS (941100 y otras). No bloquea
    el redirect abierto.
  - Tres peticiones benignas de la aplicación: `DELETE` de la API (911100, método no permitido en la
    configuración por defecto), un `Content-Type: text/plain` (920420) y un JSON malformado (200002).

  Es observación sobre peticiones escritas aquí, no una tasa de CRS.

## Límites

- Se usó el doble: ninguna cifra de aquí es de calidad, latencia o capacidad. El camino `--v5 real` del
  stack no se ejecutó, porque no hubo cesión de GPU.
- Flask usa servidor de desarrollo. El oráculo XSS es textual, sin navegador.
- La evidencia de framing del gateway cubre frente → gateway → aplicación, no cliente → frente.
- El brazo CRS también añade `X-Real-IP` y `X-Forwarded-*` hacia la aplicación (comportamiento de la imagen).
- Durante una prueba manual, un `*` sin comillas en un comando de curl se expandió a nombres de archivo. curl
  hizo algunos `GET /` a dominios con esos nombres (p. ej. `readme.md`). No se envió ningún dato del proyecto.

## Dependencias para la integración final

1. Codex entrega un manifiesto v2 fijado. `stack.py pin` crea la configuración y `stack.py up --v5 real`
   necesita la cesión de GPU.
2. Con ese candidato se repiten la recepción, el efecto, la carga, la cola y la recuperación. TLS nuevo y
   reutilizado y HTTP/2 se miden aparte.
3. Población final para `fwlab-notes`: definirla y sellarla con el protocolo de Codex antes de abrirla. Sus
   rutas no deben usarse en entrenamiento ni en selección si debe contar como aplicación no vista.
4. CRS para la evaluación final: su configuración (PL1, 5 y 4) debe quedar fijada en el protocolo antes
   de abrir el conjunto final. No se ajusta con resultados.
