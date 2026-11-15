# Qué necesitamos para probar contra una aplicación real

Hoy el destino es un sink inerte. **Solo demuestra entrega:** recibe bytes y responde 200, sin lógica, sin estado y sin poder explotarse. Nada de lo medido dice qué ocurre en una aplicación real. Este documento lista lo que debe aportar el propietario. No se ha inventado ningún contrato de aplicación y ninguna política productiva está habilitada.

## Decisiones previas del propietario

Ninguna está aprobada. Un relevo de GPU o un resultado de esta prueba no las aprueba.

| # | Decisión | Por qué bloquea |
|---|---|---|
| 1 | Autorización escrita: qué aplicación, qué entorno, quién responde | Sin ella no se dirige tráfico de ataque a nada que no sea el sink |
| 2 | Topología: confirmar reverse proxy delante de esa aplicación | El alcance actual es solo ese |
| 3 | ¿TLS o HTTP/2 hacia el cliente? | Hoy se rechazan. Si la aplicación los necesita, hace falta otro contrato de framing y evidencia propia |
| 4 | Resolución de D70: ¿se acepta `gateway-framing/v1` como control? | `FRAMING_VERIFIED` exige esa resolución fuera del laboratorio. La garantía es de egreso: no acredita los bytes del cliente |
| 5 | P9 o R3, y fijar br/zstd con hashes | Afecta a la canonicalización en uso activo |
| 6 | Presupuesto de falsos bloqueos y umbral de Model 2 | 0,9 es experimental. Elegirlo necesita validación independiente sobre tráfico de esa aplicación |
| 7 | ¿Qué perfil de V5 sirve? | `verified-suffix` y NF4 son experimentales |
| 8 | Retención y privacidad de registros | Con tráfico real hay datos personales posibles, y el camino V4 registra paths |

## Contrato de la aplicación (necesario para Fast Path)

Fast Path necesita una lista positiva y cerrada. Sin esto sigue deshabilitado.

- **Inventario** versionado de endpoints, por ejemplo OpenAPI, con responsable y fecha.
- **Por endpoint elegible:** métodos, forma exacta de ruta, parámetros con tipo y gramática cerrada, cabeceras esperadas y sus valores.
- **Confirmación** de que esos endpoints no tienen efectos laterales, no dependen de sesión y no reflejan entrada.
- **`Host`** y dominios exactos que atiende.
- **Quién aprueba** cada política y cómo se revoca. La política necesita `approved_by`, fecha y referencia de decisión.
- **Cómo se notifica** un cambio de la aplicación, porque una política desactualizada permitiría de más.

`fast_path.py` sigue siendo `fast-path/v1-shadow`. Un uso productivo requiere también una versión nueva de ese contrato.

## Entorno de prueba

- Instancia **aislada y desechable**, sin datos reales y sin salida a Internet, restaurable a un estado conocido.
- Datos sintéticos propios y cuentas de prueba creadas para esto.
- Acceso a los **logs de la aplicación**: son la recepción independiente, y ya no bastaría con hashes en un sink.
- Conocer su **framing:** servidor, versión y proxies intermedios. La garantía supone un destino conforme y hay que probar diferencias reales de parser con él.
- Comportamiento ante reconexiones: el guard abre una conexión por cada conexión de mitmproxy.

## Cómo saber si un ataque tuvo efecto

Es lo que el sink no puede decir. Para pasar de «entregado» a «explotado o no» necesitamos, por cada familia:

- Un **oráculo de efecto** observable: fila insertada, archivo leído, callback recibido, sesión cambiada.
- **Casos autorizados** construidos para esa aplicación, con su efecto esperado.
- **Estado** para JWT y CSRF: `canonical-request/v1` no los distingue con una sola petición, y hay pares opuestos con texto canónico idéntico. Resolverlo exige una interfaz versionada con contexto autorizado, no ampliar el contrato actual.

## Tráfico

- Tráfico benigno **de esa aplicación**, capturado o generado con su permiso, y sellado antes de usarlo.
- Mezcla esperada: rutas, tamaños, proporción de lecturas y escrituras, y pico por segundo.
- Objetivos reales de latencia y disponibilidad. Hoy no existe ningún SLO: los criterios de saturación de este informe son descriptivos.
- Una población propia para validar el umbral, separada de cualquier conjunto protegido.

## Operación

- Dónde corren V4, V5 y el gateway, y si V4 se mantiene cargado para el retorno.
- Quién decide un retorno a V4 y con qué señal.
- Cómo se comporta la aplicación si recibe 403, 413, 501 o 503 del gateway.
- Plan de despliegue en sombra: empezar en `CASCADE_OBSERVE` antes de dar autoridad a la cascada.

## Orden propuesto

1. Decisiones 1 a 3 y entorno aislado.
2. Contrato de la aplicación y oráculos de efecto.
3. `CASCADE_OBSERVE` con tráfico benigno, midiendo el coste sobre V4.
4. Casos autorizados de ataque, con oráculo.
5. Decisiones 4 a 7, con esa evidencia.
6. Solo entonces, `CASCADE_ACTIVE` en ese entorno.
