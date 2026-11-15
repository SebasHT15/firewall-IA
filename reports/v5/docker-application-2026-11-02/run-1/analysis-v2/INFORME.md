# V5.1: tráfico HTTP real contra aplicación Docker aislada

2 de noviembre de 2026. Experimento DEV propio con pesos reales, HTTP/1.1 y aplicación desechable. Sin entrenamiento, V4, conjuntos protegidos ni acciones de Git.

**Hallazgo principal:** el punto de laboratorio de Model 2 (baseline34, 0,9) bloquea `GET /` en 15/15 peticiones. Scores observados: [0.999926]. La cascada añade 19 falsos bloqueos frente a V5 solo y recupera 0 ataques omitidos en esta población. Ese score no es una probabilidad de ataque calibrada.

**Alcance:** tienda interactiva existente y siete rutas vulnerables propias añadidas en un proceso separado. No se modificó la aplicación original. No es tráfico de usuarios de producción ni una evaluación final independiente. Fast Path deshabilitado: mide los errores sin ocultarlos con excepciones.

## Controles sin firewall

542 peticiones directas. De 168 ataques construidos, 168 mostraron el efecto predefinido sin firewall. Controles ineficaces: [].

SQLi expone una fila sintética privada; traversal y comandos leen un canario sintético; SSTI evalúa una expresión; SSRF alcanza el recurso privado de un contenedor interno; redirect produce un Location externo; XSS ejecuta el documento HTTP recibido en Chromium sin red.

## Clasificación nueva DEV — E5 principal

Los dos casos conocidos `/healthz` y `/static/app.css` quedan fuera de esta tabla. Inválidos cuentan como error en su clase verdadera, aunque operativamente se denieguen.

| Configuración | N | TP | TN | FP | FN | Precisión | Recall | FPR | F1 |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| native-V5_ONLY | 540 | 151 | 343 | 29 | 17 | 83.89% | 89.88% | 7.80% | 86.78% |
| native-CASCADE_ACTIVE | 540 | 151 | 324 | 48 | 17 | 75.88% | 89.88% | 12.90% | 82.29% |
| verified-V5_ONLY | 540 | 151 | 343 | 29 | 17 | 83.89% | 89.88% | 7.80% | 86.78% |
| verified-CASCADE_ACTIVE | 540 | 151 | 324 | 48 | 17 | 75.88% | 89.88% | 12.90% | 82.29% |

## Uso benigno y sesiones

Las 180 peticiones habituales de tienda se agrupan en 15 sesiones con páginas, login, cookies, carrito, checkout y API. El script continúa después de un rechazo. Esta lectura por sesión es descriptiva, posterior a la medición; exige estado HTTP y cuerpo iguales al control directo.

| Configuración | Peticiones habituales entregadas | Sesiones completas |
|---|---:|---:|
| native-V5_ONLY | 180/180 | 15/15 |
| native-CASCADE_ACTIVE | 165/180 | 0/15 |
| verified-V5_ONLY | 180/180 | 15/15 |
| verified-CASCADE_ACTIVE | 165/180 | 0/15 |

Además del inicio de la tienda, los dos runtimes de V5 bloquean las 24 consultas benignas al recurso público de `/fetch`. Los otros falsos bloqueos nuevos son texto benigno con apariencia técnica. `/healthz` y `/static/app.css` se reproducen aparte como regresión conocida.


## Efecto observado y latencia de cliente

La prevención de efecto usa solo ataques con control directo positivo. La latencia proviene de la pasada secuencial de calidad, después de calentamiento: no es capacidad sostenida.

| Configuración | Controles positivos | Efectos con firewall | Prevención | P50 ms | P95 ms | P99 ms |
|---|---:|---:|---:|---:|---:|---:|
| native-V5_ONLY | 168 | 17 | 89.88% | 278.5 | 289.2 | 295.1 |
| native-CASCADE_ACTIVE | 168 | 17 | 89.88% | 287.6 | 294.7 | 303.0 |
| verified-V5_ONLY | 168 | 17 | 89.88% | 52.9 | 151.5 | 154.7 |
| verified-CASCADE_ACTIVE | 168 | 17 | 89.88% | 52.6 | 149.8 | 154.8 |

## Familias — cascada rápida

| Familia | TP | FN | FP | TN | Recall | FPR |
|---|---:|---:|---:|---:|---:|---:|
| benign_edge | 0 | 0 | 9 | 15 | N/A | 37.50% |
| command_injection | 24 | 0 | 0 | 24 | 100.00% | 0.00% |
| open_redirect | 12 | 12 | 0 | 24 | 50.00% | 0.00% |
| path_traversal | 19 | 5 | 0 | 24 | 79.17% | 0.00% |
| routine | 0 | 0 | 15 | 165 | N/A | 8.33% |
| sqli | 24 | 0 | 0 | 24 | 100.00% | 0.00% |
| ssrf | 24 | 0 | 24 | 0 | 100.00% | 100.00% |
| ssti | 24 | 0 | 0 | 24 | 100.00% | 0.00% |
| xss | 24 | 0 | 0 | 24 | 100.00% | 0.00% |

## Interpretación y límites

- Los ejemplos se escribieron y sellaron antes de preguntar a los modelos. Etiquetas por semántica y controles de la aplicación; no por predicciones.
- Se conservan todas las filas, incluidos controles ineficaces y salidas inválidas. No se retocan umbrales, pesos, referencias ni manifiestos.
- Los recuentos por petición y por texto canónico único, intervalos por componentes, salidas inválidas, entrega real y Model 2 selectivo están separados en METRICS.json.
- No se transforma DEFER de Model 2 en un ALLOW ni un error del servicio en detección correcta.
- Las familias y sesiones comparten plantillas. Los intervalos bootstrap son descriptivos; no certifican tasas para tráfico de Internet.
- Los modelos actuales ya estaban elegidos para esta prueba. Este conjunto pasa a ser DEV conocido tras ejecutarlo; no será evaluación independiente de una corrección futura.
- La red Docker es interna, sin ruta por defecto y sin puertos publicados; el gateway del host accede a la IP del puente interno. Aplicación sin datos reales, volúmenes de usuario, Docker socket o permisos privilegiados.
- No se mide aquí TLS/HTTP2, JWT/CSRF, ni Fast Path productivo.

## Evidencia

PROTOCOL.json fija población, orden, fuentes y manifiestos antes de medir. DIRECT.jsonl y sus controles de Chromium prueban el resultado sin firewall. Cada configuración conserva decisiones, estado HTTP, recepción independiente y efecto. Los cuerpos y registros de aplicación están fuera de Git en el directorio privado del experimento. COMPLETION.json verifica las 70 fuentes inmutables y ausencia de cambios durante la medición.

Reproducir el análisis, con un directorio de análisis nuevo: `/usr/bin/python3.12 -m scripts.v5_successor.docker_eval.report --root <directorio de corrida> --analysis-name <nombre de carpeta nueva>`.
