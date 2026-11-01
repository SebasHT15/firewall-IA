# Firewall-IA: métricas experimentales de modelos y cascada

Fecha: 30 de octubre de 2026. Rama `feat/hybrid-cascade-integration`.

**Resultado:** ambos modelos y la cascada funcionan en el laboratorio HTTP/1.1 y ya tienen evidencia experimental reproducible. Esto no acredita despliegue ni evaluación final: persisten la selección/calibración de la política, el objetivo de latencia y los conjuntos reservados. No se entrenó, no se hizo staging/commit/push y no se abrió PR.

## 1. Qué se ejecutó

- 1.034 peticiones de desarrollo: 600 del conjunto anterior y 434 casos del diagnóstico emparejado del proyecto. Veintidós solicitudes del conjunto anterior fallan el parser de protocolo; quedan 578 + 434 = 1.012 entradas comunes para comparar V4, V5 y Model 2.
- V4 recibe el render D1 del gateway real; V5 recibe el texto canónico; Model 2 recibe sus features C1. Se preserva la petición de origen común. No se mandó a V4 el texto de V5 ni se confundieron las arquitecturas.
- Tres procesos nuevos por LLM; cada uno separa una primera inferencia fría, cuatro calentamientos y 96 peticiones de benchmark en el mismo orden. Batch 1 y concurrencia 1. Sincronización CUDA en los núcleos originales. Percentiles por rango más próximo, sin eliminar atípicos.
- Repetibilidad: 58 textos fijos, tres salidas por texto y LLM, comparadas por hash del texto generado. Diagnóstico de desarrollo, no gate STAB.
- Tres pasadas reales por gateway, 600 peticiones cada una: V5_ONLY, cascada baseline34 y cascada path-ablation32. Destino controlado independiente; hashes de bytes recibidos. Cuatro calentamientos del servicio excluidos.
- Carga de API: 48 solicitudes por nivel de concurrencia 1/4/8/16. Carga del gateway completo: 48 por modo y concurrencia 1/4/16, con el mismo tráfico sintético mixto. No son pruebas de capacidad sostenida.
- Guardas de Fast Path, latencia de 64 permisos sintéticos por candidato, fallos controlados, recuperación tras carga y comprobación adicional de las cinco rutas reales.

Los conjuntos reservados INTERNAL_TEST, STAB-HELD y externos no se abrieron. El umbral 0,9 y la política Fast Path siguen siendo experimentales; no se ajustaron pesos, calibradores ni umbrales con estas mediciones.

## 2. Calidad: decisiones de seguridad, no solamente accuracy

Clase positiva = BLOCK. E5 cuenta cada salida inválida como error de su clase real; también se informa la vista de salidas válidas y se separan rechazos del límite de contenido.

| Población | Sistema | TP | TN | FP | FN | Precision BLOCK | Recall BLOCK | FPR benignos | F1 |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Anterior DEV | V4 | 268 | 237 | 63 | 10 | 80.97% | 96.40% | 21.00% | 0.8801 |
| Anterior DEV | V5 | 185 | 297 | 3 | 93 | 98.40% | 66.55% | 1.00% | 0.7940 |
| Anterior DEV | baseline34 (gateway real) | 199 | 289 | 11 | 79 | 94.76% | 71.58% | 3.67% | 0.8156 |
| Anterior DEV | path-ablation32 (gateway real) | 194 | 287 | 13 | 84 | 93.72% | 69.78% | 4.33% | 0.8000 |
| Diagnóstico DEV | V4 | 206 | 153 | 68 | 7 | 75.18% | 96.71% | 30.77% | 0.8460 |
| Diagnóstico DEV | V5 | 172 | 221 | 0 | 41 | 100.00% | 80.75% | 0.00% | 0.8935 |
| Diagnóstico DEV | baseline34 (derivada) | 173 | 220 | 1 | 40 | 99.43% | 81.22% | 0.45% | 0.8941 |
| Diagnóstico DEV | path-ablation32 (derivada) | 175 | 218 | 3 | 38 | 98.31% | 82.16% | 1.36% | 0.8951 |

V5 elimina los 68 falsos bloqueos que V4 produce en los 221 benignos del diagnóstico del proyecto. Sin embargo, detecta 172/213 ataques frente a 206/213 de V4: mejorar benignos no equivale a mantener toda la detección. El denominador y la familia importan. Cero errores observados tampoco prueba un riesgo real igual a cero.

En el conjunto anterior, la vista binaria de las categorías de salida cubiertas por V5 tiene recall 84.54% (82/97); en ataques fuera de ese vocabulario, 56.91% (103/181). Son observaciones DEV, no recall validado de las categorías TRAIN-only. Las razones se puntúan solo en ataques correctamente bloqueados y con una correspondencia definida.

Las peticiones anteriores se transformaron en wire HTTP y se renderizaron por D1, incluyendo Content-Length cuando corresponde. Por eso las cifras de V4 aquí no sustituyen ni contradicen automáticamente su evaluación histórica: cambia la población/representación de prueba. La comparación válida es la emparejada dentro de este experimento.

También se entregan accuracy, balanced accuracy, specificity, NPV, MCC, F1 macro, F2, FNR, matrices, errores de parseo/EOS, rechazos sin generación, motivos exactos, cortes por familia/carrier y pares ataque/benigno. Los intervalos Wilson y McNemar son diagnósticos nominales bajo independencia; las dependencias impiden tratarlos como garantía poblacional.

## 3. Model 2: evaluación selectiva y probabilística

| Candidato / población | Ataques bloqueados temprano | Benignos bloqueados temprano | Precision temprana | DEFER | ROC-AUC | AP | Brier | ECE |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| baseline34 / legacy_dev | 117/278 | 8/300 | 93.60% | 78.37% | 0.8611 | 0.8653 | 0.1820 | 0.1726 |
| baseline34 / authored_paired_dev | 51/213 | 1/221 | 98.08% | 88.02% | 0.9054 | 0.9155 | 0.1299 | 0.0951 |
| path-ablation32 / legacy_dev | 97/278 | 10/300 | 90.65% | 81.49% | 0.6648 | 0.7278 | 0.2648 | 0.3102 |
| path-ablation32 / authored_paired_dev | 74/213 | 3/221 | 96.10% | 82.26% | 0.8777 | 0.8874 | 0.1426 | 0.0900 |

Se entregan log-loss, reliability con 15 bins, curvas ROC/PR, siete umbrales descriptivos y ponderación por grupos de vectores idénticos. DEFER significa derivar al LLM y no se etiqueta como un falso negativo del decider. El corte 0,5 de algunas tablas es una convención binaria de diagnóstico; no crea una ruta ALLOW ni cambia el umbral activo del laboratorio.

- Coincidencias con TRAIN, baseline_34 / legacy_dev: texto canónico 0/578; vector exacto 1/578.
- Coincidencias con TRAIN, baseline_34 / authored_paired_dev: texto canónico 0/434; vector exacto 0/434.
- Coincidencias con TRAIN, target-path-neutralized/v1 / legacy_dev: texto canónico 0/578; vector exacto 128/578.
- Coincidencias con TRAIN, target-path-neutralized/v1 / authored_paired_dev: texto canónico 0/434; vector exacto 27/434.

La vista sin path tiene más colisiones de features. Se entregan resultados sobre la vista disjunta de TRAIN y sobre grupos de vectores; ninguna de estas vistas demuestra independencia de familias o fuentes. La ablación retira solo path_length/path_depth, no toda información indirecta del path. No se declara ganador operativo.

## 4. Cascada: qué evita y qué entrega realmente

| Modo | Llamadas reales a V5 | Llamadas evitadas / 578 | Falsos bloqueos semánticos | Ataques entregados al destino | Desacuerdos L2 | Bytes alterados |
|---|---:|---:|---:|---:|---:|---:|
| V5_ONLY | 578 | 0 (0.00%) | 3 | 89 | 0 | 0 |
| baseline34 | 453 | 125 (21.63%) | 11 | 77 | 0 | 0 |
| path-ablation32 | 471 | 107 (18.51%) | 13 | 82 | 0 | 0 |

L1 compara referencia y decisión; L2 compara acción, estado HTTP y recepción independiente; L3 compara referencia y entrega real. Los inválidos son errores en L1 aunque el bloqueo preventivo reduzca ataques entregados en L3. La entrega a un servidor inerte no demuestra explotación ni compromiso. Bajo concurrencia se compara la recepción agregada por hash, sin inventar correspondencias individuales entre solicitudes repetidas.

En estas 600 solicitudes ninguna cumple la política positiva Fast Path; su cobertura no se inventa. Sus rutas positivas y negativas se miden por separado con entradas sintéticas. El ahorro de llamadas ahora sí procede de ejecuciones reales, mientras que las cascadas del diagnóstico emparejado siguen marcadas como derivadas.

## 5. Latencia, carga y recursos

D36 exige P95 ≤ 200 ms del pipeline de inferencia estable. No es solo generación ni tiempo total por HTTP.

| Modelo | P95 pipeline, ejecución 1 | Ejecución 2 | Ejecución 3 | P95 agrupado | Pico VRAM asignada |
|---|---:|---:|---:|---:|---:|
| V4 | 229.83 ms | 259.98 ms | 246.49 ms | 249.67 ms | 908.8 MiB |
| V5 | 301.35 ms | 296.92 ms | 312.94 ms | 308.91 ms | 858.1 MiB |

**D36 no se cumple en las ejecuciones medidas.** La comparación es de los stacks nativos, con sus respectivas plantillas y cuantización; no es una ablación que aísle el efecto de los pesos. Evitar llamadas reduce trabajo, pero no hace que la inferencia restante cumpla 200 ms.

| API: clientes concurrentes | Respuestas/s | Clasificaciones válidas/s | 503 | P95 cliente (todas) | P95 espera GPU (válidas) |
|---|---:|---:|---:|---:|---:|
| 1 | 3.07 | 3.07 | 0.00% | 344.43 ms | 0.01 ms |
| 4 | 3.10 | 3.10 | 0.00% | 1355.31 ms | 1021.63 ms |
| 8 | 3.10 | 3.10 | 0.00% | 2736.52 ms | 2395.96 ms |
| 16 | 18.79 | 3.13 | 83.33% | 1908.72 ms | 2218.92 ms |

La API y el gateway completo tienen tablas separadas. Se registran latencias de todas las respuestas, válidas y errores; cola, clasificación, throughput y goodput; rutas, saturación y recuperación. Un 403 por indisponibilidad no cuenta como clasificación autorizada en el goodput del gateway. Con 48 solicitudes por nivel, P99 es una observación extrema con mucha incertidumbre; no acredita un SLO ni carga sostenida. El gateway local usa ThreadingTCPServer, no un servidor de producción optimizado.

Se incluyen carga del modelo, primera inferencia fría, calentamientos, tiempos de etapas, tokens, tokens/s de generación, RSS, VRAM asignada/reservada y muestras de temperatura, utilización, potencia y reloj de la GPU. La VRAM total de nvidia-smi incluye procesos ajenos; las muestras de potencia no equivalen a energía causal ni permiten afirmar CO₂ o coste energético por solicitud.

## 6. Verificación de mecanismos

- 72/72 pruebas unitarias afectadas; incluye la regresión de un CRLF de chunk repartido entre recepciones. Se distingue mensaje incompleto de terminador realmente mal formado.
- Verificación real adicional: 18 comprobaciones sobre las cinco rutas del laboratorio, con pesos reales. Registro en real_routes.log.
- V4: 58 textos × 3 salidas; divergencias por hash: 0.
- V5: 58 textos × 3 salidas; divergencias por hash: 0.
- Fallos controlados superados: 4/4. Excepción de Model 2 y respuesta no-OK+BLOCK derivan a V5; V5 no disponible o inválido bloquea. Los fallos inyectados están identificados como tales. Recuperación tras carga: ok.
- El servicio temporal se detiene al acabar. Adaptadores, hashes del código, datasets, entorno, protocolo, selección/orden, registros y cálculos quedan vinculados en los manifiestos.

## 7. Qué falta para una conclusión final del proyecto

1. Fijar un presupuesto de falsos bloqueos y elegir/calibrar la política de Model 2 en VALIDATION adecuada e independiente. La validación original tiene 40 filas y un componente: no permite prometer tasas raras con precisión. No usar INTERNAL_TEST para resolverlo.
2. Resolver o aceptar explícitamente la pérdida de recall por familia y el incumplimiento de D36. Usar los diagnósticos DEV para el trabajo de ingeniería; cualquier versión nueva requiere conservar su propia identidad y protocolo.
3. Congelar modelo/candidato, umbral, política, representación y protocolo; ejecutar una sola evaluación final conjunta autorizada de INTERNAL_TEST, STAB-HELD D77 G1–G5 y evaluación externa correspondiente, sin selección ni depuración sobre esos resultados.
4. Medir la integración de despliegue pendiente: delta mitmproxy D70, HTTP/2/TLS si están en alcance, auditoría asíncrona de FAST_ALLOW, observabilidad y pruebas sostenidas de recuperación/carga. C2 sigue opcional y ausente; no se le atribuyen métricas.

G1/G2 requieren los controles y contrastes registrados, C_hi propio y la interpretación ratificada de D77. G3/G4 requieren la población protegida correspondiente; los cortes por benignos/carrier de este experimento solo son diagnósticos. Las 58 repeticiones DEV tampoco acreditan G5. No se sustituyeron estos gates por muestras más cómodas.

Para planificar una tasa rara: con cero errores y observaciones Bernoulli realmente independientes, el límite superior unilateral exacto al 95% es `1 - 0.05^(1/n)`. Harían falta al menos 2.995 benignos sin errores para bajar de 0,1%, y 29.956 para bajar de 0,01%. Son ejemplos teóricos, no garantías aplicables a estos datos dependientes ni presupuestos operativos inventados.

## 8. Archivos y reproducción

Tablas: quality.csv, slices.csv, stability_dev_by_carrier.csv, model2_probability.csv, model2_thresholds_descriptive.csv, latency.csv y metric_inventory.csv. Datos estructurados completos: summary.json. Los JSONL incluyen decisiones, hashes y tiempos, nunca peticiones privadas. Los inputs derivados de terceros quedan fuera del repositorio, con hash y receta de reconstrucción.

El protocolo congelado vive en protocol.json; supplemental_protocol.json declara el ensayo sintético de carga antes de ejecutarlo. executed_sources conserva los tres programas de medición ejecutados. measurement_source_hashes.json identifica el código real; evidence_manifest.json y code_manifest.json permiten verificar el conjunto final.

Las etapas de análisis se vuelven a ejecutar sin GPU ni modelos: `analyze.py`, `figures.py`, `report.py`. Para repetir mediciones hay que usar un directorio nuevo y reconstruir los inputs con prepare.py; no sobreescribir esta evidencia. No ejecutar entrenamiento para reproducir estas métricas.

## Gráficas

### Calidad y falsos bloqueos

![Calidad y falsos bloqueos](/home/sebas/Documents/Codex/2026-10-26/ta/outputs/Metricas_Firewall_2026-10-30/figures/quality_tradeoffs.png)

### Latencia de los stacks nativos

![Latencia de los stacks nativos](/home/sebas/Documents/Codex/2026-10-26/ta/outputs/Metricas_Firewall_2026-10-30/figures/native_latency_ecdf.png)

### Discriminación y calibración de Model 2

![Discriminación y calibración de Model 2](/home/sebas/Documents/Codex/2026-10-26/ta/outputs/Metricas_Firewall_2026-10-30/figures/model2_probability_diagnostics.png)

### Carga de API

![Carga de API](/home/sebas/Documents/Codex/2026-10-26/ta/outputs/Metricas_Firewall_2026-10-30/figures/api_load.png)

### Carga de la cascada completa

![Carga de la cascada completa](/home/sebas/Documents/Codex/2026-10-26/ta/outputs/Metricas_Firewall_2026-10-30/figures/gateway_load.png)

### Rutas y llamadas reales a V5

![Rutas y llamadas reales a V5](/home/sebas/Documents/Codex/2026-10-26/ta/outputs/Metricas_Firewall_2026-10-30/figures/routes_and_actual_calls.png)

