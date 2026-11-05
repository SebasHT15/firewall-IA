# V5 sucesor: evaluación posterior al entrenamiento

Pesos reales, sin reentrenar ni modificar adaptadores. V4 no participa. No se aprueba despliegue, umbral o perfil productivo.

## Qué significa el resultado del entrenamiento

Las 1.553 coincidencias exactas de 2.080 no son 527 ataques omitidos. El registro del entrenador contiene 1.040 BLOCK correctos, 1.036 ALLOW correctos y cuatro falsos bloqueos. Solo 517 de 1.040 motivos BLOCK son exactos: 496 redirecciones se explican como SSRF y 27 SSRF se explican como SSTI. Detección y motivo se evalúan por separado.

Los hashes de todos los archivos del adaptador coinciden con el registro. Sus 308 tensores tienen los mismos valores que el mejor checkpoint 486; el archivo final usa float32 y el checkpoint bfloat16, por eso sus hashes de archivo difieren. No se sustituyeron las pesas por el último checkpoint 648.

## Censos reales por API

| Modelo | Cohorte | TP | TN | FP | FN | Recall BLOCK | Inválidos |
|---|---|---:|---:|---:|---:|---:|---:|
| previous_fast | authored DEV | 173 | 221 | 0 | 40 | 81.22 % | 1 |
| previous_fast | URL | 512 | 1039 | 1 | 528 | 49.23 % | 33 |
| successor_native | authored DEV | 194 | 215 | 6 | 19 | 91.08 % | 0 |
| successor_native | URL | 1040 | 1036 | 4 | 0 | 100.00 % | 0 |
| successor_fast | authored DEV | 193 | 215 | 6 | 20 | 90.61 % | 0 |
| successor_fast | URL | 1040 | 1036 | 4 | 0 | 100.00 % | 0 |
| counterfactual_baseline34_t09 | authored DEV | 194 | 214 | 7 | 19 | 91.08 % | 0 |
| counterfactual_baseline34_t09 | URL | 1040 | 1036 | 4 | 0 | 100.00 % | 0 |
| counterfactual_path-ablation32_t09 | authored DEV | 194 | 212 | 9 | 19 | 91.08 % | 0 |
| counterfactual_path-ablation32_t09 | URL | 1040 | 1036 | 4 | 0 | 100.00 % | 0 |

previous_fast y successor_fast comparten la familia de ejecución NF4 sin doble cuantización + verified-suffix. La receta y vocabulario nuevos forman parte del candidato; no se atribuye toda diferencia a un solo cambio.

Hay 2.080 casos de validación URL procedentes de 15 componentes fuente, usados para selección de checkpoint. Los 434 authored son regresión DEV conocida. Las referencias son políticas/expectativas construidas, no explotación observada. Cero omisiones en esta muestra no garantiza cero omisiones futuras.

Las filas counterfactual se reconstruyen a umbral de laboratorio 0,9, sin Fast Path: no son rutas observadas ni ahorro de GPU medido. Las matrices principales son E5: inválido cuenta como error en su clase verdadera. La denegación fail-closed derivada está separada en los JSON. JWT/CSRF conservan referencias opuestas con texto canónico idéntico; no se atribuye al modelo información que no recibe.

## Perfil rápido: comprobación separada de pesos nuevos

Comparación del decodificador con generación nativa usando la misma cuantización NF4 sin doble cuantización: 100 casos únicos, 300 pares en tres procesos nuevos; 0 discrepancias de salida/EOS/hash.

- native_nf4: P50 271.88 ms; P95 300.12 ms; P99 316.43 ms (300 observaciones sobre 100 entradas).
- verified_suffix: P50 99.75 ms; P95 207.39 ms; P99 221.90 ms (300 observaciones sobre 100 entradas).

Control del V5 anterior con los MISMOS 100 casos y tres procesos nuevos: P95 rápido 146.99 ms; sucesor rápido 207.39 ms. No se comparan cohortes diferentes para atribuir este cambio.

El perfil rápido del sucesor sigue siendo más lento que el rápido anterior en esta mezcla. En el benchmark SSRF/SSTI necesitan siete tokens de prefijo antes de verificar el sufijo; ALLOW necesita uno. El vocabulario ampliado y las decisiones nuevas cambian ese trabajo. Esto explica un mecanismo de coste, no atribuye causalmente toda la diferencia a un único factor.

## Regresión por categoría de referencia authored

| Referencia | BLOCK correctos anterior | BLOCK correctos sucesor rápido | Total BLOCK |
|---|---:|---:|---:|
| sql_injection | 34 | 34 | 36 |
| command_injection | 32 | 31 | 34 |
| path_file_access | 35 | 34 | 35 |
| xss | 34 | 34 | 34 |
| ssti | 10 | 10 | 10 |
| ssrf | 10 | 34 | 34 |
| open_redirect | 6 | 5 | 8 |
| jwt | 0 | 0 | 6 |
| csrf | 0 | 0 | 4 |
| other_attack | 12 | 11 | 12 |

Cambios entre el runtime nativo de la receta (con doble cuantización) y el perfil rápido completo: **9** casos. Se conservan individualmente en COMPARISON.json. Esta comparación cambia cuantización y decodificador; no se confunde con la prueba del decodificador solo.

Se reprodujeron los 9 casos cambiados con native-noDQ y verified-noDQ sobre el mismo modelo: 0 discrepancias entre ambos y 0 salidas API no reproducidas. Es diagnóstico posterior a observar diferencias, no benchmark independiente.

Los tiempos del censo API son una pasada de calidad, no capacidad ni un ensayo de carga. El benchmark aislado tampoco mide el gateway. Los 200 ms son aspiracionales; D36 histórico no se reescribe.

## Próximo paso

Entregar adaptador, receta, medición de tokens y manifiesto/perfil experimental a Claude para rutas reales y carga de la cascada. La selección final de runtime/candidato exige revisar las regresiones y falsos bloqueos de estas tablas; la existencia de un manifiesto no la aprueba. Hay una omisión authored más en el perfil rápido que en el nativo de receta: no se oculta a cambio de latencia. Model2 continúa BLOCK/DEFER con su política de laboratorio, sin selección de umbral por este informe.

Fast Path productivo necesita contrato de aplicación; el sink demuestra entrega y no explotación. No se abrieron reservas ni conjuntos protegidos y no se hicieron operaciones de Git.
