# Evaluación del sucesor V5 — 1 de noviembre de 2026

Este paquete prepara y ejecuta comparaciones DEV, no una evaluación final ni una autorización productiva. No incluye V4. El entrenamiento del sucesor no se inicia desde estas herramientas.

## Poblaciones y referencias

`cohorts/protocol.v2.json` fija los hashes y la selección antes de medir V5. `cases.public.jsonl` no contiene peticiones ni valores de payload. Los textos están en el directorio privado referenciado por el protocolo.

- **2.080 casos URL:** validación del paquete de entrenamiento, 1.040 ALLOW y 1.040 BLOCK, 18 fuentes en 15 componentes. Se utiliza para selección de checkpoint durante el entrenamiento; no es un test independiente. Las referencias BLOCK representan las políticas URL del proyecto. Se mantienen juntos los hermanos benigno/ataque al describir pares y grupos.
- **434 casos authored DEV conocidos:** regresión sobre expectativas construidas; no oráculos de explotación. No se atribuye independencia entre filas ni se calculan intervalos IID como garantía de seguridad. Los casos ya fueron examinados durante el desarrollo.
- Ninguna coincidencia exacta con los textos TRAIN en estas dos poblaciones. Esto no demuestra ausencia de toda similitud ni vuelve independientes a los casos DEV.
- Existen 22 casos con referencias opuestas que comparten texto canónico, en dos grupos. Un clasificador determinista que solo recibe ese texto no puede satisfacer todas esas referencias. Los resultados conservan los casos y explican la limitación; no se cambian las etiquetas para favorecer al modelo.
- No se admiten los 600 casos legacy del antiguo paquete en estas cohortes. No se abre ni materializa la reserva ni los conjuntos protegidos históricos.

## Qué está implementado

`scripts/v5_successor/evaluation_metrics.py` calcula matriz TP/TN/FP/FN, precisión, recall, FPR/FNR, especificidad, NPV, F1/F2, macro F1, balanced accuracy y MCC. La vista principal E5 cuenta un inválido como error en su clase real. La vista parseable-only y la acción fail-closed derivada se presentan por separado. Una denegación por fallo no recibe crédito como detección correcta.

Se separan motivos exactos de etiquetas binarias, pares mínimos completos, cohortes, categorías, carriers, familias, componentes y longitudes. Los intervalos descriptivos remuestrean componentes fuente enteros. Se conserva su limitación por pocas fuentes y dependencia cruzada con templates. No se sustituye una agrupación desconocida por independencia fila a fila.

Model 2 tiene métricas selectivas BLOCK/DEFER: bloqueo temprano de ataques, falsos bloqueos tempranos, precisión del bloqueo y derivación. Se añaden ROC AUC con empates, average precision, Brier, log-loss y reliability/ECE descriptivos. La rejilla de umbrales está fijada antes de medir y **no selecciona ninguno**.

Las comparaciones emparejan identificador y hash del texto. Registran mejoras/regresiones e intervalos de diferencias por componente. El McNemar nominal por filas se etiqueta expresamente como descriptivo y no acredita significación en poblaciones dependientes.

## Reproducción y candidatos nuevos

Desde `/home/sebas/Desktop/firewall-IA`. Cada salida debe ser NUEVA; las herramientas rechazan sobrescribir evidencia. Los comandos no hacen staging ni commits.

Revisión CPU del paquete: ya ejecutada en `training-review/run_record.json`, sin cargar pesos ni entrenar. La receta sigue pendiente de admisión del propietario y commit; ver el README del paquete de entrenamiento.

Preparar otra versión de las cohortes, solo si cambia la preparación:

```bash
/usr/bin/python3.12 -B scripts/v5_successor/prepare_evaluation.py \
  --manifest reports/v5/successor-training-2026-10-31-reviewed/dataset-manifest.EXPERIMENTAL.json \
  --out NUEVO_REPORTE_COHORTES --private NUEVO_DIRECTORIO_PRIVADO
```

Medir un Model 2 en CPU con su SHA completo:

```bash
.venv-analyzer/bin/python -B scripts/v5_successor/collect_evaluation.py \
  --protocol reports/v5/successor-evaluation-2026-11-01/cohorts/protocol.v2.json \
  --out NUEVO_REPORTE_MODEL2 model2 --artifact RUTA_ARTEFACTO --artifact-sha256 SHA_COMPLETO
```

Medir un V5 en un servicio temporal propio, con GPU libre. La herramienta comprueba la coordinación, no detiene servicios ajenos, fija identidad, conserva fuentes ejecutadas y cierra su servicio al terminar. El registro y el log privado deben ser nuevos:

```bash
/usr/bin/python3.12 -B scripts/v5_successor/run_evaluation_service.py \
  --protocol reports/v5/successor-evaluation-2026-11-01/cohorts/protocol.v2.json \
  --adapter RUTA_ADAPTADOR_NUEVO --recipe RUTA_RECETA_NUEVA \
  --out NUEVO_REPORTE_V5 --private-log NUEVO_LOG_FUERA_DEL_REPO
```

Sin `--profile`, usa el runtime nativo de su receta. Un perfil experimental requiere `--profile` y `--profile-sha256`; debe estar ligado a las pesas/receta nuevas. No reutilizar el perfil del adaptador anterior. Alternativamente `collect_evaluation.py ... v5-http` usa una API loopback ya existente sin arrancar servicios.

Comparar dos censos V5 sobre la misma población:

```bash
/usr/bin/python3.12 -B scripts/v5_successor/collect_evaluation.py \
  --protocol reports/v5/successor-evaluation-2026-11-01/cohorts/protocol.v2.json \
  --out NUEVA_COMPARACION analyze --predictions PREDICCIONES_CANDIDATO \
  --baseline-predictions PREDICCIONES_REFERENCIA
```

La opción `counterfactual` combina resultados V5 y probabilidades Model 2 a un umbral explícito. No contiene Fast Path, no mide recepción ni ahorro de GPU, y no se presenta como una ejecución real de la cascada.

## Orden de evaluación tras entrenar

1. Identidad y recarga de los pesos guardados; contrato de tokens, vocabulario, plantilla y receta. No confundir pérdida de entrenamiento baja con seguridad medida.
2. Calidad del nuevo V5 en runtime nativo frente a la referencia. Revisar benignos, categorías originales, URLs nuevas, motivos e inválidos por separado. La validación URL sola no demuestra ausencia de regresión en categorías originales.
3. Paridad del perfil rápido con el runtime nativo del NUEVO modelo: comparar salidas y EOS, verificar fallback y rechazos sin inferencia, conservar cualquier diferencia por cuantización. Una equivalencia observada no demuestra equivalencia universal.
4. Comparación selectiva Model 2 y combinación contrafactual. Elegir candidato/umbral exige definir el presupuesto de falsos bloqueos y validar su impacto; este paquete no inventa ese presupuesto ni aprueba 0,9.
5. Claude: rutas reales sobre la cascada con el manifiesto nuevo y recepción independiente. Contrastar salida del modelo, acción aplicada, estado HTTP y recepción; no sustituir unos por otros.
6. Rendimiento controlado y carga: procesos frescos, orden balanceado, frío/warmup/estable separados, semilla, mezcla y tamaños declarados. P50/P95/P99 agrupados desde filas crudas, sin promediar percentiles; repeticiones no son entradas independientes.
7. Aplicación aislada con oráculo por familia antes de afirmar explotación impedida. Estado/cabeceras para JWT/CSRF necesitan otra interfaz: más ejemplos no recuperan información ausente.

## Métricas operativas a integrar con la entrega de Claude

Inferencia, generación, tokenización, transferencia, cola, servicio, salto HTTP, coste del gateway y latencia cliente. Separar VERIFIED/FALLBACK/no-inferencia. Longitud y tokens generados, memoria GPU/RAM, CPU, utilización, potencia/energía si están realmente medidas, y tiempo de carga.

Carga ofrecida, iniciada, respuestas completas, respuestas útiles, 403, 503, 502, timeouts, conexiones fallidas, cuerpos incompletos, carga descartada y crecimiento de cola. Tiempo de recuperación y pérdida durante el fallo. Un 503 rápido no es capacidad útil y un 200 truncado no es una respuesta completa. Las tasas deben declarar su ventana y cola final.

Por ruta: Fast Path, Model 2 BLOCK, DEFER→V5 ALLOW/BLOCK, rechazo de protocolo y error fail-closed. Auditorías solicitadas/completadas/perdidas/fallidas, impacto en tráfico principal y discrepancias de auditoría. Una reducción contrafactual de llamadas no es un ahorro medido de GPU.

Los 200 ms son aspiracionales. No se reescribe el resultado histórico D36 ni se impone un aprobado nuevo por alcanzar esa cifra. Las tasas de la mezcla DEV y el sink no garantizan capacidad productiva.
