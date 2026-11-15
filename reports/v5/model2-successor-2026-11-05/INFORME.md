# Model 2 experimental de rutas cortas

**Nota de publicación 2026-11-14:** los pesos `artifact/model2.json` y las cohortes con texto
HTTP permanecen locales y excluidos de Git. `PRIVATE_ARTIFACTS.json` conserva sus rutas, tamaños
y SHA-256. La receta, composición y reporte siguen siendo públicos; reproducir este experimento
histórico requiere los artefactos locales. No se modificó su contenido.

5 de noviembre de 2026. Este artefacto es un candidato de ingeniería, no una selección para el paper ni una política de despliegue.

## Procedencia y entrenamiento

`scripts/model2/successor.py` leyó exclusivamente TRAIN (3080) y VALIDATION (40) del conjunto original mediante `load_final_examples`, que verificó el prerregistro, congelamiento, autorización, integridad y separación antes de entregar filas. Añadió un cohorte **POLICY_DEFINED** de peticiones HTTP benignas con rutas cortas: 84 TRAIN y 42 VALIDATION, con rutas distintas entre divisiones. `GET /` quedó en TRAIN. No se usaron rutas de `fwlab-notes`, casos Docker, etiquetas producidas por V5 ni conjuntos protegidos para ajustar el modelo.

El artefacto experimental está conservado en `artifact/model2.json`, SHA-256 `ed00693cc702d21dcd86b22dc3958021c03e7f09e92958f48e132802aa4963bc`. Conserva la vista de 34 variables y la regresión logística original, con pesos nuevos y sin umbral dentro del modelo. La composición, cohortes, receta y reporte de validación están junto al artefacto. La política separada `policy.LAB_EXPERIMENTAL.json` mantiene 0,9 como punto de laboratorio heredado; no ha sido calibrada ni aprobada. La fidelidad del score portátil respecto al ajuste nativo fue comprobada en las 82 filas VALIDATION al entrenar. Las 16 pruebas del sucesor y entrenador pasaron.

El nuevo cohorte se limita a 18 rutas y siete métodos sin cuerpo. Que corrija `GET /` no demuestra cobertura de rutas cortas con cuerpos, cabeceras, sesiones ni aplicaciones ajenas. En las 40 filas de VALIDATION original, el punto 0,9 deja 18 de 20 BLOCK para V5; las 42 benignas nuevas quedan por debajo. Es una comprobación de desarrollo, no una tasa final.

## Regresión conocida Docker

El archivo `known-docker-dev.json` coteja los 540 casos ya conocidos con las decisiones V5.1 registradas. El score nuevo se calculó en CPU; **no** se ejecutó el gateway con este artefacto. Los casos incluyen repeticiones de textos y plantillas. Por ello las cifras son una regresión de desarrollo, no una estimación independiente.

| Escenario | TP | TN | FP | FN | Bloqueos tempranos TP | Bloqueos tempranos FP |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| V5.1 solo, observado | 151 | 343 | 29 | 17 | 0 | 0 |
| Model 2 original + V5.1, observado/reconstruido | 151 | 324 | 48 | 17 | 24 | 19 |
| Model 2 nuevo + V5.1, contrafactual CPU | 151 | 341 | 31 | 17 | 12 | 2 |

`GET /` pasa de 0,999926 a 0,547082 de score de bloqueo, por debajo de 0,9. En los casos conocidos elimina los 15 falsos bloqueos repetidos de la raíz. Los dos bloqueos tempranos incorrectos restantes corresponden a dos búsquedas benignas de borde, con dos textos distintos. Los 12 ataques que bloquea temprano ya los bloqueaba V5.1; no recupera ninguno de sus 17 FN.

Los 12 redirects externos que V5.1 dejó pasar obtienen scores entre 0,510 y 0,578; los cinco traversal omitidos, entre 0,352 y 0,372. Este modelo de 34 variables estadísticas no los detecta en el punto 0,9. Bajar el umbral usando ese mismo DEV sería una selección sesgada y podría aumentar bloqueos benignos; queda fuera de esta corrida.

También se puntuó el DEV anterior de 2.514 casos, conservando su protocolo y sin volver a entrenar. En sus 434 regresiones conocidas, AUROC baja de 0,905 (Model 2 original) a 0,891 (nuevo), y Brier sube de 0,130 a 0,137. En las 2.080 filas de selección de desarrollo, AUROC baja de 0,902 a 0,853 y Brier sube de 0,202 a 0,240. `known-v51-dev/` contiene los scores y resúmenes. Es una regresión de discriminación que impide presentar el nuevo Model 2 como una mejora general, aunque arregle la raíz.

La compatibilidad de carga también se comprobó con el manifiesto `compat-v51.EXPERIMENTAL.json`: la identidad pasó el chequeo offline y el stack `CASCADE_ACTIVE` arrancó el nuevo worker con el doble de V5. En la demo TLS/h2, la raíz llegó a la aplicación (HTTP 200); terminaron los procesos y contenedores sin restos. Esta demo comprueba conexión y limpieza, no calidad de detección del V5 real.

**Decisión:** mantener V5_ONLY como brazo de referencia y la cascada nueva como brazo experimental. Model 2 mejora claramente el fallo de raíz frente al anterior, pero todavía no demuestra beneficio neto frente a V5 solo. Medir con V5.2 real y una población de aplicación distinta antes de seleccionar cualquier política. El umbral 0,9 no se debe presentar como óptimo.

Reproducción desde la raíz del repositorio, con salidas nuevas: `.venv-analyzer/bin/python -B -m scripts.model2.successor --output-dir <salida-nueva>` y `.venv-analyzer/bin/python -B -m scripts.model2.evaluate_successor --new-artifact <salida-nueva>/model2.json --out <informe-nuevo.json>`. Ningún comando abre conjuntos protegidos ni cambia archivos originales.
