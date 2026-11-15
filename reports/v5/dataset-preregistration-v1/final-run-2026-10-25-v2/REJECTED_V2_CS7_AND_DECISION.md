# Build v2: C-S7 BLOCK y decisión propuesta

Estado: **v5-dataset-v2 RECHAZADO para freeze y entrenamiento**. Se conserva íntegro; ningún modelo lo ha consumido. No existe una excepción aprobada para C-S7.

El control independiente `scripts/dataset/v5_cs7_check.py` contó usos por elemento de pool, clase y split sobre los metadatos del build, sin publicar los elementos ni el contenido protegido. Evidencia agregada: `cs7-counts.json` (SHA-256 `f670d0babe308bb404fc9aa27eb4a3fc1bafb2647a2d7132f8d5c40970fec195`). El umbral ratificado en D75 y fijado en `final-run-2026-10-25-v2/preregistration.json` es WARN si una cuota supera 1% y BLOCK si supera 3%.

| Celda | Filas | Mayor uso de un elemento | Elementos >3% | Resultado |
|---|---:|---:|---:|---|
| TRAIN / ALLOW | 1540 | 7 (0.45%) | 0 | PASS |
| TRAIN / BLOCK | 1540 | 5 (0.32%) | 0 | PASS |
| VALIDATION / ALLOW | 20 | 4 (20%) | 15 | BLOCK |
| VALIDATION / BLOCK | 20 | 0 | 0 | PASS |
| INTERNAL_TEST / ALLOW | 20 | 2 (10%) | 19 | BLOCK |
| INTERNAL_TEST / BLOCK | 20 | 0 | 0 | PASS |

Con 20 filas por clase, un elemento presente en una sola fila ya representa 5%; por tanto, el límite BLOCK 3% es imposible para una celda tan pequeña con cualquier uso de valores de pool. Los metadatos actuales sí contienen esos usos. El `gates.ok=true` del generador no prueba C-S7; el precheck ahora muestra el fallo.

## Decisión revisable del propietario

**Recomendación para este experimento:** autorizar una enmienda prospectiva de C-S7 para `VALIDATION` e `INTERNAL_TEST`: mantener el cálculo y publicar sus porcentajes, tratarlos como **WARN / limitación de concentración**, sin bloqueo; mantener el BLOCK >3% plenamente vigente para ambas clases de `TRAIN`. No cambia el split, ejemplos, etiquetas, D60, D74, I-9 ni los demás controles §7. No se aplica retroactivamente a v2: preparar **prerregistro v3** que cite esta decisión, reconstruir un **dataset v3** con nuevo ID y repetir todos los controles de freeze sobre v3 antes de entrenar. Ningún resultado de modelo se ha visto al proponerlo, pero el cambio surge de observar el build v2 y debe declararse como tal.

**Alternativa conservadora:** conservar BLOCK >3% en todos los splits y rediseñar/aumentar de manera sustancial el número de filas por clase, pools y cuotas antes de un nuevo piloto y build. Con 20 filas por clase, no hay corrección de código o semilla que haga pasar el control mientras haya valores de pool.

Hasta que exista una decisión expresa, v2 sigue rechazado. Esta propuesta no firma un freeze ni autoriza entrenamiento.
