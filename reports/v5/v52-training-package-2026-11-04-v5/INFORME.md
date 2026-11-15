# V5.2: paquete experimental de corrección, listo para revisión del dueño

4 de noviembre de 2026. **Estado: propuesto; no hay entrenamiento ni candidato V5.2.** Este paquete no autoriza abrir los conjuntos protegidos ni desplegar un modelo. La revisión técnica se ejecutó con CPU y terminó `TECHNICAL_REVIEW_PASS_PENDING_OWNER` en `review-1/run_record.json`.

## Por qué existe

En el experimento Docker nuevo del 2 de noviembre, V5.1 solo obtuvo TP 151, TN 343, FP 29 y FN 17. Los errores se concentran en 24 consultas permitidas a `/fetch`, cinco búsquedas benignas, doce redirects externos y cinco lecturas por traversal. Es DEV conocido, no una medición independiente. Model2 baseline34 añadió falsos bloqueos y rompió las 15 sesiones al denegar `GET /`; no se incorpora a este entrenamiento.

El delta nuevo apunta a esas familias con política explícita de la aplicación desechable: 780 filas TRAIN (420 ALLOW, 360 BLOCK) y 210 VALIDATION (120 ALLOW, 90 BLOCK). Hay pares ALLOW/BLOCK completos para SSRF, redirect y traversal, con componentes de plantilla separados entre splits. Las búsquedas benignas suman 60 TRAIN y 30 VALIDATION y **no están emparejadas**. Los textos exactos no se superponen entre splits, con TRAIN/VALIDATION V5.1 ni con el DEV conocido. También se comprobó ausencia de firmas iguales tras sustituir números por `#` entre los splits nuevos. Esto reduce fugas obvias; no demuestra independencia semántica universal.

La corrección v5 del delta cambió un control benigno de traversal que quedaba bajo `/public/` pero apuntaba a un archivo inexistente. Ahora los seis controles benignos de esa familia resuelven a `readme.txt` o `guide.txt`, presentes en la aplicación; los seis ataques resuelven a `private/canary.txt`. La corrección v6 cruzó el alias público y la IP privada del callback en ambos lados de los pares SSRF. La aplicación devuelve el canario para `/internal/` en cualquiera de los dos nombres; el criterio correcto es la ruta solicitada, no el nombre del host. La validación estática coincide con el código de la aplicación, pero **no se han ejecutado efectos de las 990 filas**.

## Identidad y revisión técnica

| Registro | SHA-256 |
|---|---|
| `PACKAGE.PROPOSED.json` | `d5d92a5a4f0482f64407234d9b6937a6cda88d6e6844153cb283a78731673f61` |
| `recipe.PROPOSED.json` | `57df19b2e66ff6cc60852fbdb8cd0f27e1ff3021b361f8701c4075511d355300` |
| `protocol.PROPOSED.json` | `018039048ce04b6c74430501cc7114c05e4c2c4e1aac92a25fd8f2b18a85234d` |
| Delta `v52-correction-candidate-2026-11-04-v6/MANIFEST.PROPOSED.json` | `a03832b1bb29759260976a078f6b2ecf7b765111ed1819f5cd682578896a60e6` |
| Auditoría `v52-correction-candidate-2026-11-04-v6/CPU_AUDIT.json` | `02bb9b4a34cc783f26a322c3c0854d83928b87dbfdda425bace54baf5bd75208` |
| `SHORTCUT_AUDIT.json` | `63faa790ae46c35d1831723295af2c99c687588f9d209ffd109ac1707d4bc9b4` |

Se revalidaron las 70 fuentes inmutables de Model2, el manifiesto padre de V5.1 y los hashes de sus datos privados. El delta pasó 990/990 análisis canónicos y 990/990 tokenizaciones, sin rechazos ni truncamientos; máxima secuencia nueva: 174 tokens. La composición completa tiene 5.946 TRAIN y 2.290 VALIDATION; las 8.236 secuencias se reconstruyeron sin error, con máximo 406 tokens y presupuesto B=415. La prueba `tests/test_v52_correction.py` pasa 4/4: pares contra política, rechazo de falsos benignos, denegación temprana de entrenamiento con admisión borrador y tratamiento de inválidos como errores en la matriz principal.

Las filas privadas del delta viven fuera del repositorio en `.../firewall-ia-cierre-pc-paper/work/v52-correction-candidate-20261104-v6/`, con hashes y recuentos en el manifiesto público. No se copiaron a `reports/`. No se abrió ninguna reserva ni conjunto protegido. La GPU no se usó para esta revisión.

### Auditoría de atajos

`SHORTCUT_AUDIT.json` usa solo el delta no protegido. Una regla que llama ataque a cualquier URL SSRF con IP privada queda exactamente al azar en TRAIN (TP 60, TN 60, FP 60, FN 60) y VALIDATION (15 de cada celda): el host ya no separa etiquetas. En cambio, un clasificador léxico muy simple de caracteres 3–5 gramas, ajustado solo con delta TRAIN, acierta 210/210 en delta VALIDATION. Las mismas rutas y señales de política hacen esta validación fácil incluso con componentes de plantilla separados. **Esta cifra es una alarma de atajos, no una métrica de calidad del firewall ni una prueba independiente.** El test de aplicación no vista y las cohortes nuevas siguen siendo necesarios.

## Qué se propone entrenar

Una LoRA nueva desde la base fijada TinyLlama, con TRAIN y VALIDATION originales de V5.1 más este delta; no se continúa el adaptador V5.1. Se conservan las restricciones de token, seed, optimización y vocabulario del contrato previo. La receta usa NF4 con doble cuantización para entrenar. La elección de checkpoint es la pérdida mínima de VALIDATION combinada, con resultados del delta informados aparte. Se admite **una** corrida inicial, sin selección automática de candidato, umbral o perfil rápido.

El paquete contiene `owner-admission.DRAFT.json`, con `training_allowed=false` y campos de decisión vacíos. `train_candidate.py --mode gate|train` exige una admisión separada con estado `APPROVED_EXPERIMENTAL`, hashes exactos y todos los registros/códigos vinculados **comprometidos e idénticos a HEAD** antes de leer filas privadas. Sebas conserva la decisión y las operaciones Git. La revisión de CPU no equivale a esa admisión.

`scripts/v52_correction/analyze_training_run.py` queda preparado para la corrida posterior: verificará que el censo greedy tenga una salida por cada una de las 2.290 filas de VALIDATION y que los hashes, orden y expectativas coincidan. Entregará matrices separadas para padre, delta, familia y componente, más motivos e inválidos. No carga pesos; todavía no se ha ejecutado porque no existe un entrenamiento V5.2.

## Archivos necesarios para una admisión posterior

El compromiso que habilitaría el gate debe contener, como mínimo, estos archivos nuevos de Codex, además de una admisión aprobada separada:

- `scripts/v52_correction/build_candidate.py`, `audit_candidate.py`, `prepare_training_package.py`, `train_candidate.py`;
- `scripts/v5_successor/docker_eval/target.py` (fuente de la aplicación desechable que el paquete vincula);
- `reports/v5/v52-correction-candidate-2026-11-04-v6/MANIFEST.PROPOSED.json` y `CPU_AUDIT.json`;
- `reports/v5/v52-training-package-2026-11-04-v5/recipe.PROPOSED.json`, `protocol.PROPOSED.json` y `PACKAGE.PROPOSED.json`.

El manifiesto padre, `successor_contract.py`, `v5_train_data.py`, `finetune_v5.py`, `v5_tokenization.py` y `v5_output_contract.py` ya están en HEAD y deben seguir sin cambios. `tests/test_v52_correction.py`, `scripts/v52_correction/shortcut_audit.py`, `scripts/v52_correction/analyze_training_run.py`, este informe y el diagnóstico de atajos se recomiendan para trazabilidad, aunque no son parte del gate. Los borradores anteriores v1–v5 del delta y v1–v4 del paquete son historia de revisión y **no** son el candidato propuesto actual. Los JSONL privados no deben entrar a Git.

## Evaluación obligatoria después de entrenar

1. Censo completo por clase, motivo e inválidos en VALIDATION padre y delta, separado por componente; reportar tanto clasificación como motivo exacto. Una salida inválida que se deniega por fail-closed no cuenta como acierto del clasificador.
2. Repetir el DEV Docker conocido y el DEV authored anterior con V5.2; comparar contra V5.1 con los mismos textos y el mismo perfil. No usar esas filas para ajustar este paquete después de ver resultados.
3. Aislar NF4 con y sin doble cuantización y, manteniendo la misma cuantización y los mismos pesos cargados, comparar decodificador nativo con sufijo verificado. El caso legacy `dev-00236` mostró una diferencia atribuible a cuantización en esa entrada; no prueba una regla general.
4. Crear una cohorte de selección nueva separada por fuente/componente/plantilla antes de elegir perfil o umbral. Mantener `fwlab-notes` fuera de entrenamiento y selección si se quiere usar como aplicación no vista.
5. Solo con candidato, perfil y política fijados y autorización posterior del dueño, evaluar el test final protegido. En la prueba de gateway real, atribuir los 400 de nginx por traversal de ruta al frente, no al modelo; medir TLS nuevo/reutilizado y HTTP/2 por separado. Repetir recepción, efecto, carga, cola y recuperación con el manifiesto fijado.

## Límites que importan para el paper

Los ejemplos nuevos son sintéticos y específicos de una aplicación vulnerable propia. Aunque el host SSRF aparece en ambas clases, los destinos usan una sola IP privada de laboratorio; los redirects de ataque usan nombres `collector*.example.test`. El diagnóstico léxico muestra señales fáciles de aprender. Los ejemplos de búsqueda de borde no tienen pares adversarios. Los efectos no se han ejecutado para este delta; una etiqueta `POLICY_DEFINED` no es una explotación observada. Una sola seed y una sola aplicación tampoco acreditan generalización. Los resultados de Claude con V5 doble prueban integración y atribución, no calidad V5 real.

La decisión actual es **preparación técnica completa, entrenamiento pendiente de admisión del dueño**. Model2 baseline34 no se promueve; V5_ONLY queda como referencia operativa hasta que un candidato nuevo demuestre mejora real.
