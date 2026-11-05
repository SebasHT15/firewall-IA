# Prueba Docker real de V5.1 y cascada — 2 de noviembre de 2026

La ejecución terminada es `run-1`. Informe principal: [analysis-v2/INFORME.md](analysis-v2/INFORME.md).

- 542 casos por ejecución: 540 nuevos DEV (168 BLOCK, 372 ALLOW) y 2 regresiones benignas conocidas, separadas de la tabla principal.
- 5 ejecuciones: control directo y cuatro configuraciones reales (nativo/rápido × V5_ONLY/CASCADE_ACTIVE), 2.710 peticiones evaluadas, más calentamiento y sondas de infraestructura.
- Los 168 controles de ataque tuvieron el efecto predefinido sin firewall. Con cada configuración quedaron 17 efectos: 12 redirecciones externas y 5 lecturas por traversal.
- V5 solo: TP151/TN343/FP29/FN17; recall89,88%, FPR7,80%, F1 86,78%.
- Cascada baseline34 a0,9: TP151/TN324/FP48/FN17; recall89,88%, FPR12,90%, F1 82,29%.
- Ambos runtimes coinciden en las 542 decisiones de cada modo sobre esta población.
- V5 permite las180 peticiones habituales y completa15/15 sesiones. La cascada bloquea GET / en las15 sesiones y completa0/15, pese a que el script continúa después del403 para medir los demás pasos.
- La página inicial es un texto canónico único repetido en15 sesiones, no15 fallos independientes. METRICS.json contiene también recuentos por467 textos canónicos únicos nuevos e intervalos por componentes.
- V5 bloquea24/24 consultas legítimas al recurso público de fetch. Más ejemplos públicos benignos y variantes de traversal/redirect son frentes de corrección; no se hizo entrenamiento.
- P95 secuencial cliente: nativo V5 289,2ms; nativo cascada294,7ms; rápido V5 151,5ms; rápido cascada149,8ms. No es una medición de capacidad sostenida ni aprobación de D36.
- Fast Path deshabilitado; no se usaron excepciones para ocultar errores.

## Segundo candidato de Model 2: diagnóstico CPU posterior

`model2-posthoc/COMPARISON.json` contiene una reconstrucción de path-ablation32 a0,9, NO una ejecución de su cascada contra Docker: TP151/TN339/FP33/FN17 (FPR8,87%). Su score para GET / es0,5053, frente a0,999926 en baseline34. La reproducción CPU de baseline34 coincide exactamente con sus542 scores observados en el gateway. Ningún candidato ni umbral quedó seleccionado.

## Archivos y gráficas

- `analysis-v2/METRICS.json`: confusión, precision/recall/F1/F2, FPR/FNR, specificity, NPV, balanced accuracy, MCC, intervalos por componentes, sesiones, cortes por familia y Model2 selectivo con AUC/AP/Brier/logloss/ECE.
- `analysis-v2/metrics.csv`: tabla exportable.
- `analysis-v2/confusion-matrices.png` y `.pdf`.
- `analysis-v2/detection-and-false-blocks.png` y `.pdf`.
- `analysis-v2/attack-family-recall.png` y `.pdf`.
- `analysis-v2/latency-ecdf.png` y `.pdf`.
- `analysis-v2/model2-roc-pr.png` y `.pdf`.
- `PROTOCOL.json`, `cases.jsonl`, `DIRECT.jsonl`, las cuatro filas JSONL por configuración y los controles Chromium: evidencia por petición.
- `COMPLETION.json`, `FINAL_VERIFICATION.json`, `BUNDLE_SHA256.json`: integridad y cierre.

`analysis/` conserva el primer análisis; `analysis-v2/` añade lectura por sesión y destaca el defecto de inicio, sin cambiar filas, modelos, referencias ni parámetros. `analysis-v1-source/report.py` conserva el generador original. La ampliación del análisis ocurrió después de cerrar las mediciones.

Los pilotos previos están en carpetas vecinas. `control-pilot-2` no alcanzó el destino porque Docker no publica esos puertos en la red interna de esta máquina; se usó entonces IP de puente interno, sin publicar puertos. `control-pilot-3` detectó un error del recibo del formulario: se medía después de que Flask consumiera el cuerpo. Se corrigió la instrumentación antes de cargar modelos. `control-pilot-4` verificó542 controles y168/168 efectos, sin consultar modelos. Se conservan los intentos; ninguna fila parcial se presenta como evaluación completa.

## Reproducción

Desde `/home/sebas/Desktop/firewall-IA`, usando nombres NUEVOS de corrida y directorios privados:

```bash
.venv-dataplane/bin/python -B scripts/v5_successor/docker_eval/experiment.py --run-id NUEVO-ID --out reports/v5/docker-application-2026-11-02/NUEVA-CORRIDA --work /home/sebas/Documents/Codex/2026-10-26/ta/work/NUEVA-CORRIDA
/usr/bin/python3.12 -B -m scripts.v5_successor.docker_eval.report --root reports/v5/docker-application-2026-11-02/NUEVA-CORRIDA --analysis-name analysis
```

La primera orden carga modelos: solo con GPU libre y coordinación explícita. La segunda recompone métricas y figuras sin cargar pesos. El código se niega a sobrescribir corridas o análisis.

## Alcance

Tráfico HTTP generado por nosotros contra aplicación Docker real, no usuarios de producción. Tienda original más fixtures vulnerables propios y desechables. No acredita generalización a otras aplicaciones ni tasas de Internet. XSS se comprueba ejecutando el documento HTTP real en Chromium sin red; no se mide navegación de víctima ni exfiltración. Redirect mide Location externo, no que un usuario lo siga. Sin TLS/HTTP2, JWT/CSRF, Fast Path productivo ni conjuntos protegidos. No se tocaron pesos, manifiestos, umbrales, referencias o fuentes inmutables. No hubo staging, commit, push ni PR.
