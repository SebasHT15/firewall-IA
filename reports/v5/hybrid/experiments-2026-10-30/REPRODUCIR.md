# Reproducir sin modificar Git ni sobreescribir evidencia

Desde `/home/sebas/Desktop/firewall-IA`, con GPU libre y los mismos pesos/datos locales:

```bash
/usr/bin/python3.12 -B scripts/cascade_lab/experiments/run.py \
  --out reports/v5/hybrid/experiments-REPLICA-NUEVA \
  --private /home/sebas/Documents/Codex/2026-10-26/ta/work/metrics-REPLICA-NUEVA \
  --deliver /home/sebas/Documents/Codex/2026-10-26/ta/outputs/Metricas_REPLICA-NUEVA
```

Los tres directorios deben ser nuevos. El lanzador rechaza directorios existentes, mantiene peticiones privadas fuera de Git, ejecuta las pruebas afectadas antes de medir y apaga exclusivamente el servicio temporal que inicia. No entrena ni abre conjuntos reservados. El diagnóstico de desarrollo anterior y la muestra de 434 casos se reconstruyen desde las fuentes locales; el manifiesto vincula su hash antes de inferir.

El paquete no redistribuye pesos, eval.jsonl, inputs privados ni el log original de posibles salidas inválidas. Contiene resultados por petición sin payloads, código, protocolo, hashes, pruebas y figuras. Los checkpoints y dependencias fijadas deben existir en el repositorio local para repetir inferencias.

Para recalcular solamente el informe de la ejecución original, sin GPU ni nuevas inferencias:

```bash
/usr/bin/python3.12 -B scripts/cascade_lab/experiments/analyze.py
/usr/bin/python3.12 -B scripts/cascade_lab/experiments/figures.py
/usr/bin/python3.12 -B scripts/cascade_lab/experiments/verify.py
/usr/bin/python3.12 -B scripts/cascade_lab/experiments/report.py
```

El protocolo y las observaciones originales permanecen identificados por sus hashes. Las salidas derivadas pueden volver a calcularse. Solo Sebas realiza staging, commit, push, PR o merge.
