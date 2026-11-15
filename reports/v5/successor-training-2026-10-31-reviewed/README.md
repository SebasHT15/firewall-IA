# Paquete V5 sucesor — revisión del 31 de octubre de 2026

Preparación técnica terminada. No se entrenó ningún modelo y no se utilizó la GPU de Claude.

TRAIN tiene 5.166 filas (2.583 ALLOW y 2.583 BLOCK): conserva literalmente el prefijo de 3.080 filas originales y añade 2.086 filas URL. VALIDATION tiene 2.080 filas nuevas, balanceadas. La comprobación CPU tokenizó las 7.246 filas sin rechazar ni truncar ninguna; máximo 406/512 tokens, B415, overhead76 y presupuesto de salida de13 tokens incluido EOS. Fuente TRAIN:86 registros/18 componentes; validación18 registros/15 componentes. Las filas no son observaciones independientes.

La receta propone cuatro épocas, batch efectivo32,648 pasos y evaluación/guardado cada162 pasos. Parte de la base TinyLlama fijada con una LoRA nueva; no continúa entrenando el adaptador V5 existente. Los pesos anteriores y todas las categorías originales se conservan.

## Qué significa la admisión

Esta entrega propone una composición EXPERIMENTAL versionada: hereda únicamente el TRAIN del padre congelado, verifica su auditoría original y añade URLs cuya etiqueta deriva de las políticas D62/D75. La admisión H1 acotada de fuentes nuevas debe aceptarse expresamente; no se inventa un PASS_AI_AUDITED para esas URLs. El lector FINAL anterior permanece intacto y no se presenta este paquete como FINAL.

El propietario debe revisar y adoptar este protocolo experimental antes de entrenar. El registro owner-admission.DRAFT.json permanece deshabilitado. Para aprobarlo después de revisar ambas entregas, crear un archivo separado owner-admission.APPROVED.json con los mismos hashes; cambiar status a APPROVED_EXPERIMENTAL, training_allowed y accept_scoped_policy_sources a true, y completar owner_decision, authorized_by y date con una referencia y datos reales del propietario. No inventar una decisión Dxx. Solo Sebas hace el commit de ese registro y de los archivos revisados.

COMMIT_PATHS.json enumera los archivos propios pendientes, sin hacer staging ni seleccionar cambios de Claude. Los datos crudos permanecen privados, ligados por hash. Antes de ejecutar, el lector exige que autorización, manifiesto, receta, protocolo, evidencia y fuentes estén comprometidos y sin cambios. El commit por sí solo no aprueba un DRAFT.

## Comandos preparados

Desde /home/sebas/Desktop/firewall-IA, usar un directorio de reporte NUEVO en cada comando. La revisión se puede ejecutar con GPU ocupada:

    /usr/bin/python3.12 -B scripts/v5_successor/train_successor.py --mode review --manifest reports/v5/successor-training-2026-10-31-reviewed/dataset-manifest.EXPERIMENTAL.json --report-dir reports/v5/successor-training-2026-10-31-reviewed/review-NUEVA

Después de la aprobación y el commit del propietario, verificar permisos y todos los ejemplos sin cargar pesos:

    /usr/bin/python3.12 -B scripts/v5_successor/train_successor.py --mode gate --manifest reports/v5/successor-training-2026-10-31-reviewed/dataset-manifest.EXPERIMENTAL.json --authorization reports/v5/successor-training-2026-10-31-reviewed/owner-admission.APPROVED.json --report-dir reports/v5/successor-training-2026-10-31-reviewed/gate-NUEVO

Solo cuando Claude libere la GPU, iniciar el experimento:

    /usr/bin/python3.12 -B scripts/v5_successor/train_successor.py --mode train --manifest reports/v5/successor-training-2026-10-31-reviewed/dataset-manifest.EXPERIMENTAL.json --authorization reports/v5/successor-training-2026-10-31-reviewed/owner-admission.APPROVED.json --report-dir reports/v5/successor-training-2026-10-31-reviewed/training-NUEVO --run-id v51-policy-EXPERIMENTO-NUEVO

La salida se guarda en model-output-v5/experimental/ con un nombre exclusivo. El lanzador rechaza un nombre existente, una GPU reservada por Claude o procesos GPU ajenos. No hay modo FINAL ni opción para saltar permisos. Reutiliza el fitting, las máscaras de pérdida, el guardado y la recarga del entrenador existente, con un acceso nuevo explícito para esta composición.

## Qué revisar al terminar

Medir etiquetas y motivos por separado, salidas inválidas y denegación efectiva, por política/carrier/familia/componente. Comprobar no regresión en las categorías originales y benignos DEV; no convertir errores conocidos en evaluación independiente. Conservar los conjuntos protegidos fuera del desarrollo. La validación nueva mide políticas URL del proyecto, no explotación universal de una aplicación.

No se promete resolver JWT/CSRF sin estado/cabeceras ni CMD en JSON, que necesita una compatibilidad versionada. ALT_A tiene salidas NoSQL/XPath/CRLF sin ejemplos en este experimento; no atribuirles cobertura. Las nuevas pesas y vocabulario requieren volver a verificar NF4 y verified-suffix; el perfil rápido actual está ligado al adaptador viejo y no sirve para promover automáticamente el nuevo.

## Evidencia y recuperación

composition-check.json registra la composición; reports/v5/successor-training-2026-10-31-reviewed/cpu-preflight-final/run_record.json contiene los tokens, versiones y calendario reales. expected-refusal-draft/run_record.json conserva el rechazo esperado del DRAFT antes de abrir filas para entrenamiento.

DATA_RETENTION.json contiene el archivo privado de recuperación, hashes e índice de diez rutas de entrada. Se restauraron sus blobs en una carpeta temporal y se verificaron todos los hashes. No contiene reservas, pesos ni los pools de auditoría antiguos: estos últimos conservan sus procedimientos de retención originales. No se redistribuyen filas crudas en esta entrega.
