# V5.1 con Model 2 en deferencia de análisis

5 de noviembre de 2026. V5.1 sigue tomando todas las decisiones de firewall. Model 2 conserva su score para análisis, pero una política explícita `decision_mode: DEFER_ONLY` convierte **todo** resultado suyo en `DEFER`, incluso si el score supera 0,9. Errores de score también difieren, como antes. El umbral 0,9 queda solo como marcador contrafactual; este modo se permite únicamente con `LAB_EXPERIMENTAL`.

El manifiesto `manifest.EXPERIMENTAL.json` fija el adaptador V5.1 y el Model 2 original baseline34, que discriminó mejor que el sucesor de rutas cortas en el DEV anterior. `v51-only.stack.json` sirve de referencia y `v51-model2-observe.stack.json` activa el worker de Model 2 con esta política. El modo técnico del gateway en la segunda configuración es `CASCADE_ACTIVE`, pero su política impide cualquier bloqueo temprano. `manifest.IDENTITY.json` confirma identidad consistente. El chequeo con `--previous` se conserva en `manifest.CHECK.json`: rechaza correctamente la comparación como *nuevo peso V5*, porque aquí se cambió solo la política de Model 2.

## Comprobaciones

- En la demo local con V5 doble, ambos brazos dieron exactamente las mismas 12 respuestas y los mismos resúmenes de gateway. En el brazo de análisis, 11 peticiones llegaron al gateway, las 11 recibieron score de Model 2 con estado `OK`, las 11 fueron decididas por V5 y ninguna por Model 2. La raíz tenía score 0,999926 y aun así llegó a la aplicación. La petición restante la respondió nginx antes del gateway. Ambas corridas limpiaron todos sus procesos y contenedores. `demo-comparison.json` registra los hashes y la comparación. Esta demo verifica mecanismo, no detección del modelo real.
- Sobre los 540 casos Docker DEV conocidos, la reconstrucción CPU difirió 540/540 peticiones a las decisiones V5.1 registradas. Resultado final: TP 151, TN 343, FP 29, FN 17, exactamente V5.1 solo. El antiguo punto activo habría bloqueado temprano 24 ataques y 19 benignas. `known-docker-dev.json` conserva solo agregados e identidades; es una regresión conocida, no una estimación nueva.
- Pruebas: la política y el decider pasaron 12/12 en el entorno de Model 2; router, stack y política pasaron 67/67 en el entorno del gateway. Las 70 fuentes declaradas inmutables permanecen intactas.

## Límite y siguiente medición

La garantía de **cero FP añadidos por Model 2** en este modo es estructural: Model 2 nunca emite `BLOCK`. No implica que V5.1 no tenga FP, ni que el nuevo Model 2 sea mejor, ni ahorro de llamadas a V5. Sí añade trabajo y latencia de score; deben medirse por separado contra V5.1 solo cuando se conecte la aplicación. Para habilitar bloqueo temprano haría falta una política nueva, fijada antes de un conjunto independiente, con presupuesto de FP y evidencia de beneficio incremental. El candidato de Model 2 entrenado el 5 de noviembre queda experimental y no seleccionado porque empeoró AUROC en el DEV de selección.
