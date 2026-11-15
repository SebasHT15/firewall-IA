# Model 2 activo con abstención selectiva — candidato de laboratorio

5 de noviembre de 2026. Se conserva **V5.1** y el artefacto original Model 2 baseline34. No se reentrenó ni se cambió un peso: el score y, por tanto, su AUROC y ordenamiento son exactamente los originales. La política `GUARDED_ENFORCE` decide cuándo un score ≥0,9 puede bloquear temprano; en los demás casos Model 2 difiere a V5.1.

## Por qué aparecían FP

El TRAIN original no tenía rutas de menos de siete caracteres. `GET /` queda fuera de soporte y recibe score 0,999926; se repitió 15 veces como bloqueo benigno en el Docker DEV. Cuatro búsquedas benignas con Unicode o símbolos codificados también superaron 0,9. El modelo usa 34 estadísticas de forma y caracteres, sin comprender el significado del parámetro; una cadena benigna codificada puede parecerse a un ataque. El umbral 0,9 era un punto de laboratorio, no un umbral calibrado con presupuesto de FP. El reentrenamiento de rutas cortas corrigió la raíz pero empeoró AUROC en otro DEV, por eso no se eligió.

## Regla de abstención probada

El guard fijo `c1-selective-abstention/v1`, ligado por política al SHA del artefacto original, permite bloquear solo si la ruta y la proporción de símbolos están dentro de los límites observados en TRAIN (longitud ≥7; `symbol_ratio` ≤0,5286624203821656). Difiere métodos fuera de GET/POST/PUT/PATCH/DELETE; difiere cuerpos que no son JSON; y difiere queries que, tras hasta tres decodificaciones, contienen Unicode, `<`, `>`, o escapes sin resolver. Ante cualquier error de extracción, difiere a V5.1. Son filtros de **cobertura para un bloqueo temprano**, no etiquetas ni una mejora del clasificador.

| DEV conocido | Bloqueos tempranos original @0,9 | Bloqueos tempranos con guard | Benignas bloqueadas con guard |
| --- | ---: | ---: | ---: |
| Anterior, 2.514 peticiones | 93 ataques, 1 benigna | 70 ataques | 0 |
| Docker, 540 peticiones | 24 ataques, 19 benignas | 24 ataques | 0 |

En Docker, el contrafactual con las decisiones V5.1 ya registradas queda TP 151, TN 343, FP 29, FN 17, igual que V5.1 solo. Model 2 evitaría 24 llamadas a V5.1 de 540 (4,44 %). En el DEV anterior evita 70 de 2.514 (2,78 %) y difiere 23 ataques que el modelo original habría bloqueado temprano; V5.1 sigue evaluándolos. `known-dev.json` verifica hashes, scores idénticos al artefacto original y estos agregados.

De esos 70 bloqueos tempranos del DEV anterior, V5.1 ya bloqueaba 58 y dejaba pasar 12 (`incremental-v51.json`). Por tanto, el contrafactual **rescataría 12 ataques sin añadir FP en ese DEV**. Este resultado es posterior al diseño del guard y no valida todavía la mejora en una población independiente.

El stack `v51-model2-guarded.stack.json` cargó el manifiesto y la política. En la demo por TLS/HTTP/2 con **V5 doble**, la raíz llegó a la aplicación (200) y una consulta SQLi fue bloqueada por Model 2 (403); el doble de V5 no la bloqueaba. La limpieza terminó sin restos. Esta demo verifica el cableado de una política activa, no la calidad de V5.1 real.

## Pruebas con V5.1 real

Se ejecutaron dos brazos sobre el mismo gateway y el mismo V5.1 real: control `DEFER_ONLY` (toda decisión pasa a V5.1) y `GUARDED_ENFORCE` (Model 2 puede bloquear temprano). En la demo de 12 pasos con TLS, HTTP/1.1 y HTTP/2, ambos brazos dieron los mismos estados y capas finales. La consulta SQLi recibió 403 en ambos: V5.1 decidió en el control y Model 2 en el brazo activo. `real-v51-demo/SUMMARY.json` conserva la atribución de cada paso y confirma limpieza en ambos brazos.

La prueba ampliada envió 434 peticiones `authored_paired_dev` al gateway en cada brazo, con referencias fijadas y V5.1 real. El control entregó 215/221 benignas y bloqueó 193/213 intentos de ataque; tuvo 6 FP y 20 FN según esas referencias. El brazo activo entregó las mismas 215 benignas y bloqueó 194 ataques: **6 FP y 19 FN**. Model 2 decidió 41 bloqueos tempranos, todos etiquetados como ataque, y evitó 41 llamadas a V5.1 (9,45 % de las 434 peticiones). Uno de esos bloqueos rescató un intento que V5.1 dejaba pasar. No hubo FP añadidos ni FN nuevos en este conjunto. `real-v51-paired-dev/PAIRED.json` fija los hashes de entradas, manifiestos, filas y logs; la GPU quedó `AVAILABLE` y Docker sin contenedores en marcha.

Estas son observaciones de un **DEV conocido y construido en laboratorio**. El guard se diseñó después de examinar errores conocidos; por ello, el resultado no estima el FP ni la detección en una aplicación nueva. Las referencias son etiquetas de intentos, no una confirmación de explotación. Tampoco se midieron todavía latencia, capacidad o comportamiento bajo carga con V5.1 real.

## Decisión y prueba siguiente

Este guard se diseñó después de observar errores en ambos DEV: **cero FP añadidos allí no es una garantía en una aplicación nueva**. Sigue en estado `LAB_EXPERIMENTAL` y no está seleccionado para la medición final. El modo `DEFER_ONLY` permanece disponible como control. Antes de activar el guard en la aplicación del usuario, fijar la política y medirla en tráfico independiente junto a V5.1 solo, con etiquetas y oráculos de efecto, FP por sesión/texto único, ataques adicionales detectados, llamadas V5 evitadas y latencia/capacidad. Un resultado de calidad igual y latencia peor justificaría V5.1 solo.
