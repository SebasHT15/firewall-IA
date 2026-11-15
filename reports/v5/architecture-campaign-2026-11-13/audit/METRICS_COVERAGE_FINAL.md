# Cobertura final M01-M35

|ID|Métrica|Estado|Valor y alcance|Fuentes|
|---|---|---|---|---|
|M01|TP, TN, FP, FN **principales** y matriz por brazo|MEDIDA|Candidato TP/TN/FP/FN=66/982/3/2; matrices por app y brazo.|S1-S3|
|M02|Recall/TPR = TP/(TP+FN); FNR = FN/(TP+FN)|MEDIDA|Recall 66/68=97,06%; FNR2/68=2,94%; familias/apps separadas.|S1-S3|
|M03|FPR = FP/(FP+TN); especificidad = TN/(FP+TN)|MEDIDA|FPR3/985=0,3046%; especificidad982/985=99,6954%; tarea/app/sesión.|S1-S3|
|M04|Precisión/PPV = TP/(TP+FP), F1 y prevalencia|MEDIDA|PPV66/69=95,65%; F1=96,35%; prevalencia artificial68/1053=6,46%.|S2|
|M05|Inválidos, errores y timeouts V5 por clase; tasa fail-closed|MEDIDA|0 inválidos/errores V5 o denegaciones de infraestructura en población principal; fallos operativos aparte.|S1-S3,S7|
|M06|Motivo BLOCK exacto y familia correcta|PARCIAL|49 TP de V5: 30/45 motivos gold exactos, 15 desajustes, 4 HTML sin adjudicar; 17 TP de guardia fuera del denominador.|S2-S3,S8|
|M07|Ataques con efecto directo positivo; efecto observado con firewall; prevención de efecto|MEDIDA|65/65 controles efectivos; candidato: 63 prevenidos, 2 persistentes y 0 desconocidos; estado fuera de banda.|S1-S3|
|M08|Recepción indebida, bypass y discrepancia decisión/entrega|MEDIDA|0 DENY recibidos por app; pares de entrega y oráculos contrastados, errores separados.|S2-S3|
|M09|Tareas benignas y sesiones completas; falsos bloqueos por sesión|MEDIDA|169/172 completas, 3 con FP; 21/172 referencia; 35 plantillas.|S1-S3|
|M10|Rechazos propios de aplicación|PARCIAL|Errores/rechazos legítimos se comparan con directo mediante oráculos; JWT/CSRF no se evalúan en estas apps.|S1,S5|
|M11|Cobertura de entradas|PARCIAL|584 sondas/48 clases; rutas fuera de contrato y front NUL aparte. No matriz universal de media/tamaños/normalización.|S1,S3,S5|
|M12|Bloqueos tempranos de Model2: TP, FP y tasa por clase|NO APLICA|Model2 eliminado del perfil activo; resultados históricos preservados. El ahorro de Fast Path se atribuye por separado.|S4-S5|
|M13|DEFER, indisponible y fuera de soporte; cobertura de Model2|NO APLICA|Model2 eliminado del perfil activo; resultados históricos preservados. El ahorro de Fast Path se atribuye por separado.|S4-S5|
|M14|**Rescates:** ataques que V5_ONLY omitía y Model2 bloqueó|NO APLICA|Model2 eliminado del perfil activo; resultados históricos preservados. El ahorro de Fast Path se atribuye por separado.|S4-S5|
|M15|**Daño nuevo:** benignas que V5_ONLY permitía y Model2 bloqueó|NO APLICA|Model2 eliminado del perfil activo; resultados históricos preservados. El ahorro de Fast Path se atribuye por separado.|S4-S5|
|M16|Llamadas V5 evitadas y tiempo V5 ahorrado, más tiempo Model2 añadido|NO APLICA|Model2 eliminado del perfil activo; resultados históricos preservados. El ahorro de Fast Path se atribuye por separado.|S4-S5|
|M17|Diferencia pareada de recall, FPR, prevención de efecto, sesiones completas y rendimiento útil|NO APLICA|Model2 eliminado del perfil activo; resultados históricos preservados. El ahorro de Fast Path se atribuye por separado.|S4-S5|
|M18|Model2 AUC-PR/ROC, Brier/ECE, score por clase y curva riesgo-cobertura|NO APLICA|Model2 eliminado del perfil activo; resultados históricos preservados. El ahorro de Fast Path se atribuye por separado.|S4-S5|
|M19|Latencia extremo a extremo P50/P95/P99 y distribución completa|MEDIDA|P50/P95/P99 y crudos cliente por brazo/ruta; carga: 107 corridas, muestras por punto.|S1-S3,S7|
|M20|Tiempos de TLS, frente, canonización, Model2, espera V5, inferencia V5, egress, aplicación, respuesta|PARCIAL|Etapas gateway/cola V5 y cliente, TLS de carga; no descomposición completa egress/app por event_id. Model2 N/A.|S2-S3,S7|
|M21|HTTP/1.1 plano, HTTP/1.1 TLS nuevo/reutilizado, HTTP/2 TLS nuevo/reutilizado|PARCIAL|H1 TLS nuevo principal; H2 TLS persistente subset; H1 persistente carga. Otros estratos sin nueva medición.|S3,S5,S7|
|M22|Carga ofrecida, completada, útil y rechazada (rps); escalera y punto de saturación|MEDIDA|Escalera 4-64 rps, 3 repeticiones/punto, SLO 1 s. An0 nB0 ard: 16 a 32 rps; directo/CRS alcanzan techo 64. Cliente incluido.|S3,S7|
|M23|Cola: profundidad/espera de admisión, in-flight, worker V5, auditoría; rechazos por límite|PARCIAL|Espera cliente/admisión/V5 y snapshots de colas; sin serie exhaustiva continua de todos los componentes.|S2-S3,S7|
|M24|502, 503, 4xx, timeouts, desconexiones, cuerpos incompletos y reintentos|MEDIDA|Status, incompletos/timeouts y utilidad por ofrecidas/capa en crudos; fallos controlados separados.|S3,S7|
|M25|GPU: utilización, VRAM media/pico, proceso dueño, potencia/energía si medible; CPU/RAM por servicio|PARCIAL|GPU/VRAM/potencia, RSS y CPU contenedores muestreados; sin energía aislada ni CPU%de proceso calculada.|S3,S7|
|M26|Inicio en frío, calentamiento, carga estable, soak, reinicio bajo tráfico, recuperación|PARCIAL|Inicio frío/warmup, escalera20 s, reinicio bajo tráfico y recuperación; sin soak prolongado.|S3,S7|
|M27|Fallos y recuperación|PARCIAL|10 fallos reales y 2 reinicios bajo tráfico; error/invalid/timeout de V5 tienen pruebas de mecanismo con doble previo.|S3,S7|
|M28|Contabilidad de auditoría|MEDIDA|Foreground cierra; auditoría candidata presente, conservada y drenada, con 0 llamadas (tasa 0). Auditoría V5_ONLY no aplica.|S1,S3|
|M29|Identidad y configuración CRS|MEDIDA|CRS4.25.2, digest fijo, PL1, umbrales5/4; reglas/puntaje por fila; sin ajuste TEST.|S1,S3-S5|
|M30|Ahorro y cobertura Fast Path|MEDIDA|789/985=80,10%neto auditoría; 6 apps; por tarea/cliente; guardia separada.|S1-S3|
|M31|Nuevo daño y entrega indebida Fast Path|MEDIDA|Cero daño nuevo por paso o sesión; cero inyecciones por Fast Path, violaciones en 584 sondas o diferencias de respuesta.|S2-S3|
|M32|SSTI por cabeceras y ablación|MEDIDA|15/15 SSTI de cabecera rescatadas por guardia; 2 ctype ya bloqueadas; 2 HTML persisten. Ablación explícita.|S1-S3|
|M33|Intervalos y unidades de independencia|MEDIDA|Benigno: 985 pasos, 934 HTTP, 151 canónicos, 172 sesiones, 35 plantillas. Ataques: 65 sesiones, 14 familias, 3 apps. Wilson condicionado.|S1-S3,S5-S6|
|M34|Identidad/reproducibilidad de fuentes|MEDIDA|451 fuentes, 70 inmutables y 21 runners. Huellas de filas, configuraciones, políticas y casos; freeze intacto.|S3-S6|
|M35|Tráfico orgánico/humano|FUERA DE ALCANCE|Sin tráfico humano/orgánico por alcance elegido; sin afirmación de validez de producción.|S5|
