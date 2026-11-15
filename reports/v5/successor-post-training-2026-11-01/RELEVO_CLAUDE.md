# Relevo V5.1 para Claude — 1 de noviembre de 2026

Los pesos nuevos están entrenados y medidos. Puedes pasar de las simulaciones a la cascada real, en el laboratorio HTTP/1.1 reverse y contra el sink inerte. V4 queda fuera. Esto no aprueba despliegue, umbral ni perfil productivo. Solo Sebas hace staging, commit, push, PR o merge.

## Archivos concretos

- Inventario con hashes de toda la entrega: `/home/sebas/Desktop/firewall-IA/reports/v5/successor-post-training-2026-11-01/DELIVERY.json`.
- Adaptador: `/home/sebas/Desktop/firewall-IA/model-output-v5/experimental/v51-policy-20261101T210119Z/adapter`. SHA de pesos: `f101b2f1a8e849220adb0bd7948a4ab681579f0b3fac24629cdc1831c127c20c`.
- Receta: `/home/sebas/Desktop/firewall-IA/reports/v5/successor-training-2026-10-31-reviewed/recipe.EXPERIMENTAL.json`. SHA: `8a831ad2dcd5e4beed917c44230b802ef7091c2cdc48fd7215d4fcf6deb68df1`.
- Tokens, con sección `measured`: `/home/sebas/Desktop/firewall-IA/reports/v5/successor-evaluation-2026-11-01/successor-token-measurement.json`. B415, max512, margen8, overhead76, etiqueta13; vocabulario12 salidas.
- Manifiesto nativo: `/home/sebas/Desktop/firewall-IA/reports/v5/successor-post-training-2026-11-01/cascade-native.EXPERIMENTAL.json`.
- Manifiesto rápido: `/home/sebas/Desktop/firewall-IA/reports/v5/successor-post-training-2026-11-01/cascade-verified.EXPERIMENTAL.json`.
- Perfil rápido nuevo: `/home/sebas/Desktop/firewall-IA/reports/v5/successor-post-training-2026-11-01/profiles/verified-suffix.EXPERIMENTAL.json`. SHA: `7fc17ef8261262857061c2c58aa569540dc9981fc77cbe94efd4a0bd86ad136c`.
- Evidencia del decoder: `/home/sebas/Desktop/firewall-IA/reports/v5/successor-post-training-2026-11-01/decoder-benchmark/verification.json`. Diagnóstico adicional: `/home/sebas/Desktop/firewall-IA/reports/v5/successor-post-training-2026-11-01/runtime-change-diagnosis/diagnosis.json`.
- Informe y comparación: `/home/sebas/Desktop/firewall-IA/reports/v5/successor-post-training-2026-11-01/INFORME.md` y `/home/sebas/Desktop/firewall-IA/reports/v5/successor-post-training-2026-11-01/COMPARISON.json`.

Los manifiestos v2 ya se generaron con tu herramienta y pasaron candidate_check tanto offline como contra sus servicios V5 reales. Eso prueba identidad; el arranque desde TU arnés de candidato y el gateway real con estos pesos sigue siendo tu siguiente comprobación. No reutilices el perfil antiguo e81d70f3 con estos pesos.

## Qué medí

- Dos censos por API reales: 2.514 casos en runtime nativo y 2.514 en el perfil rápido; cero inválidos en ambos.
- Validación URL de selección: 1.040 BLOCK correctos, 1.036 ALLOW correctos, cuatro falsos bloqueos y cero omisiones en ambos runtimes. Son 15 componentes fuente, no 2.080 observaciones independientes ni un test final.
- Authored DEV conocido: nativo TP194/TN215/FP6/FN19; rápido TP193/TN215/FP6/FN20. El V5 anterior rápido tenía TP173/TN221/FP0/FN40. El nuevo gana cobertura y pierde benignos; no promover automáticamente.
- Motivos: el entrenador coincidió en 1.553 salidas completas, pero eso no significa 527 ataques omitidos. Solo 517 de 1.040 motivos BLOCK fueron exactos; confunde muchas redirecciones con SSRF. Etiqueta y motivo están separados en los informes.
- Decoder con misma cuantización noDQ: 100 casos fijos, tres procesos nuevos, 300 pares; cero diferencias de texto/EOS/hash. En los nueve casos donde nativoDQ y rápido noDQ cambiaron, ambas rutas noDQ reprodujeron exactamente la API rápida: diferencia observada atribuible al cambio de cuantización en esas reproducciones. El caso paired-ATK-0067 pasa BLOCK→ALLOW; no ocultarlo.
- Benchmark aislado sobre mismos 100 IDs: nuevo nativoNF4 P95=300,12ms, nuevo rápido207,39ms. Control anterior rápido146,99ms. Las tasas antiguas 16r/s no se heredan. La latencia de censos de calidad tampoco sustituye al ensayo de carga.
- Model2+V5 a 0,9 se reconstruyó como CONTRAFACTUAL, sin Fast Path. En authored baseline34 deja TP194/TN214/FP7/FN19; ablación TP194/TN212/FP9/FN19. Son políticas LAB_EXPERIMENTAL ya existentes, no umbral elegido.

## Siguiente trabajo de Claude

1. Lee la comparación antes de elegir qué configuración medir. Conserva ambos manifiestos como candidatos experimentales. Ejecuta candidate_check, candidate_walkthrough y la comparación V5_ONLY/CASCADE_ACTIVE con los pesos reales; usa tu configv2. Prueba nativo y rápido de uno en uno, sin V4.
2. Ejecuta la escalera de carga propia del candidato antes de fijar soak/recuperación; no heredes tasas del modelo anterior. Agrupa percentiles desde filas crudas y cuenta respuestas completas, rechazos, colas, capacidad útil, recuperación y auditorías reales.
3. Separa clasificación, acción aplicada, estadoHTTP y recepción independiente. Tus 434 authored son regresión conocida; el sink no mide explotación. Los 2.080 casos URL se midieron a través de la API canónica, no como 2.080 peticiones wire por el gateway; no afirmes ese recorrido sin ejecutarlo y verificar el round-trip.
4. Conserva y revisa los falsos bloqueos y regresiones; no cambies referencias ni añadas los mismos fallos al entrenamiento para presentarlos luego como evaluación independiente. Los CSV/JSON tienen las vistas E5 y runtime separadas.
5. Mantén Model2 baseline34 como punto comparativo de laboratorio y la ablación como control, sin aprobar 0,9 ni inventar presupuesto de falsos bloqueos. Fast Path productivo, D70/P9/R3, TLS/HTTP2 y contextoJWT/CSRF siguen abiertos.

La GPU está entregada explícitamente en GPU_STATUS.json como AVAILABLE_FOR_CLAUDE; todos mis servicios y procesos GPU están cerrados. No cargues V4. No se autoriza por este relevo usar lab-app con salida a Internet ni dirigir ataques fuera del laboratorio; conserva el sink existente hasta acordar aislamiento y oráculos de aplicación. No se abrieron reservas ni conjuntos protegidos. No hice operaciones de Git ni otro entrenamiento.
