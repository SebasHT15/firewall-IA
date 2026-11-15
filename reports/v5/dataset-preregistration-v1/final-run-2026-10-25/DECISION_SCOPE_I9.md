# Decisión para el build V5 completo — 2026-10-25

**Estado:** RATIFICADO por el propietario en este chat el 2026-10-25 (D74: “Sí, ratifico ese alcance”). El piloto r2 pasó sus gates; ningún dataset FINAL está congelado y ningún entrenamiento FINAL ha comenzado.

## Evidencia fija del piloto y de la partición completa

- Pool candidato: 1815 registros, SHA-256 `4d43e0bf190e6b08b9fb0828ae20aa4c17f9eef849b149389a00abc035ae0c39`.
- Piloto r2: 320 filas generadas, `gates_ok=true`; SPL-3 a SPL-9 pasan. 308 filas de TRAIN, 4 de VALIDATION, 4 de INTERNAL_TEST y 4 de la slice de TRAIN.
- Familias independientes después de las 220 fusiones SPL-9: CmdI 25, SQLi 44, SSTI 57, XSS 54. Por D60/D62 (mínimo 100 familias y 30 en INTERNAL_TEST), cada una queda `NOT_EVALUABLE`, con todas sus familias en TRAIN. `path_file_access` sí es evaluable: 403 familias repartidas en 283 TRAIN, 40 VALIDATION y 80 INTERNAL_TEST, más 35 en E6_RESERVE.
- La cuota completa fijada para el piloto fue 20 pares por celda. Su plan, antes de render, contiene 79 celdas: TRAIN 1540 pares en 22 clústeres, VALIDATION 20 pares en un solo clúster `path-media`, INTERNAL_TEST 20 pares en un solo clúster `path-export`. Esta composición hace que el 100% de cada split protegido proceda de un solo clúster. No hay una redistribución que pueda reducir esa proporción sin añadir estructuras nuevas.
- En TRAIN, el clúster mayor aporta 100/1540 pares = 6.49% del plan. El piloto realizado tuvo un máximo de 20/154 filas = 6.49%.
- Prueba de cuotas sin generar datos nuevos: I-9 con WARN 8% / BLOCK 12% y las dos excepciones propuestas termina sin redistribución (`changed=false`), sin clúster TRAIN fuera de límite y registra exactamente las dos excepciones. Esto comprueba factibilidad del **plan**, no el resultado del build completo.

## Propuesta única para avanzar con el lote actual

1. Mantener las cinco categorías de ataque del generador (seis salidas finales contando traversal y file inclusion por separado). Entrenar con el pool admitido. Registrar CmdI, SQLi, SSTI y XSS como **entrenadas pero NOT_EVALUABLE** en esta versión; no publicar métricas por categoría ni afirmar protección demostrada para ellas. La VALIDATION y el INTERNAL_TEST de este lote solo pueden medir `path_file_access`. D60/D62 y sus umbrales se mantienen intactos; no se mueven familias a evaluaciones protegidas.
2. Fijar el control I-9 del build completo en WARN **8%**, BLOCK **12%**, `cap=warn`. Esta es una relajación explícita de los valores propuestos 2%/5% de §11.2, basada en el piloto, y requiere resolución escrita del propietario. El 8% deja margen sobre el máximo observado de TRAIN (6.49%). El límite se sigue midiendo y aplicando antes de congelar; si el build real supera el 8% en un clúster sin excepción y no puede redistribuirse correctamente, el build se detiene.
3. Autorizar **solo** las dos excepciones estructurales I-9 `path-media` en VALIDATION y `path-export` en INTERNAL_TEST: son los únicos clústeres capaces de expresar `path_file_access` en esos splits bajo la partición D60/D62 actual. Su concentración 100% se registra en manifest y freeze report, sin ocultarla ni declararla conforme al 8%.
4. Conservar la cuota completa de 20 pares por celda y el piloto de 2. No ampliar ni sustituir las poblaciones auditadas, no alterar votos, hashes, reglas SPL, denominadores o resultados de admisión. Esta decisión **no** constituye una afirmación de calidad del modelo ni habilita una política de bloqueo.

**Alternativa si se exige evaluación interna por las seis salidas:** no congelar este lote; curar y auditar suficientes familias independientes nuevas para que las cuatro categorías de inyección alcancen el umbral D60, ampliar estructuras compatibles y repetir piloto/build. El déficit mínimo antes de nuevas fusiones es CmdI 75, SQLi 56, SSTI 43 y XSS 46 familias. No hay una corrección de software que cree esa evidencia legítimamente.

## Registro de implementación

Se corrigió `v5_generator.realised_share_report`: un clúster con excepción I-9 se muestra como WARN/BLOCK con su marca `owner_ruled`, pero ya no causa un bucle de rebalanceo. La convergencia registra la excepción y el estado ratificado del umbral. Prueba específica añadida; `python3 -m tests.test_v5_rebalance` pasa 23/23.

La decisión de este documento fija solo el alcance de evaluación y el control I-9. Los demás valores y gates de §11.2 permanecen por prerregistrar y ratificar antes de un build REAL. Las autorizaciones finales de Model 2 y V5 permanecen separadas.
