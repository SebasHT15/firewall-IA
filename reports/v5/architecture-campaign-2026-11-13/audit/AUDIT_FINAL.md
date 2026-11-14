# Auditoría final independiente - Firewall-IA

Fecha: 13 de noviembre de 2026, Costa Rica. Autor: Codex. Campaña: `fastv5-public-v3-headerguard-v2-20261111`.

## Dictamen publicado para cerrar la coordinación

**PASS C1-C5. La evidencia respalda proponer la promoción experimental del candidato congelado dentro del alcance de estas seis apps y estos contratos.** No es una aprobación de producción. No se cambia el manifiesto EXPERIMENTAL, el candidato, los pesos, los casos, los criterios ni las fuentes congeladas. La decisión de adopción corresponde a Sebas.

Claude puede cerrar su campaña y publicar DONE conservando los crudos, con la errata de regresiones indicada abajo. No necesita repetir GPU, Docker ni las mediciones. Codex continúa únicamente la edición del informe final PDF/LaTeX; su estado seguirá AUDITING hasta entregar esos artefactos. Este dictamen ya está completo y no depende del maquetado del PDF.

## Evidencia y método

Se ejecutaron los dos analizadores independientes preparados antes del test: `audit_evidence.py` y `analyze_results_codex.py`, sin importar el scorer de Claude. Se añadió una lectura posterior `audit_extended.py`, identificada como auditoría de resultados y sin cambiar el algoritmo experimental. Los scripts, resultados JSON y CSV se conservan con el paquete final.

- 451 archivos congelados: verificación sin drift. Freeze SHA256 `ae1cf86fc7c3710f35014501fadbea0a0b03ad9e097fb2fd2bbc9d969b69e51d`.
- 70 fuentes inmutables del contrato de Model2 conservadas; 21 runners del manifiesto coinciden.
- 39 corridas principales/transporte: 30 H1 y 9 H2; 11.318 filas en total, incluidas poblaciones de apoyo y regresiones, sin reinterpretarlas como casos independientes.
- 107 corridas de carga: 105 puntos/repeticiones de escalera y 2 reinicios bajo tráfico; 10 escenarios de fallo con controles y limpieza.
- **1.640 comprobaciones automáticas de evidencia, cero discrepancias pendientes.** Son comprobaciones de registros/identidad/conteos; no se presentan como 1.640 pruebas unitarias nuevas.
- SHA de filas/configs/casos/runners; identidad pareada de pasos y etiquetas en todas las poblaciones; sello de controles directos; cierre de contadores foreground/auditoría; limpieza y ALPN contrastados.

El helper inicial produjo 9 alertas `audit_accounting_missing`, exclusivamente V5_ONLY (6 H1 y 3 H2). Se conservan y adjudican: cada config tiene `fast_path=null`, activación `disabled`, contabilidad terminal de auditoría explícitamente null y contabilidad foreground cerrada. Es la ausencia diseñada del subsistema, prevista en `AUDIT_TOOL_CAVEATS_PRETEST.md`; no se supone que un contador ausente del candidato valga cero. Los candidatos tienen contadores presentes, conservados y drenados.

## Criterios prefijados

| Criterio | Recuento independiente | Dictamen |
|---|---|---|
| C1: sin Model2 | Cero procesos/invocaciones/registros; `model2_worker=null` explícito en candidato y ablación | PASS |
| C2: utilidad Fast Path | 789/985 llamadas benignas de referencia evitadas por Fast Path = 80,1015%; auditoría real 0, guardia benigna 0; cobertura en las 6 apps | PASS |
| C3: coste por tarea | Gateway benigno 69.599,9 -> 14.870,0 ms; suma V5 68.246,2 -> 13.208,8 ms; mediana V5/sesión 394,62 -> 59,30 ms, método del scorer prefijado | PASS |
| C4: seguridad Fast Path | 0 pasos de inyección por Fast Path; 0 violaciones en 584 sondas; 0 diferencias status/cuerpo entre respuestas Fast Path y directo, incluidas poblaciones de apoyo | PASS |
| C5: daño benigno nuevo | 0 nuevos pasos fallidos, 0 nuevas sesiones dañadas frente a V5_ONLY, 0 benignas bloqueadas por guardia; 208 pasos recuperados | PASS |

## Resultados comprobados del test principal

985 peticiones benignas, 172 sesiones benignas, 35 plantillas; 65 sesiones de ataque con efecto directo positivo en 14 familias de 3 apps, que contienen 68 pasos de inyección. Las 584 sondas de contrato y 43 pasos DEVREG se informan por separado. Las etiquetas y los intervalos por petición no crean independencia entre pasos.

| Brazo | TP/TN/FP/FN | Sesiones benignas completas | Inyecciones impedidas / efectos positivos directos | Efectos persistentes |
|---|---|---|---|---|
| V5_ONLY | 51/774/211/17 | 21/172 | 48/65 | 17/65 |
| Fast Path + V5.1 | 51/982/3/17 | 169/172 | 48/65 | 17/65 |
| Fast Path + V5.1 + guardia | 66/982/3/2 | 169/172 | 63/65 | 2/65 |
| CRS PL1 | 53/985/0/15 | 172/172 | 50/65 | 15/65 |

Candidato: FPR 3/985 = 0,3046%; recall por paso 66/68 = 97,0588%; prevención por sesión 63/65 = 96,9231%. Son denominadores diferentes. Precisión 66/69 = 95,6522% y F1 132/137 = 96,3504% dependen de la mezcla artificial (68/1053 pasos etiquetados de ataque). No se trasladan a prevalencias reales.

Los 15 rescates de SSTI de cabecera respecto de Fast Path sin guardia se atribuyen al control determinista específico de Inf3ct. Dos casos `ssti_ctype_param` también son interceptados por guardia, aunque V5 ya los bloqueaba; no son rescates adicionales. Se conservan 2 efectos `stored_html_header`, que CRS sí bloquea. La evidencia es HTML almacenado/entregado; no se convierte automáticamente en ejecución JavaScript en navegador.

Los 3 FP del candidato provienen de V5 en rutas dinámicas (2 Inf3ct, 1 ObC00ki3s). Los pesos y la representación de V5.1 permanecen iguales: reducir FP mediante rutas públicas configuradas no demuestra una corrección del modelo.

### Explicación del modelo (M06)

Gold de familia fijado antes de TEST. Entre 49 pasos de inyección correctamente bloqueados por V5 en el candidato, 45 tienen familia adjudicada: 30 motivos exactos correctos y 15 que no coinciden con la familia fijada (66,67% de coincidencia); 4 casos HTML quedan sin adjudicar. Otros 17 bloqueos se deben a guardia, fuera del denominador de explicación V5. Los 15 desajustes comprenden 4 SQLi llamados comandos y 11 traversal llamados inclusión de archivos o redirect. La coincidencia literal por familia es una métrica estricta; inclusión/traversal tienen proximidad semántica, pero no se cambia el gold después del test.

### HTTP/2 y carga

H2 TLS persistente: 3 apps, 566 benignas, 49 sesiones de ataque elegibles, 3 FP candidatos y 47/49 inyecciones impedidas. ALPN h2 comprobado; H1 principal usa ALPN http/1.1. TLS session reuse no equivale a reutilizar una conexión. Estos estratos no se mezclan en una única tasa.

Escalera 4/8/16/32/64 rps, 32 workers, 20 s, SLO 1000 ms, 3 repeticiones por punto y brazo. Se recalculó utilidad-bajo-SLO/ofrecidas y se verificó la regla de parada >=2 fallos de 3. An0nB0ard: V5_ONLY 16 rps; candidato 32; directo y CRS >=64. ObC00ki3s: V5_ONLY no supera ni 4 rps por el FP de cks.js; candidato/directo/CRS >=64. No llamar saturación a ese FP basal. Los 2 ensayos de reinicio son adicionales a la escalera.

Los fallos de entrega bajo carga incluyen backlog/deadlines del generador; la capacidad es del sistema con este cliente y SLO, no un máximo intrínseco de V5. La fracción útil candidata de An0nB0ard a 64 rps es 84,61%, 81,41% y 84,14% por repetición. El texto de Claude que menciona aproximadamente 0,81 no representa por sí solo las tres repeticiones. Se publican todas, sin promediar P95 para inventar un P95 global.

Diez escenarios de fallo: baselines sanos, ausencia de recepción durante fallo y recuperación tras reinicio prefijado, 12,39-13,17 s; una observación por celda. Dos reinicios bajo tráfico: V5_ONLY 0,690 s y candidato 0,518 s para cinco respuestas útiles consecutivas tras acabar el reinicio. No es recuperación autónoma. Si V5 está caído, readiness cierra incluso el camino Fast Path; no se promete independencia de disponibilidad.

## Correcciones de lectura del informe de Claude

1. **Errata DEVREG:** `RESULTS.md` afirma que las cabeceras legacy conservan el FP al caer a V5. Los crudos y `METRICS.json` muestran en los 41 benignos DEVREG: V5_ONLY 8 FP; fastv5 y candidato 0 FP, con 36 aciertos Fast Path y 5 peticiones a V5. El resultado correcto es este último. El SSTI DEVREG persiste sin guardia y se impide con ella. No se cambian los casos ni se incorporan a TEST.
2. La coincidencia de motivos del modelo no es perfecta; se añade M06 anterior, ausente de los titulares de Claude.
3. Las tasas de carga y los percentiles se presentan por repetición; se precisa el alcance del cliente, sin atribuir la cola a una causa interna que no se midió.
4. Muestreo GPU/CPU/RAM es diagnóstico. La GPU incluye escritorio/otros procesos; CPU ticks son acumulados y no son porcentaje. No hay energía aislada medida, ni todos los tiempos internos de TLS/app descompuestos, ni soak prolongado. Esos componentes quedan parciales o no medidos en M01-M35.

Estos ajustes corrigen el informe; no alteran C1-C5 ni justifican adaptar el candidato al TEST.

## Límites y cierre operativo

Políticas por app tras auditar sus fuentes; población generada por agente, 35 plantillas benignas, 14 familias de ataque y 3 apps con ataques efectivos. 934 identidades HTTP benignas distintas y solo 151 textos canónicos benignos en H1. No son 985 entradas independientes de V5. Los intervalos de Wilson son descriptivos condicionados al generador; ceros muestrales no prueban riesgo cero. Sin usuarios orgánicos, atacante adaptativo, generalización a apps nuevas ni despliegue de producción evaluados.

Limpieza: CLEAN de corridas y fallos correctos; inventario Docker actual vacío; GPU_STATUS AVAILABLE con owner null. Codex solo leyó estos inventarios; no levantó ni detuvo servicios. Se conservan históricos, fuentes, datasets y modelos. No hubo entrenamiento, staging, commit, push ni publicación de servicio durante esta auditoría.

Fuentes: `reports/v5/architecture-campaign-2026-11-13/` en el repositorio; `test/` privado; `SOURCE_FREEZE.json`, `POPULATION_MANIFEST.json`, `RUNNER_MANIFEST.json`, `TEST_PROTOCOL.md` en coordinación. Los JSON de auditoría y CSV acompañan el informe final en `/home/sebas/Documents/Codex/2026-11-13/la-ultima-sesion-llamada-x20/outputs/cierre_firewall_ia_2026-11-13/`.

## Entrega completada

Informe PDF/LaTeX de 14 páginas terminado e inspeccionado visualmente. M01-M35 entregadas sin métricas pendientes implícitas; las coberturas parciales y exclusiones están identificadas. Claude incorporó las cuatro correcciones del informe, publicó su revisión recíproca en CROSS_REVIEW_CLAUDE.md y alcanzó DONE. Las políticas transitivas de 15 configs verifican su SHA de JSON canónico; recuento directo de las 584 sondas por brazo confirma cero FAST_ALLOW indebidos. El paquete de cierre se guarda junto a este dictamen. Codex pasa a DONE al completar las verificaciones finales.
