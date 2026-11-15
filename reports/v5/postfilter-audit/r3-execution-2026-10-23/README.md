# R3 — ejecución y adjudicación (2026-10-23)

Estado: revisión ciega COMPLETA (217/217); adjudicación automática reproducida sobre el marco original de 453. Siete casos siguen UNRESOLVED. No autoriza entrenamiento FINAL.

## Ejecución e independencia

El owner autorizó explícitamente sustituir la designación original por `gpt-6-sol` y usar cinco subagentes nuevos, sin historial (fork_turns=none), uno por lote. Los cinco recibieron únicamente el prompt congelado y su lote. No recibieron etiquetas anteriores, pertenencia a desacuerdos ni resultados esperados. Se seleccionó `gpt-6-sol` en la herramienta; la revisión interna exacta del backend no está expuesta. No se inventa una identificación. La autorización textual está en execution-record.json y las respuestas originales en raw/.

Los lotes se verificaron contra SHA256SUMS congelado. El preregistro estaba versionado y sin cambios en HEAD 97b0be0. Las fuentes a1/a2 y el marco coinciden con los hashes fijados por coordinator/integrity.json. Las respuestas mantienen orden/IDs, esquema y 217 IDs únicos. Cada uno de los 16 registros compartidos se cuenta una sola vez.

## Resultado por categoría

| Categoría | Estado | n original | INCORRECT resueltos | Sin resolver | Wilson superior I / U+I |
|---|---|---:|---:|---:|---|
| CRLF Injection | PASS_AI_AUDITED | 22 | 0 | 0 | 14.87% / 14.87% |
| Command Injection | INSUFFICIENT_EVIDENCE | 50 | 5 | 1 | No estimado: adjudicación incompleta |
| NoSQL Injection | INSUFFICIENT_EVIDENCE | 50 | 17 | 1 | No estimado: adjudicación incompleta |
| Open Redirect | NOT_SUPPORTED | 50 | 3 | 0 | 16.22% / 37.41% |
| SQL Injection | NOT_SUPPORTED | 50 | 10 | 0 | 33.04% / 43.75% |
| Server Side Request Forgery | NOT_SUPPORTED | 50 | 21 | 0 | 55.77% / 55.77% |
| Server Side Template Injection | NOT_SUPPORTED | 50 | 9 | 0 | 30.80% / 33.04% |
| XPath Injection | PASS_AI_AUDITED | 31 | 1 | 0 | 16.19% / 20.72% |
| XSS Injection | INSUFFICIENT_EVIDENCE | 50 | 10 | 5 | No estimado: adjudicación incompleta |
| path_file_access | PASS_AI_AUDITED | 50 | 3 | 0 | 16.22% / 18.84% |

NOT_SUPPORTED representa incumplimiento de los límites congelados o la disposición previa de SSRF. INSUFFICIENT_EVIDENCE conserva los casos sin resolver; nunca se convierten automáticamente en INCORRECT. PASS_AI_AUDITED acredita únicamente el gate de auditoría AI, no validación humana ni VERIFIED por fila.

## Impacto inmediato en datos/V5

Del vocabulario candidato (SQLi, XSS, path traversal, file inclusion, Command Injection y SSTI), únicamente la categoría unificada path_file_access pasa esta auditoría. CRLF y XPath pasan, pero no se añaden automáticamente al vocabulario. SQLi/SSTI no cumplen el gate; XSS/Command siguen INSUFFICIENT_EVIDENCE. Las tres categorías incompletas ya tienen más de cuatro INCORRECT resueltos sobre n=50, por lo que resolver los siete votos restantes favorablemente no bastaría para cumplir el límite C1 de 20% con el marco actual.

Para conservar la cobertura candidata se necesita una corrección de filtros documentada y la ruta de reauditoría permitida por el protocolo, comprobando antes si queda disponible. La alternativa es redefinir explícitamente el alcance del dataset/vocabulario y sus cuotas con el owner. Ninguna alternativa se aplica implícitamente en este reporte. No se eliminan filas del marco ni se recalculan denominadores para fabricar PASS.

## Handoff para Claude

Consumir report.json/category_outcomes conservando las categorías y procedencia. Solo PASS_AI_AUDITED puede satisfacer el gate de categoría; no promover el estado de fila a VERIFIED. Mantener las siete decisiones de pending-owner-decisions.json abiertas. No considerar que ratificar plantilla/vocabulario/B basta para autorizar el piloto: faltan elegibilidad, entradas de #82 y decisiones de parámetros.

## Reproducción y verificación

```bash
python3 -B reports/v5/postfilter-audit/r3-execution-2026-10-23/adjudicate.py
python3 -B -m unittest discover -s reports/v5/postfilter-audit/r3-execution-2026-10-23 -p test_adjudicate.py
```

Seis pruebas focalizadas: acuerdo preservado, regla V/P, mayoría con tres votos válidos, ausencia de voto, esquema/IDs y fronteras Wilson del preregistro. La ejecución solo lee evidencia de auditoría; no abre datasets de evaluación ni ejecuta payloads.

Los hashes describen integridad; no establecen corrección de etiquetas. Las tasas son de la muestra adjudicada por IA, no tasas de error respecto de verdad humana independiente.
