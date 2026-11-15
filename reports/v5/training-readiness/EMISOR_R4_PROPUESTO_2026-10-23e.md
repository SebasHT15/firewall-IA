# Emisor #80 y recorrido de entrenamiento — 2026-10-23e

Rama `feat/hybrid-training-ready`, HEAD `97b0be0`. Implementación sin commits, refs, push, PR, entrenamiento real ni cambios de runtime. Se preservó el trabajo de Claude en builders/preparador del piloto.

## Contrato concreto implementado, pendiente de ratificación

Contrato `v5-training-reference-contract/v1-PROPOSED`, definido en `scripts/dataset/v5_row_contract.py`:

| Campo | Ataque genérico cuya referencia procede de IA |
|---|---|
| `label` | `BLOCK` |
| `label_status` | `TRAINING_REFERENCE` |
| `label_status_basis` | `ai_audit` |
| `label_rule` | `ATTACK_POOL_LEAF` |
| `policy_id` | `null` |
| Manifest `audit_type` | `ai_audited` |
| Manifest/autorización build `row_contract` | `v5-training-reference-contract/v1-PROPOSED` |

El resultado de categoría `PASS_AI_AUDITED` sigue separado del estado de la fila. No se crea VERIFIED, no se inventan políticas de seguridad ni se usa una decisión de modelo como etiqueta. Las filas sujetas a políticas existentes conservan `POLICY_DEFINED`, su `policy_id` y basis `policy_defined`.

Esta propuesta extiende **explícitamente M-1** con un estado adicional ligado a contrato. No cambia M-3 ni el documento r4 congelado, y no equivale a que D67 lo hubiese aprobado. Requiere ratificar esta extensión del contrato #80 antes de activar r4 con ella. La definición en código no concede autorización.

## Código terminado

- `label_attack_leaf` emite la referencia con procedencia separada. El emisor heredado r3 conserva su comportamiento.
- `authorized_build` exige contrato/spec/status activos antes de generar; configura una copia del World, comprueba la procedencia emitida y persiste el contrato en el manifest. Las comprobaciones de evidencia, categorías, cuotas, invariantes e integridad siguen siendo efectivas.
- Lectores y `prepare` validan el nuevo estado únicamente con el contrato correcto, BLOCK, basis IA, regla de ataque y ausencia de política; se mantiene el rechazo de IA+VERIFIED y de un basis IA bajo otro tipo de auditoría.
- Model 2 acepta esas referencias tras el lector compartido y conserva el contrato como metadato, sin incorporarlo a features. La fuente del contrato queda fijada en los pins de código de V5/Model 2.
- La plantilla REAL_BUILD sin firmar ya contiene el campo requerido. Los campos del owner siguen vacíos.

`SUPPORTED_SPECS` sigue r3; `AI_AUDIT_ROW_STATUS_ALLOWED=()`; los esquemas REAL_BUILD y autorización FINAL siguen `None`. No se simulan ratificaciones en configuración activa.

## Evidencia de ejecución

Nuevo test `tests/test_v5_r4_emitter.py`: build → manifest/filas → lector compartido → preparación efectiva de V5, 232 TRAIN / 24 VALIDATION. Nuevo test Model 2: misma salida → entrada pública EXPERIMENTAL → fit → guardado → recarga → scoring idéntico. También se prueba el rechazo antes de generar si falta ratificación y la inmutabilidad del World del caller.

Solo son dobles las decisiones/esquemas pendientes, las comprobaciones de commit y los registros/resultados de auditoría sintéticos. No se mockean generador, gates, integridad, lectores, preparación o fit. El World es sintético aunque se configura `mode=real` para ejercitar esa rama de producción. Esto **no es un piloto real ni una autorización de entrenamiento**.

Evidencia retenida: `EMISOR_R4_EVIDENCIA_SINTETICA_2026-10-23e.json`. Ambas vistas de Model 2 se guardaron y recargaron, delta portable máximo 1.5543122344752192e-15 / 5.551115123125783e-16. No se ajustó umbral ni política operativa. Se verificó la preparación de V5; no se entrenaron sus pesos ni se ejecutó el recorrido FINAL completo desde este build.

Verificación afectada: 160 pruebas datos/lectores/generador/evidencia (4 skips); 34 Model 2 (sin skips); 131 remediación/pools (sin skips). Ningún fallo/error. Las invocaciones adicionales sobre pruebas ya contadas no se suman como pruebas distintas.

## Fuentes y siguiente integración

Incremento 006: 14 unidades SQL con marcador de paginación se ponen en cuarentena sin sustituir valores. Quedan 3,875 filas candidatas pendientes; se conservan 25 bloques compuestos/227 líneas separados y las 2,081 filas ajenas a las cuatro familias son iguales al incremento 004. Ver `reports/v5/postfilter-audit/source-remediation-2026-10-23/increment-006/`.

No se ejecutó otra campaña de auditoría. La corrección de fuentes no cambia los resultados sellados de R3: SQLi, XSS, Command Injection y SSTI aún no están readmitidos. Cero señales de contexto de las reglas implementadas no significa que todos los candidatos sean válidos.

Siguiente paso concreto al llegar la entrega de Claude: integrar sus pools/preparador con este contrato, aplicar las decisiones pendientes del owner y ejecutar el piloto sobre categorías efectivamente elegibles. Luego build definitivo, freeze y entrenamiento, según los gates existentes. D71 ya ratificó plantilla/vocabulario/B415 y no se vuelve a pedir. Esta entrega no añade una fase de auditoría al plan.
