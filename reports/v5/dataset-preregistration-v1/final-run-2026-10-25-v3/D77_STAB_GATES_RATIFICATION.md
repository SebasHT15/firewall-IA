# D77 — STAB-HELD G1–G5 ratificados

**Decisión del propietario (chat, 2026-10-26):** «Sí, ratificar G1–G5 (recomendado)» en respuesta a la pregunta que vinculaba el documento `STAB_GATES_TO_RATIFY.md` y el set STAB-HELD sellado.

- Criterios exactos: `STAB_GATES_TO_RATIFY.md`, SHA-256 `ba5c58d3a0ab9cd51338d15c63f7b3f0b5f09a89563619386547ec3fa9d31329`.
- Sello previo del set: `datasets/v5_sources/stab_held_2026-10-25-v1/SEAL.json`, SHA-256 `34d02c6962d68ed374822cf68965690847ff69861588e8b979a308cd283af6b8`.
- El sello original conserva `G1_G5_owner_ratification: PENDING` porque fue emitido **antes** de esta decisión; este registro posterior documenta la ratificación sin modificar los bytes sellados.

Esta decisión fija G1–G5 antes de cualquier salida de modelo sobre el set. Autoriza incorporar esos criterios al prerregistro de entrenamiento experimental. No declara PASS, no autoriza leer STAB-HELD antes del checkpoint/umbral congelado y no sustituye los gates de freeze ni la autorización final de entrenamiento.
