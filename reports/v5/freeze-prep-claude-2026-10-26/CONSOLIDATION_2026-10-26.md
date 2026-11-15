# Cierre técnico Codex — 2026-10-26

**Estado real: BLOCKED_H1. No basta con hacer commit.** HEAD permanece 6dc9fad, v3 permanece intacto.
El resumen anterior “H1 resuelto, solo commit pendiente” queda sustituido por esta revisión y la evidencia reproducible.

## Hecho

- Corregidos H1, excepciones por ocurrencia, extracción de autoridades completas/relativas, procedencia por pool/hash/valor/span, y resolución de tokens por replay escalar exacto.
- 34 pruebas H1 OK y 27 pruebas A5 focalizadas OK; logs conservados. No se repitieron A2/I7/A6 reales.
- C-M3 y carencias de mutación identificadas acreditadas; C-S6/L8/L9 aprovechan código existente. L10/L11 siguen advertencias.
- H2/H3 revisados; 3160 textos sin framing de transporte medido.
- Insumos externos retenidos localmente y recuperación de 18 archivos verificada byte a byte (no prueba de backup off-device).
- Contratos/recetas V5 y Model2 comprobados de forma estática; fuentes y registros vinculados sin cambiar estados habilitantes.

## Hallazgo real

H1 falla: evil.site en nueve filas TRAIN y google.com en una; marca Google+ en otra fila TRAIN.
Ver H1_FINDINGS_AND_NEXT_DECISION.md y h1-confirmed-findings.json. La disposición limitada de [ATTACKER.DOMAIN.TLD] no los autoriza.
No quedan candidatos de credenciales sin resolver en los patrones aplicados. El verificador no es un detector universal de secretos.

## Lo que requiere decisión

Recomendada versión sucesora v4 con normalización documentada de dos payloads y un valor symbols.
Propuesta exacta h1-normalization-proposal.json; no aplicada. Alternativa: enmienda explícita de H1 por el propietario; no aprobada aquí.
No emitir freeze v3 mientras el fallo permanezca bajo la regla vigente.

A/B/C continúan separados, DRAFT y sin autorización. D73 exige PR a develop antes de entrenar.
Los registros Model2 receta/C1/protocolo y las evidencias nuevas no están comprometidos. Los dos gate-only originales siguen rechazados:
V5 F5/F6/F10; Model2 rechazó receta no comprometida antes de abrir datos. No se reinterpretan como PASS ni se repitieron en esta revisión.
Los lectores posteriores y los comandos FINAL quedan pendientes de dataset elegible, decisiones, registros comprometidos y gates satisfactorios.
