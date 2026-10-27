# Propuestas A/B/C — sin aprobación

Ninguna tiene identificador nuevo, firma ni permiso atribuido al propietario. D74/D76 no autorizan el freeze; D77 fija G1–G5, sin sustituir A/B/C.

## A. Freeze del dataset de investigación

**DRAFT_BLOCKED_H1. No se recomienda aprobar A para los bytes actuales de v3.**
Resolver primero H1 mediante una decisión sustantiva: h1-normalization-proposal.json propone un sucesor v4 con tres cambios de fuente, preservando v3.
Una excepción limitada futura tendría que ser explícita, con el alcance y la evidencia que la justifican, sin convertir automáticamente H1 en PASS.
Después: aceptación completa, manifest fijado y cinco elementos §11.3 con evidencias, incluidos procedencia, sello y advertencias.
El manifest seguirá REAL y el freeze record separado será FROZEN solo cuando corresponda y exista decisión real.
A no autoriza entrenamiento, umbrales ni runtime.

## B. V5 FINAL ai-audited

DRAFT_PENDING_OWNER_AUTHORIZATION. Requiere A sobre un dataset elegible, aceptación explícita de AI_AUDITED ≠ validación humana,
ai-audit authorization separado, training prereg RATIFIED, receta fijada, registros/evidencias comprometidos, bibliotecas y árbol verificados.
No autoriza Model2 ni runtime. Los borradores actuales siguen vinculados a v3 y sin habilitar; si cambia el dataset hay que rehacer esos vínculos.

## C. FINAL_OFFLINE_MODEL2

DRAFT_PENDING_OWNER_AUTHORIZATION. Dos registros distintos: baseline34 y path-ablation32. Ambos contratos y recetas tienen validación estática PASS,
pero eso no acredita los lectores posteriores. Requiere dataset congelado elegible, autorización compartida ai-audit, receta/C1/protocolo comprometidos,
fuentes/bibliotecas fijadas, autorización específica por receta y gates completos por candidato. No umbral ni ganador operativo.

## Secuencia posterior, sin ejecutar

1. Resolver decisión H1/dataset y medir los artefactos afectados; preservar las evidencias históricas.
2. Presentar A/B/C definitivos con hashes del dataset elegible, sin firmas inventadas.
3. Completar decisiones reales y commits de código/evidencia/registros. La revisión H2/H3 es técnica, no exige una nueva ratificación separada.
4. Cumplir PR a develop previo al entrenamiento (D73); no se dispensa ni se inventa un requisito de merge no establecido.
5. Gate-only V5 y Model2 para ambos candidatos sobre los registros definitivos y árbol limpio.
6. Solo entonces entregar los comandos completos de entrenamiento (Model2 requiere dos invocaciones o un comando compuesto, una receta por ejecución).

No se ejecutó entrenamiento, freeze, commit, PR ni push.
