# FIREWALL-IA — Dossier de continuidad para el siguiente chat de Claude

Fecha: 2026-10-20, America/Costa_Rica. Este documento es para el **coordinador**, no para el revisor ciego R3.

## 1. Punto de partida y Git

- Repositorio: `SebasHT15/firewall-IA`; carpeta principal local: `/home/sebas/Desktop/firewall-IA`.
- Rama de trabajo: `feat/v5-data-readiness`. Un único [PR #79](https://github.com/SebasHT15/firewall-IA/pull/79) hacia `develop`.
- El PR estaba **abierto, sin fusionar y sin conflictos** al verificar este dossier. Consultar su estado al empezar: no inferir que el usuario ya hizo merge.
- Último commit antes de esta actualización documental: `23c39e5`. La documentación se añade después en la misma rama/PR.
- El trabajo original de la rama y los cambios revisados de los worktrees de Claude están consolidados. No volver a aplicar sus parches completos.
- Los worktrees originales siguen intactos como recuperación: inferencia parcial, analyzer shadow, model2/fastpath y propuesta de gate FINAL. No borrarlos ni hacer nuevos cambios allí.
- Preferencia del propietario: una sola rama de trabajo a la vez, un PR por lote y sin proliferación de worktrees. No crear ramas, worktrees ni subagentes sin petición explícita. Si #79 sigue abierto, continuar en su rama. Si ya se fusionó, comprobar el estado local y acordar el siguiente lote antes de cambiar de rama; nunca resetear ni descartar trabajo.
- El usuario se encarga del merge. No añadir firmas ni trailers de autoría de asistentes.

## 2. Qué funciona y qué se incorporó

| Frente | Estado real |
|---|---|
| Gateway actual | V4 HF/PEFT sigue decidiendo todas las solicitudes; fail-closed |
| Inferencia truncada | Corregida: el API exige evidencia EOS de los tokens; un texto cortado que parece ALLOW no se permite |
| D66 | Deny-list v2 aprobada y pool de ataque reconstruido: 3.933 ACCEPTED; no equivale a filas verificadas para entrenamiento |
| D67 / r4 | Ratificados y congelados; r3 histórico conservado |
| Auditoría | a1 Sonnet 453/453, a2 Haiku 453/453; 69 V/P resueltos por la regla aprobada; R3 preparado, no ejecutado |
| R3 | 200 de muestra ciega + 33 desacuerdos relevantes − 16 solapados = 217 registros únicos |
| `names_family` | Snapshot Wikidata LIMIT 20000 adoptado; 12.104 valores aceptados; adquisición resuelta |
| Generador | Etapas independientes implementadas; `names_family` aún fuera de SLOT_POOLS; no split real ni dataset V5 final |
| Analyzer shadow | Proceso separado, con fallos/timeout observables; integrado y desactivado por defecto |
| Fast Path shadow | Evaluador conservador y logging integrados; desactivado; el gateway actual siempre carece de los prerrequisitos de elegibilidad |
| Model 2 | Propuesta BLOCK/DEFER; no entrenado, no implementado, no aplicado |
| Gate FINAL r4 | Parche y pruebas propuestos preservados, **sin aplicar**; falta ratificar contrato de procedencia/autorización |
| V5 | No entrenado; FINAL bloqueado; fallback selectivo inexistente |

La corrección EOS no resuelve #65: la inyección de tokens especiales en el **texto de entrada** es un problema distinto. El parser de benchmarks que solo recibe texto conserva sus reglas históricas.

## 3. Arquitectura objetivo que debe guiar el trabajo

```text
Solicitud HTTP en el cable
  → parser del data plane
  → validación de framing + canonicalización
  → solicitud canónica
  → Fast Path: FAST_ALLOW o CONTINUE
       FAST_ALLOW → permitir
       CONTINUE   → Analyzer C1 + posible C2 → vector de evidencia
                   → Model 2: BLOCK o DEFER
                        BLOCK → bloquear
                        DEFER → V5 semántico → ALLOW / BLOCK
```

- El Fast Path es parte del objetivo. No dejarlo fuera ni describirlo como reemplazado por el analyzer.
- C1 = extracción determinista de evidencia. C2 = componente aprendido opcional. Las salidas de ataque y categoría del analyzer congelado pertenecen a C2, no definen C1/C2.
- Model 2 no tiene salida ALLOW en la propuesta actual. Su autoridad de bloqueo temprano y sus criterios todavía necesitan ratificación.
- La política propuesta del Fast Path requiere coincidencia positiva con reglas cerradas y contexto de aplicación explícito. Un score bajo o ausencia de señales sospechosas no basta para permitir.
- #35–#38 y D29 conservan una formulación antigua basada en puntuación. Documentar la reconciliación de alcance; no inventar que D29 ya fue reemplazada.
- Shadow significa observar lo que habría ocurrido. Hoy no evita llamadas a V4 ni demuestra mejora de latencia o calidad.
- D52 sigue abierto para ubicación productiva. El worker separado es una implementación experimental, no autorización de despliegue.
- Los pesos congelados se evaluaron sobre features del texto D1. No suponer que las features de entrada canónica son equivalentes sin medirlo.

## 4. Restricciones vigentes

- No ejecutar R3 desde el chat coordinador ni entregarle al revisor etiquetas, membresía, conclusiones o este dossier. Usar una sesión fresca con el modelo designado por D67 y registrar su identificación real.
- No alterar muestras, seeds, anotaciones previas, r3/r4 congelados, umbrales o evidencias para obtener PASS.
- Criterios D67: límite superior Wilson 95% de INCORRECT ≤20%; UNCERTAIN+INCORRECT ≤35%; cobertura 100%; cero casos relevantes sin resolver para aceptar categoría. Mismos umbrales en categorías pequeñas.
- Los denominadores corresponden al marco original de 453, por categoría. No contar dos veces los 16 solapados ni usar los 33 como muestra independiente.
- AI_AUDITED/PASS_AI_AUDITED no equivalen a VERIFIED ni a validación humana independiente.
- SSRF sigue NOT SUPPORTED. No restaurarlo sin corrección y reauditoría aprobadas.
- FINAL permanece bloqueado. La integración Git no autoriza entrenamiento, cambios de pesos, bypass o enforcement híbrido.
- No tocar los conjuntos protegidos para afinar decisiones. No repetir las evaluaciones congeladas como si fueran nuevas pruebas independientes.
- Q4_K_M sigue no autorizado para decisiones reales; bf16 es referencia de fidelidad y Q8_0 candidato provisional. GGUF/llama.cpp solo tiene diagnóstico offline, no integración productiva.

## 5. Validación y recuperación

En el código consolidado anterior a esta actualización documental:

- Python 3.12: 1.343 pruebas, OK; 141 omitidas.
- Entorno data plane: 408 pruebas, OK; 2 omitidas.
- Entorno analyzer: 83 pruebas, OK; 2 omitidas.

Las suites se solapan: no sumar sus conteos como pruebas distintas. Los comandos exactos, omisiones y limitaciones están en `reports/v5/integration/README.md`. No hubo una nueva evaluación de calidad del modelo ni benchmark de rendimiento. GitHub no mostraba checks automáticos en #79 al verificarse.

Se verificaron hashes de los 59 archivos excluidos de Git y la reconstrucción exacta de los ocho archivos generados para R3 desde el archivo preservado. El respaldo local está en:

`/home/sebas/Documents/Codex/2026-10-20/pu/outputs/firewall-preservation-20261020/`

Contiene `pending-work-and-evidence.tar.gz`, manifiesto y checksums, estados originales de Git y `audit-evidence.tar.gz`. Es una copia en la **misma máquina**, no un respaldo externo. El repositorio registra la restauración en `reports/v5/data-readiness/evidence-preservation-manifest.json`. Los datos crudos no se subieron a Git; una clonación nueva necesita estos archivos para reproducir la auditoría.

Anclas:

- r3: `f1580634d35d2baf10b99d7985f9bfb1e56ebc956326a58a61b665fc5958d9cb`.
- r4: `54514850e9875f4a71d6ad3726d95746bb4e61687db4f56b072e0a01bfdc01be`.
- Preregistro r4: `1039a3ddf4d614c1700d1fd13303c50dec50619502fcc13a8df8243c5cdd73bf`.
- Snapshot familiar: `039882220480b029074243f740f4eec07646029a0b6de8ce70f99454686d3ead`.
- Archivo de evidencia: `297b1e30442e9d0c4fa15d44066f02d13f4163255bc597cb20f2d62c3aa4db47`.

## 6. Qué hacer a continuación

1. **Git:** revisar/fusionar #79 mediante el propietario. Confirmar rama, HEAD, limpieza y estado remoto al iniciar la sesión.
2. **#75:** usar el snapshot existente; medir/verificar equivalencias y rendimiento de apóstrofos/Unicode; concretar precedencias y configuración para aprobación; implementar/verificar la integración del pool cuando esas decisiones estén ratificadas. No cerrar por haber conseguido la descarga. No ejecutar todavía un split real.
3. **#77:** actualizar su descripción al protocolo aprobado D67/r4; preparar la entrega ciega a R3. Tras la ejecución separadamente autorizada, validar importación, adjudicación y reporte por categoría. No volver al requisito humano retirado ni fabricar etiquetas.
4. **Gate FINAL:** revisar el parche ya preservado y cerrar el esquema de procedencia, estado de fila y autorización independiente. Implementarlo con pruebas negativas solo tras ratificación; no entrenar.
5. **Arquitectura:** avanzar los prerrequisitos de #68 y política de #36, y preparar/ejecutar la medición de ambos observers dentro del alcance aprobado. Esto puede avanzar sin esperar a entrenar V5; no implica permiso de activar rutas de decisión.
6. **Después:** piloto real del dataset cuando pasen sus precondiciones; Model 2 con contrato BLOCK/DEFER y evidencia de calibración; V5/fallback; validación externa, rendimiento y despliegue.

El plan detallado de issues, sin duplicar #36/#68/#75/#77, está en `docs/issue-plan-2026-10-20.md`. No se cerró ni abrió ningún issue durante esta actualización de continuidad.

## 7. Lecturas mínimas para la nueva sesión

1. Este dossier y el checkpoint superior de `CONTEXT.md`.
2. `README.md`, `DECISIONS.md` (D1–D67; distinguir decisiones de notas de implementación).
3. `reports/v5/integration/README.md` y `docs/issue-plan-2026-10-20.md`.
4. `reports/v5/data-readiness/names_family-candidate/ADOPTION.md` y `provenance.json`.
5. `reports/v5/postfilter-audit/r3-review/README.md`, r4 y su preregistro, solo como coordinador.
6. `docs/hybrid_shadow_runtime.md`, `reports/v5/hybrid/fast-path-contract.md` y `model2-contract-proposal.md`.
7. `reports/v5/data-readiness/proposals/README.md` y el borrador de issue del gate.

Las secciones antiguas de CONTEXT y los reportes fechados conservan historia. Sus frases “uncommitted”, “not merged”, “names_family blocked” o “fast path fuera del objetivo” no sustituyen el checkpoint de 2026-10-20.

## 8. Prompt de arranque para Claude

# Firewall-IA — Continuity Recovery and Next Execution Package

The project work has been consolidated into `feat/v5-data-readiness`, PR #79 targeting `develop`. Read the attached continuity dossier and verify the actual repository/PR state before changing anything. Do not assume the PR has merged.

### 1. Required context recovery

Read the current checkpoint, README, DECISIONS D1–D67, integration report and issue plan. Distinguish approved decisions, implemented code, proposals and historical status. Report only material mismatches; do not restart completed research or reapply old worktree patches.

### 2. First execution package

Focus on the remaining #75 prerequisites using the adopted family-name snapshot: inspect existing evidence, verify reproducibility and cross-pool equivalence, identify the exact unratified precedence/configuration choices, and prepare a concrete minimal integration proposal with meaningful tests. Complete authorized analysis before requesting any owner decision. Do not invent approval or run a real split.

Also identify the next bounded #68/#36 architecture task so Fast Path is not dropped while the audit proceeds. Prepare the required choices and acceptance evidence; do not start unapproved gateway canonicalization or enforce FAST_ALLOW.

### 3. Architecture invariants

Target: framing/canonicalization → Fast Path FAST_ALLOW/CONTINUE → Analyzer C1 deterministic evidence + optional learned C2 → Model 2 BLOCK/DEFER → V5 ALLOW/BLOCK. Today V4 remains the only enforced decision. Both implemented observers remain off unless an explicitly authorized experiment requires enabling them. A low analyzer score is never sufficient evidence for ALLOW.

### 4. Scope restrictions

Do not run R3 in this coordinator session, alter frozen evidence or thresholds, train V5, unblock FINAL, apply the proposed gate without ratification, restore SSRF, create new worktrees/branches/subagents, or merge a PR. Do not add assistant attribution. Git publication requires the owner's applicable authorization in this session; preserve the current work regardless.

### 5. Expected report

Return a concise Spanish report covering: verified branch/PR state; completed versus pending work; concrete #75 findings; the smallest owner decisions still needed; files changed and checks actually run; exact criteria before closing #75; and the next bounded Fast Path task. Keep requests for decisions separate from facts. Do not claim a data acquisition, shadow observation or passing unit test completes the architecture.
