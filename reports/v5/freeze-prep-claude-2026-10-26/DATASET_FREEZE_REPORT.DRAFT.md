# Dataset v3 — propuesta de freeze bloqueada (Codex, 2026-10-26)

**DRAFT. No congelado. H1 FAIL; no autoriza entrenamiento.**
Dataset: `datasets/v5_sources/final_source_2026-10-25-v3/manifest.json`, SHA `7c1ebb9a98fa437c1a1be6839cfe1b2e9b31cac247b8a6ec4d08dc12d5ae8d16`.
El manifest conserva REAL; cualquier freeze futuro se expresaría en un registro separado, sin modificar esos bytes.
3080 TRAIN + 40 VALIDATION + 40 INTERNAL_TEST; 1580 pares completos; 0 shortfalls.

## §11.3

| Elemento | Estado |
|---|---|
| post_filter_audit | Evidencia existente, ai_audited, componentes separados: original path / censo CmdI-SSTI-XSS / SQLi v3; combined_pool_pass=false |
| blocking_checks | PARTIAL/BLOCKED: H1 falla; no sustituir por DONE al hacer commit |
| dataset_preregistration | RATIFIED, SHA a155018984afc1a807502047a6840d499dd225f02aaa6d1023517873a87f98d2 |
| stab_held_sealed | sello intacto, SHA 34d02c6962d68ed374822cf68965690847ff69861588e8b979a308cd283af6b8; D77 posterior sin alterar sello |
| dataset_freeze_report | este borrador negativo, no aceptación del dataset |

A2/I7/A6 siguen acreditados y no se repitieron sobre v3. La cobertura A5 identificada está corregida (`ACCEPTANCE_TABLE_AND_A5.md`).
H1 corregido: 34 tests OK; sobre v3 el resultado es FAIL por evil.site/google.com y las marcas documentadas en `H1_FINDINGS_AND_NEXT_DECISION.md`.
Emails/credenciales: procedencia por valor y ocurrencia, sin atribuciones automáticas; no quedan candidatos de credenciales sin resolver.
H2/H3: revisión técnica PASS, `h2-h3-evidence.json`. Integridad de v3 comprobada por hashes, sin modificación.

## Conservación y recuperación

Se conservó una copia local de los insumos externos en `/home/sebas/Desktop/firewall-IA/datasets/v5_sources/freeze_input_retention_2026-10-26/inputs.tar.gz`.
SHA `e8f58bd4396f347f7d7ac86dba1039dbea60f827929fd6d5b20c16fb8cc26eed`; 18 archivos recuperados temporalmente y verificados por hash/tamaño.
`external-input-retention.json` contiene inventario y límites. No se repitió A2. No hay afirmación de backup independiente fuera del equipo.

## Límites que se conservan

CmdI/SQLi/SSTI/XSS son solo TRAIN y NOT_EVALUABLE; solo path_file_access evaluable con una estructura por split protegido y excepciones D74.
L10 WARN alto: VAL 15/20, ITEST 19/20; L11 0 hits. STAB es concept-built del proyecto, no muestra externa independiente.
PATT 149 registros contextuales con hash y 1666 legacy sin hash por fila. AI_AUDITED no equivale a verificación humana.
No hay métricas ni afirmación de seguridad de producción. v1/v2 rechazados se preservan; v3 también se preserva.

## Decisión pendiente

No se recomienda emitir A para los bytes actuales mientras H1 no se resuelva bajo el protocolo.
Propuesta concreta sin aplicar: versión sucesora v4, en `h1-normalization-proposal.json`. Requiere decisión del propietario y nuevos vínculos/evidencia para las fuentes transformadas.
Las autorizaciones B (V5) y C (dos candidatos Model2) siguen independientes y sin habilitar. D73 mantiene el PR a develop antes de entrenar.
