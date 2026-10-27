# Valores restantes de §11.2 para el dataset V5 final

**Valores RATIFICADOS por el propietario en este chat el 2026-10-25 (D75); este documento no es la autorización individual del build.** Se fijan a partir del piloto r2 (`pilot_measurements.json` SHA-256 `21f7e01975fc93bbca5595770d1010bac7e407fc2edbb3e68cb27f037aaab798`). Deben incorporarse al prerregistro y commitearse antes del build completo.

| Valor | Propuesta y evidencia |
|---|---|
| Alcance | Entrenar `path_file_access`, SQLi, XSS, CmdI, SSTI. Solo `path_file_access` es EVALUABLE con el reparto D60 actual; las demás son TRAIN-only/NOT_EVALUABLE. Ver `DECISION_SCOPE_I9.md`. |
| Cuota y piloto | 20 pares por celda en el build; piloto 2 pares por celda (10%). Piloto r2 `gates_ok=true`, SPL-3…9 verdaderos y 0 celdas con shortfall. |
| I-9 | WARN 8%, BLOCK 12%, cap `warn`; excepciones específicas `path-media`/VALIDATION y `path-export`/INTERNAL_TEST. La prueba de cuota completa registra esas dos y ninguna concentración TRAIN por encima del cap. Necesita decisión expresa porque relaja 2%/5% propuestos. |
| OVER_LIMIT | Stop >1% por categoría × clase, valor propuesto por §5.5; piloto 0 casos en todas las celdas. |
| L y firmas del oráculo | `L=12`; firmas exactas del archivo `scripts/dataset/v5_policy/oracle_signatures_v1.json`, SHA-256 original `5775dc11deab41233ca116d00c974da2fda50ca57078171f3bbc78127ff12589`, SHA-256 después de actualizar solo el status D75 `162670025d6fbb812716e2ca3818ea93e24e49277d4c3138223d61431a6ff40b`. El fixture de supervivencia del oráculo pasa; no se cambió ninguna expresión. |
| Reparto de colocación | Pesos `replace:prefix:suffix:embedded = 3:1:1:1`; piloto observado 89/20/26/23 entre los pares emitidos. |
| Límite por archivo fuente | Máximo 75% del pool de cada categoría; máximos observados en el lote: CmdI 71.0%, SQLi 66.2%, SSTI 25.0%, XSS 43.1%, path 36.4%. Se aplicará también en el freeze report. |
| Denylist | `scripts/dataset/v5_lexicon/patt_third_party_denylist_v2.json`, status APPROVED, SHA-256 `3e5570580a10319fc03ca622c034786a384a3ea6dddaf95bfeb413cf3fc7dd7e`. Mantener la limitación de licencia MIT asumida para contenido sin atribución. |
| Política de URL/host/formulario | Contenido exacto de `scripts/dataset/v5_policy/policy_table_v1.json`, SHA-256 original `b4c3e7a9304da33de17ad8b96ebc98fa996025524cc25aa82a793b90561b39cf`, después del cambio de status D75 `a881df75cc31ad8e93688c073127027cb824dff45f659caa042b454074306a22`; incluye `0.0.0.0/8`, `100.64.0.0/10` y `fe80::/10`. |
| Catálogo estructural | Las 41 plantillas de `scripts/dataset/v5_templates/catalog_v1.json`, SHA-256 original `db5ba69b4f7f4bea224bad823c14dbc7c973109fced273acbe981672babec7eb`, después del cambio de status D75 `26cd2c1342e42044aa21aa65ac452cf59597fd8cb06d1f3a6bfd81a87c73d7de`. El piloto las ejercitó sin fallos de split. |
| Clase y simetría | C-M3: BLOCK 48–52% PASS, fuera WARN, fuera 45–55% BLOCK. C-S6: simetría ≥0.80 PASS, 0.50–0.80 WARN, <0.50 BLOCK. El piloto dio 50% y simetría exacta por carrier. |
| Shortcut / leakage | Conservar umbrales propuestos en `freeze-prep/C_validation_protocol.md` §4: C-S1 BLOCK margen ≥0.10 o exactitud ≥0.80; C-S2 pureza ≥0.99 con cobertura ≥1%; C-S3 WARN ≥0.80/BLOCK ≥0.95; C-S4 WARN >0.55/BLOCK >0.65; C-S7 WARN >1%/BLOCK >3%; C3 proveedor 20–80% WARN; L10 novedad WARN >50%; L7/L8/L9 cero solapes bloqueantes. |
| Auditoría de fuentes | Wilson C1 ≤0.20, C2 ≤0.35, cobertura 100%, cero pendientes relevantes, n≥50 o pool completo si menor, submuestra R3≥20, una re-auditoría máximo solo tras cambio de filtro; ya fijados para los componentes admitidos. |
| Tokenización | `B=415`, `max_length=512`, margen 8, overhead 76, label 13 según D71; repetir medición en el tokenizer exacto del modelo antes de FINAL. |
| I7 fuzz | Fijar **2500 casos** con semilla `20261013`, más el barrido exhaustivo de 256 bytes por campo, implementados en `tests/test_canonical_request_review.py` (SHA-256 `36da6dc8efdb2e87f423880dfb3c297fc422d44ac85489b4bde1e8d2358b313f`). Ambos tests I7 pasaron el 2026-10-25 sobre `data_plane/canonical_request.py` SHA-256 `991c1a11ebdb0c22e6c05102ae9a0e1e9756247ec654ab874e2c78d92f1f58b4`. La ejecución antes de congelar debe repetirse sobre el código commiteado. |

## Trabajo técnico aún necesario antes de firmar el freeze

Implementar y ejecutar los checkers completos de §7 que hoy son solo diagnósticos (C-S1–C-S7, colisiones L7/L8/L9, byte-regeneración); repetir I7 sobre el código commiteado, generar y sellar `STAB-HELD` con lexicón/salt propio, verificar el tokenizer exacto, emitir informe de freeze con evidencia por componente y commitear el código/los registros. La aprobación de esta tabla no reemplaza resultados de esos checks ni las autorizaciones finales de cada entrenamiento.
