# H1 — revisión y hallazgos verificables (Codex, 2026-10-26)

**Resultado: FAIL bajo la regla H1 vigente. No freeze ni entrenamiento.**
Manifest intacto: `7c1ebb9a98fa437c1a1be6839cfe1b2e9b31cac247b8a6ec4d08dc12d5ae8d16`. HEAD `6dc9fadf770cbe52c1e0284b6a785232aef33b8f`.

El verificador anterior solo buscaba http(s) explícito y daba por sintéticas las credenciales sin comprobarlas.
La corrección detecta también `src=//…` y `href=//…`, conserva autoridades no interpretadas como pendientes,
comprueba procedencia por cada ocurrencia y limita la excepción del marcador a su ocurrencia exacta.

| Hallazgo | Filas TRAIN (líneas desde 1) | Procedencia |
|---|---|---|
| `evil.site` (no reservado) | 124, 452, 460, 814, 840, 1340, 2078, 2736, 2918 | payload XSS `cff7a3c1097590b4a3814f590658123b9d27d152834e105031173ddbe11d8938`, contiene `script/src=//evil.site/poc.js` |
| `google.com` y marca Google | 1208 | payload XSS `de9183abc883210028132ae13e0bc6b91dec575a4a9e2b68e3eb80c88f0ac956`, contiene `script/src=//google.com/complete/search…` |
| `Google+` (marca) | 203 | valor de `symbols`, ID `48a061145f463292a1a72bf30565814a611f7984864e2add17a29f79ab4bf560`, manifest benigno `48474e3bf7adf868eea95f20337e406601624b1442bbc7c533f50f4fccf9bd0d` |

Son 10 ocurrencias de hosts en 10 filas y detecciones de marca en 2 filas (una coincide con el host).
Todos están en TRAIN; no se han ajustado los datos usando resultados de modelos.
Detalles, textos y metadatos: `h1-confirmed-findings.json`. El hallazgo no demuestra acceso de red ni rendimiento del modelo.

## Lo que sí quedó cerrado

- 6 candidatos email: prefijos de un valor construido del pool `passwords`, con archivo/manifest fijados por SHA, ID y span de hoja comprobados.
- 198 candidatos por patrones de clave/valor: 126 valores de pools controlados, 58 valores de sintaxis de ataque vinculados al pool ensamblado y 14 tokens escalares cuyo valor se reconstruyó exactamente con el RNG del generador. No quedan credenciales sin resolver ni secretos confirmados por los patrones utilizados.
- No se atribuye procedencia por el nombre del campo. Los patrones de secreto conocido fallan sin una exención de pool automática.
- El replay de tokens solo verifica valores escalares: no genera filas ni repite A2.
- El marcador `[ATTACKER.DOMAIN.TLD]` conserva la disposición limitada previa (filas 2048/2726); no exime los dos hosts nuevos.
- 34 pruebas H1 satisfactorias, incluidas credencial desconocida, fuente alterada, correo dentro de comment, IPv6, autoridad malformada, URLs relativas y segunda aparición del marcador fuera del payload.

## Decisión necesaria, preparada sin aplicarla

Recomendación: preservar v3 y preparar una versión sucesora v4 con identidades de documentación reservadas.
`h1-normalization-proposal.json` enumera las tres sustituciones propuestas y las fuentes exactas.
No se ha aplicado ninguna. Una corrección cambia las huellas y las identidades derivadas: requerirá prerregistro/build nuevos,
verificar la admisión de las fuentes transformadas y ejecutar los controles que dependan de sus nuevos bytes.
No se transfiere un PASS de auditoría al material transformado por inferencia.

La alternativa es una enmienda explícita y limitada de H1 para esos contenidos de investigación, antes del freeze y sin salidas de modelo;
no está aprobada y no se registra como PASS. H1 exige actualmente hosts reservados y ausencia de marcas en las filas.
Esto es una decisión sobre el dataset/protocolo, no una corrección que pueda simularse mediante un commit del checker.
