# H2 / H3 — revisión técnica Codex, 2026-10-26

## H2: PASS por revisión y evidencia de prueba

v5_generator.draw_scalar y la selección de pools operan sobre slot.value_type; las funciones de etiquetado no reciben nombres de campos.
La distinción de rol data/navigation de v5_labels.slot_role está permitida por la política ratificada; no convierte nombres address/password en etiquetas.
El checker M8 comprueba la firma y la nueva prueba inyecta un parámetro field_name para demostrar su rechazo.
No se necesita una nueva ratificación del propietario para que exista esta evidencia técnica.

## H3: PASS por mecanismo y scan

v5_render.render construye RequestParts con solo Content-Type y body lógico; la canonización se hace con canonical_request.canonicalize.
Las representaciones HTTP de transporte no se copian directamente a model text. Esto es independiente de ENC-3 (que regula formas de payload),
y no se atribuye a ENC un control de framing que no implementa.
Scan read-only: 3160 textos, 0 líneas Transfer-Encoding, 0 líneas de chunk-size con CRLF.
`h2-h3-evidence.json` captura las mediciones, manifest y hashes del código revisado.

No se abrieron casos STAB-HELD ni se usaron salidas de modelo. Ninguno de estos PASS autoriza freeze o entrenamiento.
