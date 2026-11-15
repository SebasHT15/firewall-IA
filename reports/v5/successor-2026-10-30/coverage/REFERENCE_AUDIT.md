# Revisión de cobertura y referencias

La medición histórica usa el antiguo eval.jsonl raíz, ya rechazado en E0; no es el eval de V4-clean. Sus números describen concordancia con etiquetas históricas, no una tasa de ataques reales que atraviesan un firewall.

Se identificaron cinco casos etiquetados SQLi cuya explicación no está sustentada por una construcción de inyección visible. El clasificador histórico busca, entre otras subcadenas, `insert`; un valor legítimo de un formulario como `modo=insertar` puede dispararlo. La anomalía binaria o intención original requiere el escenario de origen; no se relabeló automáticamente ALLOW.

La frase anterior «V5 pierde tantos ataques SQLi» fue demasiado fuerte para esta fuente. Se preservan los conteos E5 originales y se añade esta auditoría separada. No se debe entrenar para imitar esas etiquetas ni elegir configuraciones por esa concordancia exclusivamente.

En el conjunto authored DEV hay referencias de intentos construidos, pero JWT/CSRF requieren contexto de estado para concluir un bypass real. Los fallos de salida inválida son errores E5, aunque el gateway los bloquee preventivamente; no son peticiones realmente permitidas.

La ampliación del dataset debe cubrir familias ausentes y variantes reales sin recrear los falsos positivos del corpus antiguo. Se requiere trazabilidad por fuente, payload y grupo; el número de filas no mide por sí solo diversidad.
