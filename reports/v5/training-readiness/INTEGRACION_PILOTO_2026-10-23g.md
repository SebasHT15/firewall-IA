# Integración del preparador/pools con #80 — 2026-10-23g

Rama `feat/hybrid-training-ready`, HEAD `97b0be0`, sin commits/refs/push/PR. Codex integró la entrega final de Claude (23f); no se repitió R3, no se usó evaluación protegida, no se generaron splits reales ni se entrenaron pesos.

## Integración terminada

La prueba anterior de `--attack-pool` aceptaba cualquier registro stage-2 ACCEPTED, lo llamaba «admitido» y seguía configurando `fixture_synthetic`. ACCEPTED solo describe extracción; no demuestra admisión por auditoría. Esa ruta podía producir referencias VERIFIED de fuentes externas bajo un manifest fixture. Ahora un archivo de ataques supplied pasa exclusivamente por `prepare_authorized` → `authorized_build`, con pools benignos, configuraciones explícitas, preregistro, autorización REAL_BUILD y exchange/evidencia de auditoría. No se convierte la entrada a fixture ni se activan esquemas por conveniencia. El hash de la entrada debe coincidir con el pool fijado por la autorización; el gate compartido valida su cadena y las categorías.

La ausencia de `--attack-pool` conserva el recorrido sintético, que enumera las entradas pendientes y conserva su alcance fixture. Ninguna ruta persiste filas si fallan los gates; las salidas existentes no se sobreescriben.

Otros ajustes concretos:

- Captura única de bytes para verificar y parsear cada pool. IDs/pool/deduplicación aceptada comprobados. Guards antes de abrir entradas, incluidos targets de symlinks.
- Medición basada en el manifest capturado y los hashes de TRAIN/VALIDATION meta. No abre INTERNAL_TEST/E6_RESERVE. Su contribución por pool declara alcance TRAIN/VALIDATION; los diagnósticos globales son los agregados emitidos por el generador.
- Duplicados/valores descartados del builder construido llevan status EXCLUDED, además de su razón. No hay fallback silencioso de canonicalización si falla el import.
- El contador usa la configuración efectiva; una configuración `tokenizer` exige un contador. La CLI permite cargarlo desde la receta y el tokenizer local fijado, sin red.
- Se conservan hashes de manifests de pools y de los módulos de preparación en la evidencia. El fingerprint del generador incluye `v5_rebalance.py`.
- Se eliminó una imposibilidad técnica del parser I9: acepta PROPOSED o RATIFIED como estado explícito. No se cambió ningún valor a RATIFIED ni se concedió autorización; los gates del build y las restricciones numéricas siguen efectivos. La prueba de concentración sigue deteniendo la misma configuración aunque su estado sea RATIFIED.

## Entradas benignas ya disponibles

Se verificaron los cinco pools de fuentes existentes, sin asignarlos a splits:

| Pool | Valores aceptados |
|---|---:|
| names_given | 26,050 |
| names_family | 12,104 |
| streets | 12,604 |
| prose_en | 34,048 |
| symbols | 295 |

Los cinco pools construidos aportan 300 passwords, 300 URLs públicas, 300 relativas, 300 paths y 294 direcciones; las seis repeticiones de direcciones están EXCLUDED. Los valores construidos siguen marcados como tales, no como tráfico observado. Los cinco pools de fuentes no necesitan reconstruirse para esta entrada.

## Verificación y artefactos

- 112 pruebas afectadas: 3 skips, sin fallos/errores. Tras incorporar los pins de procedencia se repitió el subconjunto de 15 pruebas del piloto: todas aprobadas; no se suman como casos nuevos.
- Nuevo control positivo: diez pools sintéticos → configuraciones explícitas → autorización/evidencia sintética → build #80 efectivo → lector compartido r4. Solo se sustituyen decisiones/esquemas pendientes, comprobaciones de commit y registros/resultados sintéticos; no se mockean las funciones principales.
- Restaurando los defaults, los mismos inputs son REFUSED y no se escribe salida.
- CLI fixture ejecutada con 312 filas y gates/SPL-3…9 aprobados; `measure` ejecutado sobre bytes verificados. No es un piloto real.
- Evidencia retenida en `INTEGRACION_PILOTO_EVIDENCIA_2026-10-23g.json`; artefactos de ejecución en `/home/sebas/Documents/Codex/2026-10-22/firewall-c1-model2-continuidad/work/pilot-integration-007/`.

## Invocación con fuentes, una vez existan las decisiones/entradas

La CLI `prepare` recibe `--pilot-pools`, `--out`, `--attack-pool`, `--benign-pools`, `--build-authorization`, `--audit-exchange`, `--dataset-prereg`, `--split-config`, `--generator-config`; opcional `--tokenizer-recipe` para el contador fijado. `--benign-pools` puede apuntar a `/home/sebas/Desktop/firewall-IA/datasets/v5_sources/benign`.

Esta entrada reutiliza los requisitos actuales del build autorizado: no permite que valores PROPOSED eludan los gates ni otorga por sí misma permiso para un piloto con parámetros provisionales. La decisión del owner sobre esos parámetros/alcance sigue siendo necesaria.

## Trabajo paralelo siguiente

Claude puede preparar el entorno/comando de ejecución GPU de V5 con un módulo propio, sin modificar los módulos de integración. Prompt: `/home/sebas/Documents/Codex/2026-10-22/firewall-c1-model2-continuidad/outputs/PROMPT_CLAUDE_EJECUCION_V5_GPU.md`.

El camino de datos sigue dependiendo de la readmisión de SQLi/XSS/CmdI/SSTI y las ratificaciones pendientes de #80/autorización/valores y recetas. D71 permanece vigente y no se vuelve a pedir plantilla/vocabulario/B415. Integrar los builders no concede esas decisiones ni cambia los resultados sellados.
