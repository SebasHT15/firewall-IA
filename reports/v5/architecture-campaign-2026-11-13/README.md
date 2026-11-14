# Campaña de arquitectura 2026-11-13 — índice

Candidato congelado `fastv5-public-v3-headerguard-v2-20261111` (FAST_PATH_V5, V5.1 real, sin Model2). Resultado: **PROMOTE** en el test sellado (C1–C5, con puerta de integridad). Ver [RESULTS.md](RESULTS.md).

## Archivos (públicos: hashes, conteos y campos de decisión cerrados; sin payloads ni casos)
- `RESULTS.md` — informe.
- `METRICS.json` — métricas del transporte principal h1_tls_new (5 brazos × 6 apps), con matriz TP/TN/FP/FN, matriz de decisiones válidas, secuencias de efecto, criterios y contabilidad V5.
- `METRICS.h2.json` — subset h2_tls_keepalive (direct/v5only/fastv5_guard × An0nB0ard/Inf3ct/ObC00ki3s).
- `LOAD_INDEX.json`, `FAULT_INDEX.json` — escalera de carga y fase de fiabilidad.

## Trazabilidad
- Protocolo prefijado: `coordination/architecture-2026-11-11/TEST_PROTOCOL.md`.
- Freeze: `SOURCE_FREEZE.json` (`ae1cf86f…`), candidato FROZEN_CANDIDATE; runtime 90/90 = handoff guard-v2 validado en DEV.
- Población sellada: `POPULATION_MANIFEST.json` (generada antes de conocer la política; solo hashes/conteos públicos).
- Scorer usado: `score.py` sha256 `47419e31685bbe7397c05f543adb6c8f31f28cf035fe20f4f3a5dcbbfd66c558` (runners privados fijados en `RUNNER_MANIFEST.json`); cierres de agregación en `SCORER_CLOSURE_CLAUDE.md` + checks independientes de Codex `SCORER_FINAL_CODEX_CHECKS.json`.
- Raw privado (filas, sellos, logs, stacks): `/home/sebas/Documents/Codex/2026-11-02/fwlab-architecture-private/2026-11-11/test/`.

## Alcance / límites
Seis apps de laboratorio, tráfico de agente en espacio de clientes declarado, N=65 sesiones de ataque en 3 apps detectables. Ceros muestrales (Wilson en METRICS.json). Sin población orgánica/humana ni atacante adaptativo. No se afirma ausencia universal de vulnerabilidades ni superioridad global sobre CRS.
