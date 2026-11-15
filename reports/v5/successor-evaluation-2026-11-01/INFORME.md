# Resultados previos al entrenamiento — 1 de noviembre de 2026

**La preparación técnica y la referencia de comparación están terminadas; el sucesor todavía no se ha entrenado.** V4 no participa. Se midió el V5 actual con NF4 sin doble cuantización y `verified-suffix`, perfil experimental ligado a su adaptador.

## Qué se ejecutó

- Revisión CPU del paquete: 5.166 TRAIN +2.080 VALIDATION, cero rechazos/truncamientos; máximo 406/512 tokens. Cuatro épocas y 648 pasos. Sin fitting.
- 2.514 clasificaciones con pesos V5 reales mediante una API propia temporal; identidad antes/después igual, fuentes ejecutadas conservadas, servicio cerrado.
- Ambos Model 2 FINAL sobre los mismos 2.514 casos, en CPU y sin reentrenar. AUC/AP/Brier/log-loss contrastados con sklearn: 16 coincidencias dentro de 1e-10.
- Combinaciones Model 2→V5 reconstruidas desde las salidas conservadas a 0,9. Son CONTRAFACTUALES, excluyen Fast Path y no miden tráfico, recepción ni ahorro de GPU.

## Calidad principal E5

Un inválido cuenta como error en su clase real. En BLOCK se contabiliza como FN aunque el gateway lo deniegue por fallo. Los resultados runtime derivados están separados en los JSON.

### Validación URL: 1.040 BLOCK +1.040 ALLOW, 15 componentes fuente

| Configuración | TP | TN | FP | FN | Recall BLOCK | Inválidos |
|---|---:|---:|---:|---:|---:|---:|
| V5 actual verified-suffix | 512 | 1039 | 1 | 528 | 49.23 % | 33 |
| V5 + baseline34 a 0.9 | 524 | 1039 | 1 | 516 | 50.38 % | 33 |
| V5 + path-ablation32 a 0.9 | 522 | 1039 | 1 | 518 | 50.19 % | 33 |

### Regresión authored DEV: 213 BLOCK +221 ALLOW

| Configuración | TP | TN | FP | FN | Recall BLOCK | Inválidos |
|---|---:|---:|---:|---:|---:|---:|
| V5 actual verified-suffix | 173 | 221 | 0 | 40 | 81.22 % | 1 |
| V5 + baseline34 a 0.9 | 174 | 220 | 1 | 39 | 81.69 % | 1 |
| V5 + path-ablation32 a 0.9 | 176 | 218 | 3 | 37 | 82.63 % | 1 |

## Model 2 por separado, umbral descriptivo 0,9

| Candidato | Cohorte | Ataques bloqueados temprano | Falsos bloqueos | Deriva a V5 |
|---|---|---:|---:|---:|
| baseline34 | URL | 42 | 0 | 97.98 % |
| baseline34 | authored DEV | 51 | 1 | 88.02 % |
| path-ablation32 | URL | 64 | 0 | 96.92 % |
| path-ablation32 | authored DEV | 74 | 3 | 82.26 % |

Baseline34 conserva menos falsos bloqueos en authored; la ablación bloquea más ataques temprano. En URL ambos derivan casi todo a V5. No hay un candidato aprobado ni una calibración operativa. Cero falsos bloqueos en esta cohorte no significa FPR poblacional cero.

## Inferencia y limitaciones

P95 pipeline en el censo de calidad: **101.17 ms**; P99 **223.63 ms**. Un cliente, cuatro entradas de warmup, mezcla concreta; no es un barrido de saturación ni el benchmark D36.

- fallback: 34 casos (1.35 %), P95 pipeline 248.67 ms.
- verified: 2480 casos (98.65 %), P95 pipeline 100.57 ms.

El intervalo descriptivo del recall URL remuestreando 15 componentes es amplio: 11.35 %–80.66 %. Las 2.080 filas son variantes dependientes; no equivalen a 2.080 ataques independientes. La dependencia entre templates no queda eliminada por este bootstrap.

La validación URL se reutiliza para elegir checkpoint: no es test final independiente. Los 434 authored son casos DEV ya conocidos, con referencias construidas y sin aplicación explotable. No se usa el antiguo eval como referencia fiable.

En 22 casos hay referencias opuestas con el mismo texto canónico, en dos grupos JWT/CSRF. Hay al menos 10 errores inevitables sobre esas referencias para un clasificador determinista que solo ve ese texto. Eso requiere contexto/versionado, no más filas del mismo texto.

El V5 actual carece de motivos SSRF/open_redirect en su vocabulario; por eso cero motivos URL exactos no implica cero bloqueos binarios. El sucesor amplía ese vocabulario, pero NoSQL/XPath/CRLF siguen sin ejemplos en este entrenamiento: no se atribuye cobertura por listar una salida.

## Qué queda para entrenar y medir el sucesor

1. Sebas adopta la composición EXPERIMENTAL y la admisión acotada de fuentes; crea la autorización separada con sus hashes y realiza el commit de los archivos indicados en `../successor-training-2026-10-31-reviewed/COMMIT_PATHS.json`. Nada se ha puesto en staging ni comprometido desde este trabajo.
2. Pasar el gate y entrenar en una salida nueva. No se cambia el adaptador anterior, el lector FINAL ni el TRAIN original. La GPU quedó libre al cerrar la referencia.
3. Censar el nuevo V5 con runtime nativo y comparar los casos emparejados; revisar categorías originales además de las URLs. Separar etiquetas, motivos, inválidos y falsos bloqueos.
4. Revalidar NF4/verified-suffix con los nuevos pesos y vocabulario. No heredar perfiles ni tasas del adaptador viejo.
5. Claude ejecuta rutas/carga/recuperación de la cascada nueva con recepción independiente. V4 fuera del camino prioritario. Aplicación aislada y oráculos antes de atribuir explotación impedida.

Los comandos están en README.md y las instrucciones para Claude en el archivo entregado al propietario. No se abrieron reservas ni conjuntos protegidos y no se ejecutaron A2/I7/A6. Los 200 ms siguen siendo aspiracionales.
