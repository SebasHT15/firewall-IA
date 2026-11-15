"""Render the kept DEV comparison into payload-free CSV and Spanish report."""
import argparse
import csv
import json
from pathlib import Path


def load(path):
    return json.loads(path.read_bytes())


def percent(value):
    return f'{100*value:.2f} %' if value is not None else 'no estimable'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', type=Path, required=True)
    args = ap.parse_args()
    root = args.root
    targets = [root/name for name in ('INFORME.md', 'comparison.csv', 'model2-selective.csv')]
    if any(p.exists() for p in targets):
        raise ValueError('report exists; keep historical evidence')
    quality = load(root/'current-v5-verified-analysis-v2/quality.json')
    cohorts = ('policy_validation_selection', 'authored_regression_known_DEV')
    rows, selective_rows = [], []
    for name, path, provenance in (
        ('V5 actual verified-suffix', 'current-v5-verified-analysis-v2', 'MEASURED_MODEL_OUTPUTS'),
        ('V5 + baseline34 a 0.9', 'counterfactual-baseline34-t090', 'COUNTERFACTUAL_NO_FAST_PATH'),
        ('V5 + path-ablation32 a 0.9', 'counterfactual-path-ablation32-t090', 'COUNTERFACTUAL_NO_FAST_PATH')):
        data = load(root/path/'quality.json')
        for cohort in cohorts:
            q = data['slices']['cohort'][cohort]
            rows.append(dict(model=name, cohort=cohort, provenance=provenance,
                             **q['principal_E5'], invalid=q['invalid']['n']))
    for name in ('baseline34', 'path-ablation32'):
        data = load(root/f'model2-{name}/model2-selective.json')
        for cohort in cohorts:
            q = data[cohort]
            for item in q['descriptive_thresholds']:
                selective_rows.append(dict(model=name, cohort=cohort, N=q['N'], roc_auc=q['roc_auc'],
                    average_precision=q['average_precision'], brier=q['brier'], ece=q['ece_10bins'], **item))
    for path, data in ((root/'comparison.csv', rows), (root/'model2-selective.csv', selective_rows)):
        with path.open('x', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=list(data[0]))
            writer.writeheader()
            writer.writerows(data)
    lines = ['# Resultados previos al entrenamiento — 1 de noviembre de 2026', '',
        '**La preparación técnica y la referencia de comparación están terminadas; el sucesor todavía no se ha entrenado.** '
        'V4 no participa. Se midió el V5 actual con NF4 sin doble cuantización y `verified-suffix`, perfil experimental ligado a su adaptador.', '',
        '## Qué se ejecutó', '',
        '- Revisión CPU del paquete: 5.166 TRAIN +2.080 VALIDATION, cero rechazos/truncamientos; máximo 406/512 tokens. Cuatro épocas y 648 pasos. Sin fitting.',
        '- 2.514 clasificaciones con pesos V5 reales mediante una API propia temporal; identidad antes/después igual, fuentes ejecutadas conservadas, servicio cerrado.',
        '- Ambos Model 2 FINAL sobre los mismos 2.514 casos, en CPU y sin reentrenar. AUC/AP/Brier/log-loss contrastados con sklearn: 16 coincidencias dentro de 1e-10.',
        '- Combinaciones Model 2→V5 reconstruidas desde las salidas conservadas a 0,9. Son CONTRAFACTUALES, excluyen Fast Path y no miden tráfico, recepción ni ahorro de GPU.', '',
        '## Calidad principal E5', '',
        'Un inválido cuenta como error en su clase real. En BLOCK se contabiliza como FN aunque el gateway lo deniegue por fallo. '
        'Los resultados runtime derivados están separados en los JSON.', '']
    for cohort, label in ((cohorts[0], 'Validación URL: 1.040 BLOCK +1.040 ALLOW, 15 componentes fuente'),
                          (cohorts[1], 'Regresión authored DEV: 213 BLOCK +221 ALLOW')):
        lines += ['### '+label, '', '| Configuración | TP | TN | FP | FN | Recall BLOCK | Inválidos |',
                  '|---|---:|---:|---:|---:|---:|---:|']
        for r in rows:
            if r['cohort'] == cohort:
                lines.append(f"| {r['model']} | {r['TP']} | {r['TN']} | {r['FP']} | {r['FN']} | {percent(r['recall_block'])} | {r['invalid']} |")
        lines.append('')
    lines += ['## Model 2 por separado, umbral descriptivo 0,9', '',
        '| Candidato | Cohorte | Ataques bloqueados temprano | Falsos bloqueos | Deriva a V5 |',
        '|---|---|---:|---:|---:|']
    for r in selective_rows:
        if r['threshold'] == .9:
            lines.append(f"| {r['model']} | {'URL' if r['cohort']==cohorts[0] else 'authored DEV'} | {r['early_block_tp']} | {r['early_block_fp']} | {percent(r['defer_rate'])} |")
    lines += ['', 'Baseline34 conserva menos falsos bloqueos en authored; la ablación bloquea más ataques temprano. '
        'En URL ambos derivan casi todo a V5. No hay un candidato aprobado ni una calibración operativa. '
        'Cero falsos bloqueos en esta cohorte no significa FPR poblacional cero.', '',
        '## Inferencia y limitaciones', '']
    total = quality['timing_by_phase']['quality']['pipeline_ms']
    lines += [f"P95 pipeline en el censo de calidad: **{total['p95']:.2f} ms**; P99 **{total['p99']:.2f} ms**. "
              'Un cliente, cuatro entradas de warmup, mezcla concreta; no es un barrido de saturación ni el benchmark D36.', '']
    for path, r in quality['decoder_paths'].items():
        lines.append(f"- {path}: {r['n']} casos ({percent(r['fraction'])}), P95 pipeline {r['pipeline_ms'].get('p95', 0):.2f} ms.")
    interval = quality['component_bootstrap_by_cohort'][cohorts[0]]['intervals_95']['recall_block']
    lines += ['', f"El intervalo descriptivo del recall URL remuestreando 15 componentes es amplio: {percent(interval['low'])}–{percent(interval['high'])}. "
        'Las 2.080 filas son variantes dependientes; no equivalen a 2.080 ataques independientes. La dependencia entre templates no queda eliminada por este bootstrap.', '',
        'La validación URL se reutiliza para elegir checkpoint: no es test final independiente. Los 434 authored son casos DEV ya conocidos, '
        'con referencias construidas y sin aplicación explotable. No se usa el antiguo eval como referencia fiable.', '',
        'En 22 casos hay referencias opuestas con el mismo texto canónico, en dos grupos JWT/CSRF. '
        'Hay al menos 10 errores inevitables sobre esas referencias para un clasificador determinista que solo ve ese texto. '
        'Eso requiere contexto/versionado, no más filas del mismo texto.', '',
        'El V5 actual carece de motivos SSRF/open_redirect en su vocabulario; por eso cero motivos URL exactos no implica cero bloqueos binarios. '
        'El sucesor amplía ese vocabulario, pero NoSQL/XPath/CRLF siguen sin ejemplos en este entrenamiento: no se atribuye cobertura por listar una salida.', '',
        '## Qué queda para entrenar y medir el sucesor', '',
        '1. Sebas adopta la composición EXPERIMENTAL y la admisión acotada de fuentes; crea la autorización separada con sus hashes y realiza el commit de los archivos indicados en `../successor-training-2026-10-31-reviewed/COMMIT_PATHS.json`. Nada se ha puesto en staging ni comprometido desde este trabajo.',
        '2. Pasar el gate y entrenar en una salida nueva. No se cambia el adaptador anterior, el lector FINAL ni el TRAIN original. La GPU quedó libre al cerrar la referencia.',
        '3. Censar el nuevo V5 con runtime nativo y comparar los casos emparejados; revisar categorías originales además de las URLs. Separar etiquetas, motivos, inválidos y falsos bloqueos.',
        '4. Revalidar NF4/verified-suffix con los nuevos pesos y vocabulario. No heredar perfiles ni tasas del adaptador viejo.',
        '5. Claude ejecuta rutas/carga/recuperación de la cascada nueva con recepción independiente. V4 fuera del camino prioritario. Aplicación aislada y oráculos antes de atribuir explotación impedida.', '',
        'Los comandos están en README.md y las instrucciones para Claude en el archivo entregado al propietario. '
        'No se abrieron reservas ni conjuntos protegidos y no se ejecutaron A2/I7/A6. Los 200 ms siguen siendo aspiracionales.', '']
    with (root/'INFORME.md').open('x') as f:
        f.write('\n'.join(lines))


if __name__ == '__main__':
    main()
