"""Recompute payload-free ML/effect metrics and scientific figures from kept rows."""
import argparse
from collections import Counter, defaultdict
import csv
import hashlib
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
import evaluation_metrics as M


def read(path):
    return [json.loads(x) for x in Path(path).read_text().splitlines() if x.strip()]


def effect_rows(root, name):
    rows = read(root / f'{name}.jsonl')
    browser = {r['id']: r for r in json.loads((root / f'{name}.browser.json').read_text())['rows']}
    for row in rows:
        if row['oracle'] == 'browser_script':
            row['effect'] = browser[row['id']]['effect'] if row['received'] else False
    return rows


def prediction(row):
    record = row.get('record') or {}
    identity = {k: row[k] for k in ('id', 'canonical_sha256')}
    if record.get('deciding_stage') == 'model2' and (row.get('model2') or {}).get('status') == 'OK':
        return dict(**identity, status='ok', decision='BLOCK', invalid_reason=None)
    return identity | {k: (row.get('v5') or {}).get(k) for k in ('status', 'decision', 'invalid_reason')}


def summary(rows, baseline):
    cases = rows
    preds = [prediction(r) for r in rows]
    quality = M.quality(cases, preds)
    slices = {family: M.quality([r for r in rows if r['family'] == family],
                               [prediction(r) for r in rows if r['family'] == family])
              for family in sorted({r['family'] for r in rows})}
    valid_attacks = [r for r in rows if r['label'] == 'BLOCK' and baseline[r['id']]['effect'] is True]
    ineffective = [r['id'] for r in rows if r['label'] == 'BLOCK' and baseline[r['id']]['effect'] is not True]
    attack_effect = dict(positive_controls=len(valid_attacks),
        ineffective_control_ids=ineffective, effect_with_firewall=sum(r['effect'] is True for r in valid_attacks),
        prevented_effect=sum(r['effect'] is False for r in valid_attacks),
        unresolved_effect=sum(r['effect'] is None for r in valid_attacks),
        effect_prevention_rate=M.ratio(sum(r['effect'] is False for r in valid_attacks), len(valid_attacks)),
        by_family={family: dict(positive_controls=len(sub := [r for r in valid_attacks if r['family'] == family]),
            effect=sum(r['effect'] is True for r in sub), denied=sum(not r['received'] for r in sub),
            prevention_rate=M.ratio(sum(r['effect'] is False for r in sub), len(sub)))
            for family in sorted({r['family'] for r in valid_attacks})})
    observed = M.confusion([('TP' if not r['received'] else 'FN') if r['label'] == 'BLOCK'
                           else ('FP' if not r['received'] else 'TN') for r in rows])
    false_blocks = [r['id'] for r in rows if r['label'] == 'ALLOW' and not r['received']]
    false_allows = [r['id'] for r in rows if r['label'] == 'BLOCK' and r['received']]
    fields = {'gateway_ms': lambda r: (r.get('record') or {}).get('gateway_ms'),
              'client_ms': lambda r: r.get('client_ms'),
              'v5_pipeline_ms': lambda r: ((r.get('record') or {}).get('v5_service') or {}).get('pipeline_ms'),
              'v5_generate_ms': lambda r: ((r.get('record') or {}).get('v5') or {}).get('generate_ms'),
              'v5_queue_ms': lambda r: ((r.get('record') or {}).get('v5_service') or {}).get('queue_wait_ms'),
              'model2_ms': lambda r: ((r.get('record') or {}).get('stage_ms') or {}).get('model2')}
    latencies = {key: M.distribution([v for r in rows if isinstance(v := fn(r), (int, float))])
                 for key, fn in fields.items()}
    for stage in ('model2', 'v5'):
        latencies['client_ms_' + stage] = M.distribution([r['client_ms'] for r in rows
                       if (r.get('record') or {}).get('deciding_stage') == stage])
    unique = {}
    for row in rows:
        unique.setdefault((row['canonical_sha256'], row['label']), row)
    unique_rows = list(unique.values())
    score_rows = [r for r in rows if r.get('model2') and r['model2'].get('status') == 'OK']
    model2 = M.probability_metrics(score_rows, [r['model2'] for r in score_rows], [.9]) if score_rows else None
    return dict(N=len(rows), quality=quality, observed_non_delivery=observed, by_family=slices,
                attack_effect=attack_effect, latencies=latencies,
                unique_canonical_label_N=len(unique_rows), unique_canonical_quality=M.quality(unique_rows, [prediction(r) for r in unique_rows]),
                component_bootstrap=M.cluster_bootstrap(cases, preds, seed=20261102, replicates=1000),
                model2_selective=model2, model2_scored_cases=len(score_rows),
                stages=dict(Counter((r.get('record') or {}).get('deciding_stage') for r in rows)),
                http_statuses=dict(Counter(r['http_status'] for r in rows)),
                false_block_ids=false_blocks, malicious_delivered_ids=false_allows,
                received_count=sum(r['received'] for r in rows),
                canonical_roundtrip_checked=sum(r['canonical_matches'] is not None for r in rows),
                canonical_roundtrip_mismatches=sum(r['canonical_matches'] is False for r in rows),
                receipt_mismatches=sum(r['received_request_matches'] is False for r in rows))


def percent(value):
    return f'{100*value:.2f}%' if value is not None else 'N/A'


def make_report(root):
    root = Path(root)
    if not (root / 'COMPLETION.json').exists():
        raise ValueError('Cannot report an incomplete run as complete')
    destination = root / 'analysis'
    destination.mkdir(exist_ok=False)
    baseline = {r['id']: r for r in effect_rows(root, 'DIRECT')}
    names = ['native-V5_ONLY', 'native-CASCADE_ACTIVE', 'verified-V5_ONLY', 'verified-CASCADE_ACTIVE']
    result = {}
    all_rows = {}
    for name in names:
        all_rows[name] = rows = effect_rows(root, name)
        if set(baseline) != {r['id'] for r in rows}:
            raise ValueError('Population mismatch')
        new = [r for r in rows if r['cohort'] != 'known_regression']
        result[name] = dict(new_DEV=summary(new, baseline),
                           known_regression=summary([r for r in rows if r['cohort'] == 'known_regression'], baseline))
    comparison = dict(schema='v51-real-docker-application-results/v1', results=result,
        direct=dict(N=len(baseline), attacks=sum(r['label'] == 'BLOCK' for r in baseline.values()),
                    effective=sum(r['effect'] is True for r in baseline.values()),
                    ineffective_attack_ids=[r['id'] for r in baseline.values() if r['label'] == 'BLOCK' and r['effect'] is not True],
                    http_statuses=dict(Counter(r['http_status'] for r in baseline.values())),
                    client_ms=M.distribution([r['client_ms'] for r in baseline.values()])),
        paired_runtime_comparisons={mode: M.paired_comparison(
            [r for r in all_rows['native-' + mode] if r['cohort'] != 'known_regression'],
            [prediction(r) for r in all_rows['native-' + mode] if r['cohort'] != 'known_regression'],
            [prediction(next(v for v in all_rows['verified-' + mode] if v['id'] == r['id']))
             for r in all_rows['native-' + mode] if r['cohort'] != 'known_regression'])
            for mode in ('V5_ONLY', 'CASCADE_ACTIVE')},
        limits=['Own synthetic development experiment, not a final independent test or Internet traffic sample',
                'Repeated sessions/templates; per-request percentages are workload specific',
                'Seven fixture families; no JWT/CSRF/TLS/HTTP2 or comprehensive evasion coverage',
                'XSS effect is actual HTTP body execution in offline Chromium; no victim navigation or exfiltration',
                'Open redirect effect is externally controlled Location, not a user following it',
                'No production approval, threshold selection, fitting or protected set use'])
    (destination / 'METRICS.json').write_text(json.dumps(comparison, indent=2, sort_keys=True)+'\n')
    fields = ['configuration', 'N', 'TP', 'TN', 'FP', 'FN', 'precision_block', 'recall_block', 'fpr',
              'fnr', 'f1_block', 'f2_block', 'accuracy', 'balanced_accuracy', 'specificity', 'mcc',
              'effect_prevention_rate', 'client_p50_ms', 'client_p95_ms', 'client_p99_ms']
    with (destination / 'metrics.csv').open('w') as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for name, doc in result.items():
            s = doc['new_DEV']
            writer.writerow(dict(configuration=name, **{k: s['quality']['principal_E5'][k] for k in fields[1:16]},
                effect_prevention_rate=s['attack_effect']['effect_prevention_rate'],
                **{f'client_p{p}_ms': s['latencies']['client_ms'][f'p{p}'] for p in (50,95,99)}))
    plot(destination, result, all_rows)
    lines = ['# V5.1: tráfico HTTP real contra aplicación Docker aislada', '',
        '2 de noviembre de 2026. Experimento DEV propio con pesos reales, HTTP/1.1 y aplicación '
        'desechable. Sin entrenamiento, V4, conjuntos protegidos ni acciones de Git.', '',
        '**Alcance:** tienda interactiva existente y siete rutas vulnerables propias añadidas en un proceso '
        'separado. No se modificó la aplicación original. No es tráfico de usuarios de producción '
        'ni una evaluación final independiente. Fast Path deshabilitado: mide los errores sin ocultarlos con excepciones.', '',
        '## Controles sin firewall', '',
        f"{comparison['direct']['N']} peticiones directas. De {comparison['direct']['attacks']} ataques construidos, "
        f"{comparison['direct']['effective']} mostraron el efecto predefinido sin firewall. "
        f"Controles ineficaces: {comparison['direct']['ineffective_attack_ids']}.", '',
        'SQLi expone una fila sintética privada; traversal y comandos leen un canario sintético; '
        'SSTI evalúa una expresión; SSRF alcanza el recurso privado de un contenedor interno; '
        'redirect produce un Location externo; XSS ejecuta el documento HTTP recibido en Chromium sin red.', '',
        '## Clasificación nueva DEV — E5 principal', '',
        'Los dos casos conocidos `/healthz` y `/static/app.css` quedan fuera de esta tabla. '
        'Inválidos cuentan como error en su clase verdadera, aunque operativamente se denieguen.', '',
        '| Configuración | N | TP | TN | FP | FN | Precisión | Recall | FPR | F1 |',
        '|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|']
    for name, doc in result.items():
        s = doc['new_DEV']['quality']['principal_E5']
        lines.append(f"| {name} | {s['N']} | {s['TP']} | {s['TN']} | {s['FP']} | {s['FN']} | "
                     f"{percent(s['precision_block'])} | {percent(s['recall_block'])} | {percent(s['fpr'])} | {percent(s['f1_block'])} |")
    lines += ['', '## Efecto observado y latencia de cliente', '',
        'La prevención de efecto usa solo ataques con control directo positivo. La latencia proviene '
        'de la pasada secuencial de calidad, después de calentamiento: no es capacidad sostenida.', '',
        '| Configuración | Controles positivos | Efectos con firewall | Prevención | P50 ms | P95 ms | P99 ms |',
        '|---|---:|---:|---:|---:|---:|---:|']
    for name, doc in result.items():
        s = doc['new_DEV']; e=s['attack_effect']; t=s['latencies']['client_ms']
        lines.append(f"| {name} | {e['positive_controls']} | {e['effect_with_firewall']} | "
                     f"{percent(e['effect_prevention_rate'])} | {t['p50']:.1f} | {t['p95']:.1f} | {t['p99']:.1f} |")
    lines += ['', '## Familias — cascada rápida', '',
              '| Familia | TP | FN | FP | TN | Recall | FPR |', '|---|---:|---:|---:|---:|---:|---:|']
    s = result['verified-CASCADE_ACTIVE']['new_DEV']
    for family, doc in s['by_family'].items():
        q = doc['principal_E5']
        lines.append(f"| {family} | {q['TP']} | {q['FN']} | {q['FP']} | {q['TN']} | {percent(q['recall_block'])} | {percent(q['fpr'])} |")
    lines += ['', '## Interpretación y límites', '',
        '- Los ejemplos se escribieron y sellaron antes de preguntar a los modelos. Etiquetas por '
          'semántica y controles de la aplicación; no por predicciones.',
        '- Se conservan todas las filas, incluidos controles ineficaces y salidas inválidas. '
          'No se retocan umbrales, pesos, referencias ni manifiestos.',
        '- Los recuentos por petición y por texto canónico único, intervalos por componentes, '
          'salidas inválidas, entrega real y Model 2 selectivo están separados en METRICS.json.',
        '- No se transforma DEFER de Model 2 en un ALLOW ni un error del servicio en detección correcta.',
        '- Las familias y sesiones comparten plantillas. Los intervalos bootstrap son descriptivos; '
          'no certifican tasas para tráfico de Internet.',
        '- Los modelos actuales ya estaban elegidos para esta prueba. Este conjunto pasa a ser DEV '
          'conocido tras ejecutarlo; no será evaluación independiente de una corrección futura.',
        '- La red Docker es interna, sin ruta por defecto y sin puertos publicados; el gateway del host '
          'accede a la IP del puente interno. Aplicación '
          'sin datos reales, volúmenes de usuario, Docker socket o permisos privilegiados.',
        '- No se mide aquí TLS/HTTP2, JWT/CSRF, ni Fast Path productivo.', '',
        '## Evidencia', '',
        'PROTOCOL.json fija población, orden, fuentes y manifiestos antes de medir. '
        'DIRECT.jsonl y sus controles de Chromium prueban el resultado sin firewall. '
        'Cada configuración conserva decisiones, estado HTTP, recepción independiente y efecto. '
        'Los cuerpos y registros de aplicación están fuera de Git en el directorio privado del experimento. '
        'COMPLETION.json verifica las 70 fuentes inmutables y ausencia de cambios durante la medición.', '',
        'Reproducir el análisis, con un directorio de análisis nuevo: '
        '`/usr/bin/python3.12 -m scripts.v5_successor.docker_eval.report --root <directorio de corrida>`.', '']
    (destination / 'INFORME.md').write_text('\n'.join(lines))
    hashes = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
              for p in sorted(root.rglob('*')) if p.is_file()}
    (destination / 'EVIDENCE_SHA256.json').write_text(json.dumps(hashes, indent=2, sort_keys=True)+'\n')
    print(json.dumps({name: doc['new_DEV']['quality']['principal_E5'] for name, doc in result.items()}, indent=2))


def plot(out, result, rows):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import numpy as np
    labels = ['Native V5', 'Native cascade', 'Fast V5', 'Fast cascade']
    names = list(result)
    plt.rcParams.update({'font.size': 10, 'axes.spines.top': False, 'axes.spines.right': False})
    fig, axes = plt.subplots(1, 4, figsize=(15, 3.8), constrained_layout=True)
    for ax, name, label in zip(axes, names, labels):
        q = result[name]['new_DEV']['quality']['principal_E5']
        matrix=np.array([[q['TN'],q['FP']],[q['FN'],q['TP']]])
        ax.imshow(matrix,cmap='Blues',vmin=0,vmax=max(x['new_DEV']['N'] for x in result.values()))
        for (i,j), value in np.ndenumerate(matrix):
            ax.text(j,i,str(value),ha='center',va='center',fontsize=15)
        ax.set(xticks=[0,1],xticklabels=['ALLOW','BLOCK'],yticks=[0,1],yticklabels=['Benign','Malicious'],
               title=label,xlabel='Predicted')
    fig.suptitle('Actual Docker HTTP experiment · new synthetic DEV · E5 principal')
    fig.savefig(out/'confusion-matrices.png',dpi=180); fig.savefig(out/'confusion-matrices.pdf');plt.close(fig)
    fig,axes=plt.subplots(1,2,figsize=(11,4),constrained_layout=True)
    x=np.arange(4)
    for i,(field,title,color) in enumerate([('recall_block','Attack detection (%)','#176b8c'),('fpr','Benign false block (%)','#bd4937')]):
        values=[100*result[n]['new_DEV']['quality']['principal_E5'][field] for n in names]
        axes[i].bar(x,values,color=color)
        axes[i].set(xticks=x,xticklabels=labels,title=title,ylim=(0,max(values)*1.18 if max(values) else 1))
        axes[i].tick_params(axis='x',rotation=18)
        for j,v in enumerate(values):axes[i].text(j,v,f'{v:.1f}',ha='center',va='bottom')
    fig.savefig(out/'detection-and-false-blocks.png',dpi=180);fig.savefig(out/'detection-and-false-blocks.pdf');plt.close(fig)
    fig,ax=plt.subplots(figsize=(8,4.5),constrained_layout=True)
    for n,label in zip(names,labels):
        values=np.sort([r['client_ms'] for r in rows[n] if r['cohort']!='known_regression'])
        ax.step(values,np.arange(1,len(values)+1)/len(values),where='post',label=label)
    ax.set(xlabel='Client end-to-end latency (ms)',ylabel='Cumulative fraction',title='Sequential quality pass · not sustained capacity')
    ax.legend();ax.grid(alpha=.2);fig.savefig(out/'latency-ecdf.png',dpi=180);fig.savefig(out/'latency-ecdf.pdf');plt.close(fig)
    s=result['verified-CASCADE_ACTIVE']['new_DEV']['by_family']
    families=[f for f,d in s.items() if d['principal_E5']['TP']+d['principal_E5']['FN']]
    fig,ax=plt.subplots(figsize=(9,4.5),constrained_layout=True)
    values=[100*s[f]['principal_E5']['recall_block'] for f in families]
    ax.barh(families,values,color='#176b8c');ax.set(xlim=(0,110),xlabel='Recall (%)',title='Fast cascade · own validated attack fixtures')
    for i,v in enumerate(values):ax.text(v+.5,i,f'{v:.1f}%',va='center')
    fig.savefig(out/'attack-family-recall.png',dpi=180);fig.savefig(out/'attack-family-recall.pdf');plt.close(fig)
    selected=[r for r in rows['verified-CASCADE_ACTIVE'] if r['cohort']!='known_regression'
              and r.get('model2') and r['model2'].get('status')=='OK']
    grouped=defaultdict(list)
    for r in selected:grouped[r['model2']['p_block']].append(int(r['label']=='BLOCK'))
    positives=sum(sum(v) for v in grouped.values());negatives=len(selected)-positives
    tp=fp=0;roc=[(0,0)];pr=[(0,1)]
    for score in sorted(grouped,reverse=True):
        ys=grouped[score];tp+=sum(ys);fp+=len(ys)-sum(ys)
        roc.append((fp/negatives,tp/positives));pr.append((tp/positives,tp/(tp+fp)))
    fig,axes=plt.subplots(1,2,figsize=(10,4),constrained_layout=True)
    axes[0].plot(*zip(*roc),color='#176b8c');axes[0].plot([0,1],[0,1],'--',color='gray')
    axes[0].set(xlabel='False positive rate',ylabel='True positive rate',title='Model 2 ROC · score diagnostic')
    axes[1].step(*zip(*pr),where='post',color='#176b8c')
    axes[1].axhline(positives/len(selected),ls='--',color='gray')
    axes[1].set(xlabel='Recall',ylabel='Precision',title='Model 2 precision–recall · no threshold selection')
    fig.savefig(out/'model2-roc-pr.png',dpi=180);fig.savefig(out/'model2-roc-pr.pdf');plt.close(fig)


if __name__ == '__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--root',required=True)
    make_report(parser.parse_args().root)
