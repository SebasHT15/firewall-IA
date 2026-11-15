"""Compare kept model censuses; no inference, selection, fitting or promotion."""
import argparse
from collections import Counter
import csv
import hashlib
import json
from pathlib import Path

from collect_evaluation import population, read_jsonl
from evaluation_metrics import checked_predictions, report, paired_comparison


def load(p):
    return json.loads(p.read_bytes())


def pct(v):
    return f'{100*v:.2f} %' if v is not None else 'no estimable'


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--root', type=Path, required=True)
    ap.add_argument('--protocol', type=Path, required=True)
    ap.add_argument('--previous-predictions', type=Path, required=True)
    args = ap.parse_args()
    root = args.root
    if (root/'INFORME.md').exists() or (root/'COMPARISON.json').exists():
        raise ValueError('comparison already exists; preserve historical evidence')
    protocol, cases = population(args.protocol)
    paths = dict(previous_fast=args.previous_predictions,
                 successor_native=root/'native-recipe/quality-run/predictions.jsonl',
                 successor_fast=root/'verified-suffix/quality-run/predictions.jsonl')
    predictions = {k: checked_predictions(cases, read_jsonl(p.read_bytes())) for k, p in paths.items()}
    reports = {k: report(cases, p, bootstrap_replicates=protocol['bootstrap_replicates']) for k, p in predictions.items()}
    for name in ('baseline34','path-ablation32'):
        reports[f'counterfactual_{name}_t09'] = load(args.root/f'counterfactual-{name}-t090/quality.json')
    paired = {}
    for cohort in sorted({c['cohort'] for c in cases}):
        indexes = [i for i, c in enumerate(cases) if c['cohort'] == cohort]
        paired[cohort] = paired_comparison([cases[i] for i in indexes],
            [predictions['previous_fast'][i] for i in indexes],
            [predictions['successor_fast'][i] for i in indexes], replicates=protocol['bootstrap_replicates'])
    changes = []
    for case, left, right in zip(cases, predictions['successor_native'], predictions['successor_fast']):
        fields = ('status', 'decision', 'reason', 'invalid_reason', 'ended_with_eos')
        if any(left.get(k) != right.get(k) for k in fields):
            changes.append(dict(id=case['id'], cohort=case['cohort'], label=case['label'],
                native={k:left.get(k) for k in fields}, fast={k:right.get(k) for k in fields}))
    benchmark = load(root/'decoder-benchmark/verification.json')
    previous_benchmark = load(root/'previous-decoder-benchmark/verification.json')
    if load(root/'decoder-benchmark/protocol.json')['benchmark_ids'] != load(root/'previous-decoder-benchmark/protocol.json')['benchmark_ids']:
        raise ValueError('matched model benchmark cases differ')
    diagnosis = load(root/'runtime-change-diagnosis/diagnosis.json')
    rows = []
    for name, result in reports.items():
        for cohort, cell in result['slices']['cohort'].items():
            rows.append(dict(model=name, cohort=cohort, provenance='COUNTERFACTUAL_NO_FAST_PATH' if name.startswith('counterfactual') else 'REAL_MODEL_API',
                             **cell['principal_E5'], invalid=cell['invalid']['n'],
                             reason_exact_correct=cell['reason']['exact_correct'],
                             reason_eligible=cell['reason']['eligible_block_cases']))
    for name, data in reports.items():
        (root/f'quality-{name}.json').write_text(json.dumps(data, indent=2)+'\n')
    result = dict(schema='v51-post-training-comparison/v1', scope='DEVELOPMENT_SELECTION_AND_KNOWN_REGRESSION_NOT_FINAL_TEST',
        sources={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths.values()},
        principal_E5=rows, paired_fast_vs_previous=paired,
        runtime_bundle_changes_native_DQ_vs_fast_noDQ=changes,
        decoder_benchmark=benchmark, previous_matched_benchmark=previous_benchmark,
        runtime_change_diagnosis=diagnosis, protected_sets_used=False, reserve_opened=False,
        selected_threshold=None, runtime_production_approved=False,
        interpretation=['V5 previous/fast use the same runtime family: NF4 noDQ + verified suffix; weights/recipe/vocabulary differ.',
                        'Successor native vs fast changes quantization and decoder. Decoder-only check uses the same NF4 noDQ weights.',
                        'New URL validation selected checkpoint; authored is known DEV. Neither is independent final evaluation.',
                        'No gateway/load/exploit conclusion follows from these model censuses.'])
    (root/'COMPARISON.json').write_text(json.dumps(result, indent=2)+'\n')
    with (root/'quality-comparison.csv').open('x', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
    table = ['| Modelo | Cohorte | TP | TN | FP | FN | Recall BLOCK | Inválidos |',
             '|---|---|---:|---:|---:|---:|---:|---:|']
    for r in rows:
        table.append(f"| {r['model']} | {'URL' if r['cohort']=='policy_validation_selection' else 'authored DEV'} | {r['TP']} | {r['TN']} | {r['FP']} | {r['FN']} | {pct(r['recall_block'])} | {r['invalid']} |")
    lines = ['# V5 sucesor: evaluación posterior al entrenamiento', '',
        'Pesos reales, sin reentrenar ni modificar adaptadores. V4 no participa. No se aprueba despliegue, umbral o perfil productivo.', '',
        '## Qué significa el resultado del entrenamiento', '',
        'Las 1.553 coincidencias exactas de 2.080 no son 527 ataques omitidos. El registro del entrenador contiene 1.040 BLOCK correctos, '
        '1.036 ALLOW correctos y cuatro falsos bloqueos. Solo 517 de 1.040 motivos BLOCK son exactos: '
        '496 redirecciones se explican como SSRF y 27 SSRF se explican como SSTI. Detección y motivo se evalúan por separado.', '',
        'Los hashes de todos los archivos del adaptador coinciden con el registro. Sus 308 tensores tienen los mismos valores que el mejor checkpoint 486; '
        'el archivo final usa float32 y el checkpoint bfloat16, por eso sus hashes de archivo difieren. No se sustituyeron las pesas por el último checkpoint 648.', '',
        '## Censos reales por API', '', *table, '',
        'previous_fast y successor_fast comparten la familia de ejecución NF4 sin doble cuantización + verified-suffix. '
        'La receta y vocabulario nuevos forman parte del candidato; no se atribuye toda diferencia a un solo cambio.', '',
        'Hay 2.080 casos de validación URL procedentes de 15 componentes fuente, usados para selección de checkpoint. '
        'Los 434 authored son regresión DEV conocida. Las referencias son políticas/expectativas construidas, no explotación observada. '
        'Cero omisiones en esta muestra no garantiza cero omisiones futuras.', '',
        'Las filas counterfactual se reconstruyen a umbral de laboratorio 0,9, sin Fast Path: no son rutas observadas ni ahorro de GPU medido. '
        'Las matrices principales son E5: inválido cuenta como error en su clase verdadera. La denegación fail-closed derivada está separada en los JSON. '
        'JWT/CSRF conservan referencias opuestas con texto canónico idéntico; no se atribuye al modelo información que no recibe.', '',
        '## Perfil rápido: comprobación separada de pesos nuevos', '',
        (f"Comparación del decodificador con generación nativa usando la misma cuantización NF4 sin doble cuantización: "
         f"{benchmark['unique_cases']} casos únicos, {benchmark['paired_observations']} pares en tres procesos nuevos; "
         f"{len(benchmark['mismatches'])} discrepancias de salida/EOS/hash."), '']
    for method, d in benchmark['pooled'].items():
        lines.append(f"- {method}: P50 {d['p50']:.2f} ms; P95 {d['p95']:.2f} ms; P99 {d['p99']:.2f} ms (300 observaciones sobre 100 entradas).")
    previous_ms = previous_benchmark['pooled']['verified_suffix']['p95']
    successor_ms = benchmark['pooled']['verified_suffix']['p95']
    lines += ['', f"Control del V5 anterior con los MISMOS 100 casos y tres procesos nuevos: P95 rápido {previous_ms:.2f} ms; "
        f"sucesor rápido {successor_ms:.2f} ms. No se comparan cohortes diferentes para atribuir este cambio.", '',
        'El perfil rápido del sucesor sigue siendo más lento que el rápido anterior en esta mezcla. '
        'En el benchmark SSRF/SSTI necesitan siete tokens de prefijo antes de verificar el sufijo; ALLOW necesita uno. '
        'El vocabulario ampliado y las decisiones nuevas cambian ese trabajo. Esto explica un mecanismo de coste, no atribuye causalmente toda la diferencia a un único factor.', '',
        '## Regresión por categoría de referencia authored', '',
        '| Referencia | BLOCK correctos anterior | BLOCK correctos sucesor rápido | Total BLOCK |',
        '|---|---:|---:|---:|']
    for category in ('sql_injection','command_injection','path_file_access','xss','ssti','ssrf','open_redirect','jwt','csrf','other_attack'):
        old = reports['previous_fast']['slices']['category'][category]['principal_E5']
        new = reports['successor_fast']['slices']['category'][category]['principal_E5']
        lines.append(f"| {category} | {old['TP']} | {new['TP']} | {new['TP']+new['FN']} |")
    lines += ['', f"Cambios entre el runtime nativo de la receta (con doble cuantización) y el perfil rápido completo: **{len(changes)}** casos. "
        'Se conservan individualmente en COMPARISON.json. Esta comparación cambia cuantización y decodificador; no se confunde con la prueba del decodificador solo.', '',
        f"Se reprodujeron los {diagnosis['cases']} casos cambiados con native-noDQ y verified-noDQ sobre el mismo modelo: "
        f"{diagnosis['native_noDQ_vs_verified_mismatches']} discrepancias entre ambos y {diagnosis['API_fast_not_reproduced']} salidas API no reproducidas. "
        'Es diagnóstico posterior a observar diferencias, no benchmark independiente.', '',
        'Los tiempos del censo API son una pasada de calidad, no capacidad ni un ensayo de carga. '
        'El benchmark aislado tampoco mide el gateway. Los 200 ms son aspiracionales; D36 histórico no se reescribe.', '',
        '## Próximo paso', '',
        'Entregar adaptador, receta, medición de tokens y manifiesto/perfil experimental a Claude para rutas reales y carga de la cascada. '
        'La selección final de runtime/candidato exige revisar las regresiones y falsos bloqueos de estas tablas; la existencia de un manifiesto no la aprueba. '
        'Hay una omisión authored más en el perfil rápido que en el nativo de receta: no se oculta a cambio de latencia. '
        'Model2 continúa BLOCK/DEFER con su política de laboratorio, sin selección de umbral por este informe.', '',
        'Fast Path productivo necesita contrato de aplicación; el sink demuestra entrega y no explotación. '
        'No se abrieron reservas ni conjuntos protegidos y no se hicieron operaciones de Git.', '']
    with (root/'INFORME.md').open('x') as f:f.write('\n'.join(lines))


if __name__ == '__main__':
    main()
