"""Seal a completed run, sanitize logs, recompute metrics and package evidence."""
import csv
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import zipfile

REPO = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
OUT = REPO / 'reports/v5/hybrid/experiments-2026-10-30'
PRIVATE = Path('/home/sebas/Documents/Codex/2026-10-26/ta/work/metrics-2026-10-30')
DELIVER = Path('/home/sebas/Documents/Codex/2026-10-26/ta/outputs/Metricas_Firewall_2026-10-30')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    if not (OUT / 'execution_complete.json').exists():
        raise RuntimeError('Measurements must finish before sealing evidence.')
    original = OUT / 'v5_service.log'
    private_log = PRIVATE / 'v5_service.private.log'
    if not private_log.exists():
        shutil.copy2(original, private_log)
        os.chmod(private_log, 0o600)
    sanitized = ''.join(
        line.split(' raw=', 1)[0] + ' raw=[omitted; generated-text digest in predictions]\n'
        if ' raw=' in line else line
        for line in private_log.read_text().splitlines(keepends=True)
    )
    original.write_text(sanitized)
    retention = {
        'raw_inputs': str(PRIVATE / 'inputs.private.jsonl'),
        'raw_inputs_sha256': digest(PRIVATE / 'inputs.private.jsonl'),
        'raw_service_log': str(private_log),
        'raw_service_log_sha256': digest(private_log),
        'redistribution': 'Neither private input text nor raw malformed generated text is included in this report/bundle.',
        'recovery': 'Regenerate the same legacy sample using make_dev_sample.py (seed 20261026) and the existing eval.jsonl; prepare.py adds the project-authored paired_dev_set.generate() cases and native D1/canonical rendering. Verify protocol.json input hash before inference.',
        'third_party_policy': 'docs/data_sources.md; legacy eval redistribution terms unconfirmed. Keep local only.',
    }
    (OUT / 'DATA_RETENTION.json').write_text(json.dumps(retention, indent=2) + '\n')
    roles = {}
    resource_path = OUT / 'live_process_resources.jsonl'
    if resource_path.exists():
        for line in resource_path.read_text().splitlines():
            for rec in json.loads(line)['processes']:
                command = ' '.join(rec['command'])
                role = 'V5 service' if 'uvicorn' in command else 'live analyzer/gateway' if '/experiments/live.py' in command else None
                if role is None:
                    continue
                data = roles.setdefault(role, {'RSS_peak_bytes_observed': 0, 'CPU_peak_one_core_100_observed': 0, 'threads_peak': 0, 'samples': 0})
                data['RSS_peak_bytes_observed'] = max(data['RSS_peak_bytes_observed'], rec['rss_bytes'])
                if not rec['cpu_first_sample_unprimed']:
                    data['CPU_peak_one_core_100_observed'] = max(data['CPU_peak_one_core_100_observed'], rec['cpu_percent_one_core_100'])
                data['threads_peak'] = max(data['threads_peak'], rec['threads'])
                data['samples'] += 1
    gpu = []
    for line in (OUT / 'gpu_telemetry.jsonl').read_text().splitlines():
        row = next(csv.reader([json.loads(line)['csv']]))
        try:
            gpu.append({'temperature_C': float(row[2]), 'utilization_percent': float(row[3]), 'memory_total_used_MiB': float(row[4]), 'power_draw_W_snapshot': float(row[5]), 'SM_clock_MHz': float(row[6])})
        except (ValueError, IndexError):
            pass
    resource = {'scope': '1 Hz observations; process sample starts at live stage, GPU throughout experiment; peaks can miss subsecond transients', 'processes': roles, 'GPU_device_snapshot_ranges': {key: [min(r[key] for r in gpu), max(r[key] for r in gpu)] for key in gpu[0]} if gpu else {}, 'not_energy_measurement': True}
    (OUT / 'resources_summary.json').write_text(json.dumps(resource, indent=2) + '\n')
    for name in ('analyze.py', 'figures.py', 'verify.py', 'report.py'):
        subprocess.run(['/usr/bin/python3.12', '-B', str(HERE / name)], cwd=REPO, check=True)
    reproduction = '''# Reproducir sin modificar Git ni sobreescribir evidencia

Desde `/home/sebas/Desktop/firewall-IA`, con GPU libre y los mismos pesos/datos locales:

```bash
/usr/bin/python3.12 -B scripts/cascade_lab/experiments/run.py \\
  --out reports/v5/hybrid/experiments-REPLICA-NUEVA \\
  --private /home/sebas/Documents/Codex/2026-10-26/ta/work/metrics-REPLICA-NUEVA \\
  --deliver /home/sebas/Documents/Codex/2026-10-26/ta/outputs/Metricas_REPLICA-NUEVA
```

Los tres directorios deben ser nuevos. El lanzador rechaza directorios existentes, mantiene peticiones privadas fuera de Git, ejecuta las pruebas afectadas antes de medir y apaga exclusivamente el servicio temporal que inicia. No entrena ni abre conjuntos reservados. El diagnóstico de desarrollo anterior y la muestra de 434 casos se reconstruyen desde las fuentes locales; el manifiesto vincula su hash antes de inferir.

El paquete no redistribuye pesos, eval.jsonl, inputs privados ni el log original de posibles salidas inválidas. Contiene resultados por petición sin payloads, código, protocolo, hashes, pruebas y figuras. Los checkpoints y dependencias fijadas deben existir en el repositorio local para repetir inferencias.

Para recalcular solamente el informe de la ejecución original, sin GPU ni nuevas inferencias:

```bash
/usr/bin/python3.12 -B scripts/cascade_lab/experiments/analyze.py
/usr/bin/python3.12 -B scripts/cascade_lab/experiments/figures.py
/usr/bin/python3.12 -B scripts/cascade_lab/experiments/verify.py
/usr/bin/python3.12 -B scripts/cascade_lab/experiments/report.py
```

El protocolo y las observaciones originales permanecen identificados por sus hashes. Las salidas derivadas pueden volver a calcularse. Solo Sebas realiza staging, commit, push, PR o merge.
'''
    (OUT / 'REPRODUCIR.md').write_text(reproduction)
    sources = {}
    for directory in ('control_plane', 'data_plane', 'scripts/model2', 'scripts/training', 'scripts/dataset', 'scripts/cascade_lab'):
        for path in (REPO / directory).rglob('*.py'):
            sources[str(path.relative_to(REPO))] = digest(path)
    (OUT / 'code_manifest.json').write_text(json.dumps(sources, indent=2) + '\n')
    evidence = {str(p.relative_to(OUT)): {'sha256': digest(p), 'bytes': p.stat().st_size}
                for p in sorted(OUT.rglob('*')) if p.is_file() and p.name != 'evidence_manifest.json'}
    (OUT / 'evidence_manifest.json').write_text(json.dumps({'sealed_utc': time.time(), 'files': evidence}, indent=2) + '\n')
    for name in ('DATA_RETENTION.json', 'resources_summary.json', 'verification.json', 'REPRODUCIR.md', 'code_manifest.json', 'evidence_manifest.json'):
        shutil.copy2(OUT / name, DELIVER / name)
    package = DELIVER / 'evidencia_y_reproduccion.zip'
    with zipfile.ZipFile(package, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for path in sorted(OUT.rglob('*')):
            if path.is_file():
                archive.write(path, 'evidence/' + str(path.relative_to(OUT)))
        for path in sorted(HERE.glob('*.py')):
            archive.write(path, 'code/scripts/cascade_lab/experiments/' + path.name)
        for path in [REPO/'data_plane/http1_wire.py', REPO/'scripts/cascade_lab/lab_server.py', REPO/'control_plane/v5_classifier_api.py', REPO/'tests/test_cascade_lab.py', REPO/'tests/test_cascade_experiment_metrics.py']:
            archive.write(path, 'code/' + str(path.relative_to(REPO)))
    (DELIVER / 'bundle_sha256.txt').write_text(digest(package) + '  ' + package.name + '\n')
    print(json.dumps({'report': str(DELIVER/'INFORME.md'), 'bundle_bytes': package.stat().st_size, 'evidence_files': len(evidence)}))


if __name__ == '__main__':
    main()
