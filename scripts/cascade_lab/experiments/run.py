"""Safe replication entry point. Fresh output/private paths, no training or Git writes.

Run under /usr/bin/python3.12 with --out NEW_REPO_REPORT --private NEW_PRIVATE_DIR.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]


def load_script(name):
    spec = importlib.util.spec_from_file_location('experiment_' + name, HERE / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--out', required=True, type=Path)
    parser.add_argument('--private', required=True, type=Path)
    parser.add_argument('--deliver', required=True, type=Path)
    args = parser.parse_args()
    out, private, deliver = (p.resolve() for p in (args.out, args.private, args.deliver))
    if len({out, private, deliver}) != 3:
        parser.error('Use three different directories.')
    if private.is_relative_to(REPO):
        parser.error('Private request text must remain outside the repository.')
    for path in (out, private, deliver):
        if path.exists():
            parser.error(f'Will not overwrite an existing directory: {path}')
    subprocess.run([
        str(REPO / '.venv-dataplane/bin/python'), '-B', str(HERE / 'prepare.py'),
        '--private', str(private), '--out', str(out),
    ], cwd=REPO, check=True)
    groups = []
    for pattern in ('test_cascade*.py', 'test_http1_wire.py', 'test_model2_policy.py'):
        command = [str(REPO / '.venv-analyzer/bin/python'), '-B', '-m', 'unittest',
                   'discover', '-s', 'tests', '-p', pattern]
        result = subprocess.run(command, cwd=REPO, text=True, capture_output=True)
        log = result.stdout + result.stderr
        (out / ('tests_' + pattern.replace('*', 'all') + '.log')).write_text(log)
        if result.returncode:
            raise RuntimeError('Affected tests failed; no measurements were started.')
        count = int(re.search(r'Ran (\d+) tests?', log).group(1))
        groups.append({'command': command, 'tests': count, 'passed': count})
    (out / 'test_results.json').write_text(json.dumps({
        'groups': groups, 'total': sum(g['tests'] for g in groups), 'failures': 0,
    }, indent=2) + '\n')
    paths = []
    for directory in ('control_plane', 'data_plane', 'scripts/model2', 'scripts/training',
                      'scripts/dataset', 'scripts/cascade_lab'):
        paths.extend((REPO / directory).rglob('*.py'))
    paths.extend((REPO / 'reports/v5/hybrid/cascade-lab/policies').glob('*.json'))
    hashes = {str(p.relative_to(REPO)): {
        'sha256': hashlib.sha256(p.read_bytes()).hexdigest(), 'bytes': p.stat().st_size,
    } for p in sorted(set(paths))}
    (out / 'measurement_source_hashes.json').write_text(json.dumps({'files': hashes}, indent=2) + '\n')
    (out / 'executed_sources').mkdir()
    for name in ('controller.py', 'model_worker.py', 'live.py'):
        shutil.copy2(HERE / name, out / 'executed_sources' / name)
    controller = load_script('controller')
    controller.OUT, controller.PRIVATE = out, str(private / 'inputs.private.jsonl')
    controller.main()
    # The historical service logger may log malformed generated text. Keep the
    # original local, publish only a sanitized log. Request inputs are never copied.
    original = out / 'v5_service.log'
    shutil.copy2(original, private / 'v5_service.private.log')
    os.chmod(private / 'v5_service.private.log', 0o600)
    original.write_text(''.join(line.split(' raw=', 1)[0] + ' raw=[omitted]\n'
                                if ' raw=' in line else line
                                for line in original.read_text().splitlines(keepends=True)))
    for name in ('analyze', 'figures', 'verify', 'report'):
        script = load_script(name)
        script.OUT = out
        if name == 'figures':
            script.FIG = out / 'figures'
            script.FIG.mkdir(exist_ok=True)
        if name == 'report':
            script.DELIVER = deliver
        try:
            script.main()
        except SystemExit as exc:
            if exc.code not in (None, 0):
                raise


if __name__ == '__main__':
    main()
