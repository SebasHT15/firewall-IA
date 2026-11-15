"""Own one temporary V5 API, GPU lease and private log for a DEV census.

Never starts training, changes a serving deployment, kills another process or
reuses an existing output. The original recipe/runtime defaults are untouched.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import signal
import subprocess
import sys
import time
from urllib.error import URLError
from urllib.request import ProxyHandler, build_opener

from collect_evaluation import population, request_json, service_identity, dump
from train_successor import GPU_STATUS, gpu_available

REPO = Path(__file__).resolve().parents[2]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--protocol', type=Path, required=True)
    ap.add_argument('--adapter', type=Path, required=True)
    ap.add_argument('--recipe', type=Path, required=True)
    ap.add_argument('--profile', type=Path)
    ap.add_argument('--profile-sha256')
    ap.add_argument('--out', type=Path, required=True)
    ap.add_argument('--private-log', type=Path, required=True)
    args = ap.parse_args()
    population(args.protocol, private=True)
    if args.out.exists() or args.private_log.exists():
        raise ValueError('new output and private log required')
    if bool(args.profile) != bool(args.profile_sha256):
        raise ValueError('experimental profile and its explicit hash must be supplied together')
    if args.profile and sha(args.profile) != args.profile_sha256:
        raise ValueError('profile hash mismatch')
    adapter_sha = sha(args.adapter/'adapter_model.safetensors')
    recipe_sha = sha(args.recipe)
    lines = subprocess.check_output(['nvidia-smi', '--query-compute-apps=pid,process_name', '--format=csv,noheader'], text=True).splitlines()
    gpu_available(json.loads(GPU_STATUS.read_text()), lines)
    args.out.mkdir(parents=True)
    args.private_log.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    log = args.private_log.open('x')
    os.chmod(args.private_log, 0o600)
    record = dict(status='STARTED', scope='DEV_INFERENCE_ONLY_NO_TRAINING', adapter_sha256=adapter_sha,
                  recipe_sha256=recipe_sha, runtime_profile_sha256=args.profile_sha256,
                  private_log_path=str(args.private_log.resolve()), protocol_sha256=sha(args.protocol))
    source_files = [Path(__file__), Path(__file__).with_name('collect_evaluation.py'),
                    Path(__file__).with_name('evaluation_metrics.py'), Path(__file__).with_name('verified_suffix.py')]
    source_files += [REPO/'control_plane'/name for name in ('v5_classifier_api.py', 'v5_inference_core.py',
                     'v5_runtime_profile.py', 'v5_output_contract.py', 'v5_tokenization.py')]
    record['source_sha256'] = {str(p.relative_to(REPO)): sha(p) for p in source_files}
    for path in source_files:
        dest = args.out/'executed_sources'/path.relative_to(REPO)
        dest.parent.mkdir(parents=True, exist_ok=True)
        with dest.open('xb') as f:
            f.write(path.read_bytes())
    env = dict(os.environ, HF_HUB_OFFLINE='1', TRANSFORMERS_OFFLINE='1', PYTHONDONTWRITEBYTECODE='1',
               TOKENIZERS_PARALLELISM='false', FIREWALL_V5_ADAPTER_DIR=str(args.adapter.resolve()),
               FIREWALL_V5_RECIPE=str(args.recipe.resolve()))
    for key in ('FIREWALL_V5_RUNTIME_PROFILE', 'FIREWALL_V5_RUNTIME_PROFILE_SHA256', 'FIREWALL_V5_ALLOW_EXPERIMENTAL_RUNTIME'):
        env.pop(key, None)
    if args.profile:
        env.update(FIREWALL_V5_RUNTIME_PROFILE=str(args.profile.resolve()),
                   FIREWALL_V5_RUNTIME_PROFILE_SHA256=args.profile_sha256,
                   FIREWALL_V5_ALLOW_EXPERIMENTAL_RUNTIME='1')
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        port = sock.getsockname()[1]
    GPU_STATUS.write_text(json.dumps(dict(owner='Codex', state='IN_USE_BY_CODEX', pid=os.getpid(), UTC=time.time(),
        task='V5 successor DEV baseline/evaluation; no training', rule='Claude: CPU/doubles only until released'), indent=2)+'\n')
    process = None
    started = time.monotonic()
    def interrupted(signum, frame):
        raise KeyboardInterrupt('evaluation interrupted')
    signal.signal(signal.SIGTERM, interrupted)
    try:
        process = subprocess.Popen([sys.executable, '-B', '-m', 'uvicorn', '--app-dir', 'control_plane',
                                    'v5_classifier_api:app', '--host', '127.0.0.1', '--port', str(port)],
                                    cwd=REPO, env=env, stdout=log, stderr=subprocess.STDOUT)
        opener = build_opener(ProxyHandler({}))
        url = f'http://127.0.0.1:{port}'
        deadline = time.monotonic()+120
        while True:
            if process.poll() is not None:
                raise RuntimeError('owned V5 service exited before readiness; inspect private log')
            try:
                health = request_json(opener, url+'/health', timeout=2)
                if health.get('model_loaded'):
                    break
            except (OSError, URLError):
                pass
            if time.monotonic() >= deadline:
                raise RuntimeError('V5 readiness deadline exceeded')
            time.sleep(.25)
        record['identity'] = service_identity(opener, url, adapter_sha, recipe_sha, args.profile_sha256)
        command = [sys.executable, '-B', str(Path(__file__).with_name('collect_evaluation.py')),
                   '--protocol', str(args.protocol), '--out', str(args.out/'quality-run'),
                   'v5-http', '--url', url, '--adapter-sha256', adapter_sha, '--recipe-sha256', recipe_sha]
        if args.profile_sha256:
            command += ['--profile-sha256', args.profile_sha256]
        completed = subprocess.run(command, cwd=REPO, env=env, check=False)
        if completed.returncode:
            raise RuntimeError('quality collector failed; retain partial evidence')
        changed = [name for name, digest in record['source_sha256'].items() if sha(REPO/name) != digest]
        if changed:
            raise RuntimeError('executed evaluation/model source changed during run')
        record['status'] = 'COMPLETE'
    except BaseException as exc:
        record.update(status='FAILED_OR_INTERRUPTED', error_type=type(exc).__name__)
        raise
    finally:
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=20)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        log.close()
        current = json.loads(GPU_STATUS.read_text())
        if current.get('owner') == 'Codex' and current.get('pid') == os.getpid():
            GPU_STATUS.write_text(json.dumps(dict(owner=None, state='AVAILABLE', UTC=time.time(),
                note='Owned V5 DEV evaluation service stopped; no training run. See successor evaluation report.'), indent=2)+'\n')
        record['duration_s'] = time.monotonic()-started
        dump(args.out/'service-run.json', record)


if __name__ == '__main__':
    main()
