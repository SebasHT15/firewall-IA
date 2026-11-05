"""New local Docker application experiment. No fitting or protected input reader.

Prepare -> direct positive/benign controls -> actual V5 and cascade -> offline
Chromium response execution -> payload-free evidence. No existing files edited.
"""
import argparse
from collections import Counter
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
from types import SimpleNamespace
import urllib.parse

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
OPS = REPO / 'scripts/gateway_ops'
sys.path[:0] = [str(HERE), str(OPS), str(REPO / 'data_plane')]
import population as P
import live_stack as L
import real_check as R
import candidate_walkthrough as W
import candidate_check as CK
import fault_proxy as FP

COORD = Path('/home/sebas/Documents/Codex/2026-10-26/ta/outputs/Coordinacion_modelos_arquitectura')
APP_IMAGE = 'firewall-ia/lab-app:lab'
BROWSER_IMAGE = 'firewall-ia/generator:lab'
PYTHON_IMAGE = 'python:3.12-slim'
CONFIGS = [('native', 'V5_ONLY'), ('native', 'CASCADE_ACTIVE'),
           ('verified', 'CASCADE_ACTIVE'), ('verified', 'V5_ONLY')]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write(path, doc):
    path = Path(path)
    with path.open('x') as fh:
        json.dump(doc, fh, indent=2, sort_keys=True)
        fh.write('\n')


def readlines(path):
    return [json.loads(x) for x in Path(path).read_text().splitlines() if x.strip()] if Path(path).exists() else []


def docker(*args, **kw):
    return subprocess.check_output(['docker', *map(str, args)], text=True, **kw).strip()


def gpu_apps():
    raw = subprocess.check_output(['nvidia-smi', '--query-compute-apps=pid,process_name,used_memory',
                                   '--format=csv,noheader,nounits'], text=True)
    return [line for line in raw.splitlines() if line.rsplit(',', 1)[-1].strip().isdigit()
            and int(line.rsplit(',', 1)[-1].strip()) >= 300]


def acquire_gpu(out):
    if gpu_apps():
        raise RuntimeError('Foreign GPU workload: do not stop it')
    old = json.loads((COORD / 'GPU_STATUS.json').read_text())
    write(out / 'GPU_STATUS.before.json', old)
    if old.get('state') not in ('AVAILABLE', 'AVAILABLE_FOR_CLAUDE', 'AVAILABLE_FOR_CODEX'):
        raise RuntimeError('GPU not available')
    (COORD / 'GPU_STATUS.json').write_text(json.dumps(dict(owner='Codex', state='IN_USE_BY_CODEX',
        UTC=time.time(), note='Sebas explicitly requested real Docker traffic evaluation on 2026-11-02. '
        'V51 experiment; no training. See ' + str(out)), indent=2) + '\n')


def release_gpu(out):
    current = json.loads((COORD / 'GPU_STATUS.json').read_text())
    if current.get('owner') == 'Codex' and str(out) in current.get('note', ''):
        (COORD / 'GPU_STATUS.json').write_text(json.dumps(dict(owner='none', state='AVAILABLE', UTC=time.time(),
            note='Codex Docker traffic evaluation ended; its V5 and gateway processes stopped. '
                 'No training. Evidence: ' + str(out)), indent=2) + '\n')


class DockerLab:
    def __init__(self, work, run_id):
        self.work, self.tag = Path(work), 'fwia-v51-' + run_id
        self.port = 9100
        existing = json.loads(docker('network', 'inspect', *docker('network', 'ls', '-q').split()))
        networks = [ipaddress.ip_network(c['Subnet']) for n in existing for c in (n.get('IPAM', {}).get('Config') or [])
                    if c.get('Subnet')]
        self.subnet = next(ipaddress.ip_network(f'172.30.{i}.0/24') for i in range(81, 150)
                           if not any(ipaddress.ip_network(f'172.30.{i}.0/24').overlaps(n)
                                      for n in networks if n.version == 4))
        self.callback_ip = str(self.subnet.network_address + 3)
        self.app_ip = str(self.subnet.network_address + 2)
        self.containers = []
        self.network_created = False

    def start(self):
        self.work.mkdir(parents=True, exist_ok=True)
        os.chmod(self.work, 0o777)  # disposable evidence only; image user has no host home access
        docker('network', 'create', '--internal', '--subnet', self.subnet, self.tag)
        self.network_created = True
        common = ['--network', self.tag, '--read-only', '--cap-drop', 'ALL',
                  '--security-opt', 'no-new-privileges', '--pids-limit', '128', '--memory', '256m',
                  '--cpus', '1', '--tmpfs', '/tmp:rw,nosuid,noexec,size=64m', '--user', '1000:1000',
                  '-v', f'{HERE}:/evaluation:ro', '-v', f'{self.work}:/evidence:rw']
        callback = self.tag + '-callback'
        docker('run', '-d', '--name', callback, *common, '--ip', self.callback_ip,
               '--network-alias', 'assets.fwlab.test', PYTHON_IMAGE,
               'python3', '/evaluation/callback.py')
        self.containers.append(callback)
        target = self.tag + '-app'
        docker('run', '-d', '--name', target, *common, '--ip', self.app_ip, '--network-alias', 'shop.fwlab.test',
               '-e', f'CALLBACK_IP={self.callback_ip}',
               '-e', 'ACCESS_LOG=/evidence/shop-receipts.jsonl', APP_IMAGE,
               'python3', '/evaluation/target.py')
        self.containers.append(target)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            status, _ = L.http_get(f'http://{self.app_ip}:{self.port}/', timeout=1)
            if status == 200:
                break
            time.sleep(.1)
        else:
            raise RuntimeError('Docker application not ready')
        net = json.loads(docker('network', 'inspect', self.tag))[0]
        container = json.loads(docker('inspect', target))[0]
        routes = docker('exec', target, 'cat', '/proc/net/route')
        if not net['Internal'] or any(line.split()[1] == '00000000' for line in routes.splitlines()[1:]):
            raise RuntimeError('Target has an outbound default route')
        image_source_sha = docker('exec', target, 'python3', '-c',
                                  "import hashlib;print(hashlib.sha256(open('/srv/app.py','rb').read()).hexdigest())")
        if image_source_sha != sha(REPO / 'docker/lab-app/app.py'):
            raise RuntimeError('Existing image app source mismatch')
        return dict(network=net, container=container, routes=routes, original_shop_sha256=image_source_sha,
                    images={image: json.loads(docker('image', 'inspect', image))[0]['Id']
                            for image in (APP_IMAGE, BROWSER_IMAGE, PYTHON_IMAGE)})

    def stop(self):
        for name in reversed(self.containers):
            logs = subprocess.run(['docker', 'logs', name], capture_output=True, text=True)
            (self.work / (name + '.console.log')).write_text(logs.stdout + logs.stderr)
            subprocess.run(['docker', 'rm', '-f', name], capture_output=True)
        if self.network_created:
            subprocess.run(['docker', 'network', 'rm', self.tag], capture_output=True)


def request(port, raw, host='127.0.0.1'):
    start = time.perf_counter()
    with socket.create_connection((host, port), timeout=15) as sock:
        sock.settimeout(15)
        sock.sendall(raw)
        response = http.client.HTTPResponse(sock)
        response.begin()
        body = response.read()
        status, headers = response.status, response.getheaders()
    return dict(status=status, headers=headers, body=body.decode('utf-8', errors='replace'),
                client_ms=(time.perf_counter()-start)*1000,
                response_sha256=hashlib.sha256(body).hexdigest())


def effect(case, response):
    if case['label'] != 'BLOCK':
        return None
    body, kind = response['body'], case['oracle']
    if kind == 'secret':
        return case['expected'] in body
    if kind == 'exact_body':
        return body.strip() == case['expected']
    if kind == 'external_location':
        return (response['status'] in (301, 302, 303, 307, 308) and
                urllib.parse.urlsplit(dict((k.lower(), v) for k, v in response['headers']).get('location', '')).hostname
                == case['expected'])
    if kind == 'browser_script':
        return None  # evaluated using Chromium, never by searching the reflected text
    raise ValueError(kind)


class AppStack(L.Stack):
    """Use unchanged gateway/guard/workers with our actual Docker origin, no sink."""
    def __init__(self, *args, origin_port, origin_host, **kw):
        super().__init__(*args, **kw)
        self.sink_port = origin_port
        self.origin_host = origin_host

    def start_sink(self):
        pass

    def start_doubles(self):
        pass  # neither V4 nor any model double belongs to this experiment

    def write_config(self):
        path = super().write_config()
        doc = json.loads(Path(path).read_text())
        doc['cascade_gateway']['framing']['egress_guard']['upstream_host'] = self.origin_host
        Path(path).write_text(json.dumps(doc, indent=2)+'\n')
        return path

    def start(self):
        try:
            self.start_gateway()
            self.wait_port(self.listen_port)
        except BaseException:
            self.stop()
            raise


def run_cases(cases, ids, port, app_log, *, mode, stack=None, proxy=None, out, work, host='127.0.0.1'):
    index = {c['id']: c for c in cases}
    cookies, results = {}, []
    tail = R.Tail(str(Path(stack.workdir) / 'decisions.jsonl')) if stack else None
    if tail:
        tail.read()
    with Path(out).open('x') as public, Path(work).open('x') as private:
        for n, cid in enumerate(ids):
            case = index[cid]
            token = mode + ':' + cid
            raw = P.wire(case, token=token, cookie=cookies.get(case['session'], ''))
            calls_before = proxy.classify_calls if proxy else 0
            response = request(port, raw, host=host)
            if case['session']:
                jar = {x.split('=', 1)[0]: x for x in cookies.get(case['session'], '').split('; ') if '=' in x}
                for key, value in response['headers']:
                    if key.lower() == 'set-cookie':
                        part = value.split(';', 1)[0]
                        jar[part.split('=', 1)[0]] = part
                cookies[case['session']] = '; '.join(jar.values())
            record = None
            if tail:
                records = []
                deadline = time.monotonic()+2
                while time.monotonic() < deadline:
                    records += tail.read()
                    found = [r for r in records if r.get('kind') == 'decision']
                    if found:
                        if len(found) != 1:
                            raise RuntimeError('Ambiguous decision-to-request mapping')
                        record = found[0]
                        break
                    time.sleep(.005)
                if record is None:
                    raise RuntimeError('Missing gateway decision evidence')
            receipts = [r for r in readlines(app_log) if r.get('id') == token]
            if len(receipts) > 1:
                raise RuntimeError('Duplicate app receipt')
            receipt = receipts[0] if receipts else None
            v5 = {**((record or {}).get('v5') or {}), **((record or {}).get('v5_service') or {})}
            actual_can = proxy.canonical_sha256 if proxy and proxy.classify_calls > calls_before else None
            expected_can = hashlib.sha256(P.canonical(case).encode()).hexdigest()
            row = dict(**P.public_case(case), configuration=mode, http_status=response['status'],
                       client_ms=response['client_ms'], response_sha256=response['response_sha256'],
                       received=bool(receipt), receipt_count=len(receipts),
                       received_request_matches=(receipt['method'] == case['method']
                           and receipt['raw_target'] == case['target']
                           and receipt['body_sha256'] == hashlib.sha256(case['body'].encode()).hexdigest()) if receipt else None,
                       actual_can_sha256=actual_can,
                       canonical_matches=actual_can == expected_can if actual_can else None,
                       effect=effect(case, response),
                       record=record, model2=(record or {}).get('model2'), v5=v5)
            if actual_can and actual_can != expected_can:
                raise RuntimeError('Canonical roundtrip mismatch: ' + cid)
            if receipt and (not row['received_request_matches'] or receipt['response_sha256'] != response['response_sha256']):
                raise RuntimeError('Application/request/response integrity mismatch: ' + cid)
            if record and ((record['applied'] == 'FORWARD') != bool(receipt)):
                raise RuntimeError('Enforcement vs application receipt mismatch: ' + cid)
            if record and record['applied'] == 'DENY' and response['status'] not in (403, 413, 422, 501, 503):
                raise RuntimeError('Unexpected denial status')
            public.write(json.dumps(row, sort_keys=True)+'\n')
            public.flush()
            private.write(json.dumps(dict(id=cid, response=response, request_sha256=hashlib.sha256(raw).hexdigest()),
                                     sort_keys=True)+'\n')
            private.flush()
            results.append(row)
            if (n+1) % 100 == 0:
                print(f'{mode}: {n+1}/{len(ids)}', flush=True)
    return results


def browser_effects(cases, rows, private_responses, out):
    responses = {r['id']: r['response'] for r in readlines(private_responses)}
    index = {c['id']: c for c in cases}
    selected = [r for r in rows if r['oracle'] == 'browser_script' and r['received']]
    payload = ''.join(json.dumps(dict(id=r['id'], expected=index[r['id']]['expected'],
                                     html=responses[r['id']]['body']))+'\n' for r in selected)
    if selected:
        proc = subprocess.run(['docker', 'run', '--rm', '-i', '--network', 'none', '--read-only',
            '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges', '--pids-limit', '256',
            '--memory', '768m', '--shm-size', '256m', '--tmpfs', '/tmp:rw,nosuid,size=256m',
            '-v', f'{HERE}:/evaluation:ro', BROWSER_IMAGE, 'python3', '/evaluation/browser_oracle.py'],
            input=payload, text=True, capture_output=True, timeout=180)
        if proc.returncode:
            raise RuntimeError('Browser oracle failed: ' + proc.stderr[-1500:])
        found = [json.loads(line) for line in proc.stdout.splitlines() if line.startswith('{')]
        if {r['id'] for r in found} != {r['id'] for r in selected}:
            raise RuntimeError('Missing browser effect observations')
    else:
        found = []
    write(out, dict(schema='offline-chromium-response-execution/v1', rows=found,
          scope='Actual HTTP response document executed in Chromium with network NONE. '
                'No full browser navigation, user interaction or exfiltration measured.'))


def source_inventory():
    paths = list(HERE.glob('*.py'))
    paths += list((REPO / 'scripts/gateway_ops').glob('*.py'))
    paths += list((REPO / 'data_plane').glob('*.py'))
    paths += list((REPO / 'control_plane').glob('v5_*.py'))
    paths += [REPO / 'docker/lab-app/app.py', REPO / 'scripts/v5_successor/verified_suffix.py',
              REPO / 'scripts/v5_successor/evaluation_metrics.py']
    return {str(p.relative_to(REPO)): sha(p) for p in sorted(set(paths))}


def check_identity(manifest, url=None):
    checked, model = CK.check(SimpleNamespace(manifest=str(manifest), previous=[],
                              gateway_config=None, v5_url=url))
    result = dict(status='REFUSED' if checked.failed else 'IDENTITY_CONSISTENT',
                  checks=checked.checks, failed=checked.failed, manifest_sha256=model.sha256 if model else None,
                  service_compared=url is not None)
    if checked.failed:
        raise RuntimeError(result)
    return result


def run(args):
    out, work = Path(args.out).resolve(), Path(args.work).resolve()
    out.mkdir(parents=True, exist_ok=False)
    work.mkdir(parents=True, exist_ok=False)
    lab = DockerLab(work / 'app', args.run_id)
    cases = P.population(lab.callback_ip)
    ids = P.order(cases)
    manifests = {name: REPO / f'reports/v5/successor-post-training-2026-11-01/cascade-{name}.EXPERIMENTAL.json'
                 for name in ('native', 'verified')}
    contract = json.loads((COORD / 'CONTRATO_DE_TRABAJO.json').read_text())
    inventory = source_inventory()
    immutable = contract['immutable_model2_bound_sources']
    if any(sha(REPO / p) != h for p, h in immutable.items()):
        raise RuntimeError('Immutable source changed before experiment')
    for manifest in manifests.values():
        check_identity(manifest)
    with (out / 'cases.jsonl').open('x') as fh, (work / 'cases.private.jsonl').open('x') as private:
        for case in cases:
            fh.write(json.dumps(P.public_case(case), sort_keys=True)+'\n')
            private.write(json.dumps(case, sort_keys=True)+'\n')
    protocol = dict(schema='v51-docker-application-development/v1', seed=P.SEED, created_utc=time.time(),
        authorization='Sebas requested real Docker application traffic and recorded ML metrics/figures in this chat, 2026-11-02.',
        scope='New own synthetic DEV traffic over actual HTTP/1.1 through real models and gateway, '
              'to an isolated disposable Docker application. Not production traffic or independent final evaluation.',
        protected_inputs_used=False, training=False, fast_path='disabled: no approved application contract',
        v4_used=False, model2_threshold=.9, threshold_status='unchanged LAB_EXPERIMENTAL',
        case_counts=dict(Counter(c['label'] for c in cases)), family_counts=dict(Counter(c['family'] for c in cases)),
        unique_canonical=len({P.public_case(c)['canonical_sha256'] for c in cases}),
        known_regressions_excluded_from_new_DEV_headline=True,
        configurations=CONFIGS, order=ids, cases_sha256=sha(out / 'cases.jsonl'),
        private_cases_sha256=sha(work / 'cases.private.jsonl'),
        source_hashes=inventory, immutable_sources=immutable,
        manifests={n: dict(path=str(p.relative_to(REPO)), sha256=sha(p)) for n, p in manifests.items()},
        effect_denominator='BLOCK cases whose predeclared oracle succeeds in the direct, no-firewall control. '
            'Ineffective controls remain in classification results and are listed separately.',
        classification='E5 principal counts invalid as error in true class; parseable-only separate; '
            'observed denial/receipt/effect are independent views.',
        latency='Closed-loop sequential quality pass, not sustained capacity; cold readiness and 10 warmup requests excluded.',
        uncertainty='1000 component bootstrap resamples sessions/payload templates; synthetic families correlated, '
            'intervals descriptive and do not certify Internet traffic.',
        gaps=['No TLS/HTTP2', 'No JWT/CSRF state', 'No WAF evasion exhaustive search',
              'No production Fast Path', 'Own vulnerable fixtures do not establish real-world generalization'])
    write(out / 'PROTOCOL.json', protocol)  # sealed before direct or candidate requests
    gpu_owned = False
    try:
        isolation = lab.start()
        write(work / 'isolation.private.json', isolation)
        write(out / 'ISOLATION.json', {k: isolation[k] for k in ('images', 'routes', 'original_shop_sha256')}
              | dict(internal_network=isolation['network']['Internal'], subnet=str(lab.subnet),
                     publish='none; host gateway connects to internal bridge IP', read_only=True,
                     caps='ALL dropped', host_data='synthetic evidence mount only'))
        direct_file, direct_private = out / 'DIRECT.jsonl', work / 'DIRECT.responses.jsonl'
        direct = run_cases(cases, ids, lab.port, work / 'app/application.jsonl', mode='DIRECT',
                           out=direct_file, work=direct_private, host=lab.app_ip)
        browser_effects(cases, direct, direct_private, out / 'DIRECT.browser.json')
        if args.controls_only:
            write(out / 'CONTROL_PILOT.json', dict(status='DIRECT_CONTROLS_ONLY_NO_MODEL_EVALUATION'))
            return
        acquire_gpu(out)
        gpu_owned = True
        for runtime in ('native', 'verified'):
            if gpu_apps():
                raise RuntimeError('Foreign model before service startup')
            service_work = work / runtime
            service_work.mkdir()
            service_args = SimpleNamespace(doubles=False, manifest=str(manifests[runtime]), work=str(service_work))
            service = W.V5Service(service_args)
            proxy = None
            service.start()
            try:
                service.wait()
                checked = check_identity(manifests[runtime], service.url)
                write(out / f'{runtime}.identity.json', checked)
                proxy = FP.FaultProxy(service.url)
                for _, mode in [c for c in CONFIGS if c[0] == runtime]:
                    name = runtime + '-' + mode
                    stack = AppStack(str(work / name), mode=mode, manifest=str(manifests[runtime]),
                        v5_url=proxy.url, v4_url=W.UNUSED_V4, origin_port=lab.port, origin_host=lab.app_ip,
                        config_overrides=dict(v5_timeout=3, deadline=5, max_inflight=8, max_waiting=16,
                                              probe_interval=2, worker_backoff=2))
                    try:
                        stack.start()
                        stack.wait_ready(timeout=30, require_cascade=True)
                        for i in range(10):
                            request(stack.listen_port, P.wire(cases[0], token=f'warmup-{name}-{i}'))
                        rows = run_cases(cases, ids, stack.listen_port, work / 'app/application.jsonl',
                                         mode=name, stack=stack, proxy=proxy, out=out / f'{name}.jsonl',
                                         work=work / f'{name}.responses.jsonl')
                        write(out / f'{name}.final-status.json', stack.status())
                        browser_effects(cases, rows, work / f'{name}.responses.jsonl', out / f'{name}.browser.json')
                    finally:
                        stack.stop()
            finally:
                if proxy:
                    proxy.close()
                service.stop()
        now = source_inventory()
        changed = [p for p, h in inventory.items() if now.get(p) != h]
        immutable_changed = [p for p, h in immutable.items() if sha(REPO / p) != h]
        if changed or immutable_changed:
            raise RuntimeError('Source drift during measurement')
        write(out / 'COMPLETION.json', dict(status='COMPLETE', finished_utc=time.time(),
              sources_changed=changed, immutable_sources_changed=immutable_changed,
              immutable_sources_checked=len(immutable), source_hashes_at_end=now,
              no_staging=subprocess.run(['git', 'diff', '--cached', '--quiet'], cwd=REPO).returncode == 0,
              protected_inputs=False, training=False))
    except BaseException as exc:
        write(out / 'FAILURE.json', dict(status='INCOMPLETE', error=type(exc).__name__, detail=str(exc)))
        raise
    finally:
        lab.stop()
        if gpu_owned:
            release_gpu(out)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--out', required=True)
    parser.add_argument('--work', required=True)
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--controls-only', action='store_true')
    run(parser.parse_args())
