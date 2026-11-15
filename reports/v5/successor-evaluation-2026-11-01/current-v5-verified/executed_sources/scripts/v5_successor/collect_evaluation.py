"""Collect paired DEV scores from an existing V5 API or FINAL Model2 artifact.

Does not start services, allocate GPU or train. HTTP defaults to loopback only.
Every run uses a new directory and pins its exact population and model identity.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, Request, build_opener

from evaluation_metrics import checked_predictions, probability_metrics, report, paired_comparison

REPO = Path(__file__).resolve().parents[2]


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def load_bound(desc):
    raw = Path(desc['path']).read_bytes()
    if digest(raw) != desc['sha256']:
        raise ValueError('bound evaluation input changed')
    return raw


def read_jsonl(raw):
    return [json.loads(x) for x in raw.splitlines() if x.strip()]


def population(protocol_path, *, private=False):
    protocol = json.loads(protocol_path.read_bytes())
    if protocol.get('schema') != 'v51-post-training-dev-evaluation/v1' or protocol.get('scope') != 'DEVELOPMENT_ONLY_NOT_FINAL_EVALUATION':
        raise ValueError('unknown evaluation protocol')
    public = read_jsonl(load_bound(protocol['cases_public']))
    if private:
        cases = read_jsonl(load_bound(protocol['cases_private']))
        if [{k: v for k, v in c.items() if k != 'canonical_text'} for c in cases] != public:
            raise ValueError('public/private cohort mismatch')
        for c in cases:
            if digest(c['canonical_text'].encode()) != c['canonical_sha256']:
                raise ValueError('private canonical text changed')
    else:
        cases = public
    checked_predictions(cases, [dict(id=c['id'], canonical_sha256=c['canonical_sha256'], status='invalid') for c in cases])
    return protocol, cases


def dump(path, obj):
    with path.open('x', encoding='utf-8') as f:
        json.dump(obj, f, indent=2, ensure_ascii=False, allow_nan=False)
        f.write('\n')


def request_json(opener, url, *, body=None, timeout=30):
    req = Request(url, data=json.dumps(body).encode() if body is not None else None,
                  headers={'Content-Type': 'application/json'})
    with opener.open(req, timeout=timeout) as response:
        return json.load(response)


def service_identity(opener, url, adapter_sha, recipe_sha, profile_sha):
    health = request_json(opener, url+'/health')
    contract = request_json(opener, url+'/contract')
    if health.get('model_loaded') is not True or health.get('adapter_sha256') != adapter_sha:
        raise ValueError('V5 adapter readiness/identity mismatch')
    if contract.get('recipe_sha256') != recipe_sha:
        raise ValueError('V5 recipe identity mismatch')
    profile = health.get('runtime_profile')
    actual_profile = profile.get('sha256') if profile else None
    if actual_profile != profile_sha:
        raise ValueError('V5 runtime profile mismatch; no implicit profile adoption')
    return dict(health=health, contract=contract)


def collect_http(cases, *, url, adapter_sha, recipe_sha, profile_sha, out, warmup=4, timeout=30):
    parsed = urlsplit(url)
    if parsed.scheme != 'http' or parsed.hostname not in ('127.0.0.1', 'localhost', '::1') or parsed.path not in ('', '/') or parsed.query or parsed.fragment or parsed.username:
        raise ValueError('only an existing loopback HTTP V5 API is allowed')
    url = url.rstrip('/')
    opener = build_opener(ProxyHandler({}))
    before = service_identity(opener, url, adapter_sha, recipe_sha, profile_sha)
    # Warmup is operational only, using the same eligible cohort, not extra data.
    with (out/'warmup.jsonl').open('x') as f:
        for c in cases[:warmup]:
            start = time.perf_counter()
            request_json(opener, url+'/classify', body={'canonical_request': c['canonical_text']}, timeout=timeout)
            f.write(json.dumps(dict(id=c['id'], phase='warmup', roundtrip_ms=(time.perf_counter()-start)*1000))+'\n')
    predictions = []
    with (out/'predictions.jsonl').open('x') as f:
        for c in cases:
            start = time.perf_counter()
            error = None
            try:
                response = request_json(opener, url+'/classify', body={'canonical_request': c['canonical_text']}, timeout=timeout)
            except HTTPError as exc:
                response = dict(status='service_error', invalid_reason=f'http_{exc.code}')
                error = f'http_{exc.code}'
            except (URLError, TimeoutError, OSError) as exc:
                response = dict(status='transport_error', invalid_reason=type(exc).__name__)
                error = type(exc).__name__
            # Only closed contract fields are retained, never raw replies/errors.
            fields = ('status', 'decision', 'reason', 'invalid_reason', 'pipeline_ms', 'queue_wait_ms',
                      'service_ms', 'generate_ms', 'prompt_tokens', 'generated_tokens', 'ended_with_eos',
                      'decoder_verified', 'decoder_fallback')
            prediction = {k: response[k] for k in fields if k in response}
            prediction.update(id=c['id'], canonical_sha256=c['canonical_sha256'], phase='quality',
                              roundtrip_ms=(time.perf_counter()-start)*1000)
            if prediction.get('status') == 'ok':
                full = str(prediction.get('decision'))+' | '+str(prediction.get('reason'))
                if prediction.get('ended_with_eos') is not True or full not in before['contract']['vocabulary']:
                    prediction.update(status='invalid', decision=None, invalid_reason='api_contract_violation')
            predictions.append(prediction)
            f.write(json.dumps(prediction, allow_nan=False)+'\n')
            f.flush()
            if error:
                # Do not continue a quality census through a broken service and
                # silently turn availability failures into model quality data.
                raise RuntimeError('service/transport failed; partial evidence retained, run not COMPLETE')
    after = service_identity(opener, url, adapter_sha, recipe_sha, profile_sha)
    if before != after:
        # Health load-time fields are stable; live counters are not in this API.
        raise ValueError('service identity changed during evaluation')
    return predictions, dict(before=before, after=after)


def collect_model2(cases, artifact_path, artifact_sha, out):
    sys.path.insert(0, str(REPO))
    from scripts.model2 import training as M2
    artifact = M2.load_artifact(str(artifact_path), expected_sha256=artifact_sha)
    predictions = []
    with (out/'predictions.jsonl').open('x') as f:
        for c in cases:
            start = time.perf_counter()
            probability = M2.score(artifact, c['canonical_text'])
            prediction = dict(id=c['id'], canonical_sha256=c['canonical_sha256'], status='OK',
                              p_block=probability, score_ms=(time.perf_counter()-start)*1000)
            predictions.append(prediction)
            f.write(json.dumps(prediction, allow_nan=False)+'\n')
    return predictions, dict(artifact_sha256=artifact_sha, feature_view=artifact['feature_view'])


def counterfactual(cases, v5, model2, threshold):
    a, b = checked_predictions(cases, v5), checked_predictions(cases, model2)
    if not 0 < threshold <= 1:
        raise ValueError('invalid threshold')
    result = []
    for c, p, q in zip(cases, a, b):
        if q.get('status') == 'OK' and type(q.get('p_block')) in (int, float) and 0 <= q['p_block'] <= 1 and q['p_block'] >= threshold:
            result.append(dict(id=c['id'], canonical_sha256=c['canonical_sha256'], status='ok',
                               decision='BLOCK', invalid_reason=None, deciding_stage='model2'))
        else:
            result.append({**p, 'deciding_stage': 'v5'})
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--protocol', type=Path, required=True)
    ap.add_argument('--out', type=Path, required=True)
    sub = ap.add_subparsers(dest='mode', required=True)
    http = sub.add_parser('v5-http')
    http.add_argument('--url', required=True)
    http.add_argument('--adapter-sha256', required=True)
    http.add_argument('--recipe-sha256', required=True)
    http.add_argument('--profile-sha256')
    m2 = sub.add_parser('model2')
    m2.add_argument('--artifact', type=Path, required=True)
    m2.add_argument('--artifact-sha256', required=True)
    analyze = sub.add_parser('analyze')
    analyze.add_argument('--predictions', type=Path, required=True)
    analyze.add_argument('--baseline-predictions', type=Path)
    combine = sub.add_parser('counterfactual')
    combine.add_argument('--v5-predictions', type=Path, required=True)
    combine.add_argument('--model2-predictions', type=Path, required=True)
    combine.add_argument('--threshold', type=float, required=True)
    args = ap.parse_args()
    protocol, cases = population(args.protocol, private=args.mode in ('v5-http', 'model2'))
    if args.out.exists():
        raise ValueError('output exists; historical evidence must not be overwritten')
    args.out.mkdir(parents=True)
    record = dict(status='STARTED', mode=args.mode, scope='DEVELOPMENT_ONLY',
                  protocol_sha256=digest(args.protocol.read_bytes()), cases=len(cases),
                  protected_sets_used=False, reserve_opened=False,
                  sources={str(p.relative_to(REPO)): digest(p.read_bytes()) for p in
                           [Path(__file__), Path(__file__).with_name('evaluation_metrics.py')]})
    try:
        if args.mode == 'v5-http':
            predictions, identity = collect_http(cases, url=args.url, adapter_sha=args.adapter_sha256,
                recipe_sha=args.recipe_sha256, profile_sha=args.profile_sha256, out=args.out)
            record['identity'] = identity
        elif args.mode == 'model2':
            predictions, identity = collect_model2(cases, args.artifact, args.artifact_sha256, args.out)
            record['identity'] = identity
            checked_predictions(cases, predictions)
            summaries = {}
            for cohort in sorted({c['cohort'] for c in cases}):
                subcases = [c for c in cases if c['cohort'] == cohort]
                index = {p['id']: p for p in predictions}
                summaries[cohort] = probability_metrics(subcases, [index[c['id']] for c in subcases], protocol['thresholds_descriptive_only'])
            dump(args.out/'model2-selective.json', summaries)
        elif args.mode == 'analyze':
            predictions = read_jsonl(args.predictions.read_bytes())
            record['input_predictions_sha256'] = digest(args.predictions.read_bytes())
        else:
            v5 = read_jsonl(args.v5_predictions.read_bytes())
            m2p = read_jsonl(args.model2_predictions.read_bytes())
            predictions = counterfactual(cases, v5, m2p, args.threshold)
            record.update(provenance='COUNTERFACTUAL_NO_FAST_PATH_NOT_MEASURED_GATEWAY', threshold=args.threshold,
                          v5_predictions_sha256=digest(args.v5_predictions.read_bytes()),
                          model2_predictions_sha256=digest(args.model2_predictions.read_bytes()))
            with (args.out/'predictions.jsonl').open('x') as f:
                f.writelines(json.dumps(p)+'\n' for p in predictions)
        if args.mode != 'model2':
            dump(args.out/'quality.json', report(cases, predictions, bootstrap_replicates=protocol['bootstrap_replicates']))
        if args.mode == 'analyze' and args.baseline_predictions:
            baseline = read_jsonl(args.baseline_predictions.read_bytes())
            comparisons = {}
            for cohort in sorted({c['cohort'] for c in cases}):
                subcases = [c for c in cases if c['cohort'] == cohort]
                ids = {c['id'] for c in subcases}
                comparisons[cohort] = paired_comparison(subcases, [p for p in baseline if p['id'] in ids],
                    [p for p in predictions if p['id'] in ids], replicates=protocol['bootstrap_replicates'])
            record['baseline_predictions_sha256'] = digest(args.baseline_predictions.read_bytes())
            dump(args.out/'paired-comparison.json', comparisons)
        record['status'] = 'COMPLETE'
    except Exception as exc:
        record.update(status='FAILED_PARTIAL_NOT_A_COMPLETE_CENSUS', error_type=type(exc).__name__)
        raise
    finally:
        dump(args.out/'run.json', record)
    print(json.dumps(record, indent=2))


if __name__ == '__main__':
    main()
