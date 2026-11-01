"""Aggregate only content-free evidence; no inference or private inputs opened."""
import hashlib,json,math
from pathlib import Path

REPO=Path(__file__).resolve().parents[2]
ROOT=REPO/'reports/v5/successor-2026-10-30/verified-suffix'


def percentile(values,q):
    ordered=sorted(values);return ordered[math.ceil(len(ordered)*q)-1]


def main():
    path=ROOT/'comparison.json'
    if path.exists():raise ValueError('Do not overwrite evidence')
    grouped={};runs=[]
    for name in ['full-1','benchmark-2','benchmark-3']:
        directory=ROOT/name;summary=json.loads((directory/'summary.json').read_text())
        records=[json.loads(l) for l in (directory/'records.jsonl').read_text().splitlines()]
        for r in records:
            if r['phase']=='benchmark':grouped.setdefault(r['method'],[]).append(r['elapsed_ms'])
        runs.append(dict(run=name,latency=summary['benchmark_latency'],
                         paired_mismatches=len(summary['paired_mismatch_ids']),
                         reference_mismatches=len(summary['output_mismatch_ids_vs_previous_native']),
                         native_drift=len(summary['fresh_native_drift_ids'])))
    quality=json.loads((ROOT/'full-1/summary.json').read_text())
    http=json.loads((ROOT/'service-final/summary.json').read_text())
    native,verified=http['results']
    current_api=REPO/'control_plane/v5_classifier_api.py'
    old_api=http['source_sha256']['control_plane/v5_classifier_api.py']
    result=dict(schema='v51-verified-suffix-comparison/v1',status='EXPERIMENTAL_DEV_NOT_PRODUCTION_VALIDATION',
                date_local='2026-10-31',timezone='America/Costa_Rica',runs=runs,
                pooled={k:dict(n=len(v),unique_inputs=95,p50_ms=percentile(v,.5),p95_ms=percentile(v,.95),p99_ms=percentile(v,.99)) for k,v in grouped.items()},
                quality=dict(cases=quality['verified_cases'],output_mismatches=quality['output_mismatch_ids_vs_previous_native'],
                             suffix_success=quality['verified_suffix_successes'],native_fallback=quality['native_fallbacks'],
                             content_rejects=quality['verified_cases']-quality['verified_suffix_successes']-quality['native_fallbacks']),
                HTTP=dict(native_cases=native['cases'],verified_cases=verified['cases'],
                          native_pipeline_p95_ms=native['pipeline_p95_ms'],verified_pipeline_p95_ms=verified['pipeline_p95_ms'],
                          native_client_p95_ms=native['client_p95_ms'],verified_client_p95_ms=verified['client_p95_ms'],
                          relative_pipeline_reduction=1-verified['pipeline_p95_ms']/native['pipeline_p95_ms'],
                          mismatch_ids=verified['mismatch_ids'],services_stopped=http['services_stopped']),
                post_HTTP_change=dict(description='Only four optional decoder telemetry response fields added afterwards, tested with doubles; benchmark source snapshots preserved.',
                                      API_sha256_at_HTTP=old_api,API_sha256_current=hashlib.sha256(current_api.read_bytes()).hexdigest()),
                limits=['95 distinct timing requests repeated across three fresh processes, not 285 independent cases',
                        'Quality equality on DEV does not prove equality for every possible input or production security',
                        'Comparison is against NF4 without double quantization, which already differs once from the default on 434 authored cases',
                        'No clock locking/thermal attribution or sustained-load/cascade performance claim',
                        'Native fallback is deliberately retained and may cost more than the original path',
                        'Profile is explicitly experimental; default serving configuration unchanged'])
    path.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result,indent=2))


if __name__=='__main__':main()
