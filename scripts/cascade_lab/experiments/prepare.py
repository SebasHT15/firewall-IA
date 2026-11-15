"""Freeze DEVELOPMENT-only experiment inputs. Private text stays outside the repo."""
import sys, os, json, hashlib, random, collections, argparse, time, importlib.util
from pathlib import Path
REPO=Path(__file__).resolve().parents[3]
sys.path[:0]=[str(REPO/'data_plane'),str(REPO)]
import http1_wire as W
import cascade_runtime as RT
from scripts.evaluation import paired_dev_set as PD
from scripts.cascade_lab.make_dev_sample import to_wire
from mitmproxy import http
spec=importlib.util.spec_from_file_location('native_gateway', REPO/'data_plane/data_plane.py')
native=importlib.util.module_from_spec(spec); sys.modules[spec.name]=native; spec.loader.exec_module(native)
def sha(b): return hashlib.sha256(b).hexdigest()
def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--private',required=True); ap.add_argument('--out',required=True); args=ap.parse_args()
    private=Path(args.private); out=Path(args.out); private.mkdir(parents=True,exist_ok=True); out.mkdir(parents=True,exist_ok=True)
    source=REPO/'reports/v5/hybrid/cascade-lab/dev_sample_v1.jsonl'
    rows=[dict(json.loads(l),cohort='legacy_dev',pair_id=None,placement='unknown',family=None) for l in source.read_text().splitlines()]
    paired,problems=PD.generate(); assert not problems,problems
    for p in paired:
        rows.append(dict(id='paired-'+p['case_id'],wire=to_wire(p['request_text']),label=p['label'], category=p['oracle_reason'],cohort='authored_paired_dev',pair_id=p['pair_id'],placement=p['placement'],family=p['family'],placement_variant=p['placement_variant'],group_id=p['group_id'],oracle_reason=p['oracle_reason']))
    manifest=[]
    for r in rows:
        wire=r['wire'].encode('utf8'); r['wire_sha256']=sha(wire)
        try:
            w=W.parse_request(wire); assert not w.leftover
            snap=RT.build_snapshot(w.parts,w.framing,RT.v5_limits(415))
            r['wire_ok']=True; r['canonical_outcome']=snap.canonical.outcome; r['canonical_text']=snap.canonical.text
            parts=w.parts
            req=http.Request(host='lab.invalid',port=80,method=parts.method,scheme=b'http',authority=b'',path=parts.target,http_version=parts.http_version.encode(),headers=parts.headers,content=parts.body,trailers=None,timestamp_start=0,timestamp_end=0)
            r['v4_text']=native.render_request(req)
            r['canonical_sha256']=sha((r['canonical_text'] or '').encode()); r['v4_text_sha256']=sha(r['v4_text'].encode())
        except W.WireError as e:
            r.update(wire_ok=False,wire_reason=e.reason,canonical_outcome=None)
        manifest.append({k:v for k,v in r.items() if k not in ('wire','canonical_text','v4_text','oracle_reason')})
    eligible=[r for r in rows if r['cohort']=='legacy_dev' and r.get('canonical_outcome')=='ACCEPT']
    rng=random.Random(20261030); strata=collections.defaultdict(list)
    for r in eligible: strata[(r['label'],r['category'])].append(r['id'])
    for x in strata.values(): rng.shuffle(x)
    bench=[]
    while len(bench)<96:
        for key in sorted(strata):
            if strata[key] and len(bench)<96: bench.append(strata[key].pop())
    rng.shuffle(bench)
    repeat=rng.sample([r['id'] for r in eligible],58)
    privatepath=private/'inputs.private.jsonl'; privatepath.write_text(''.join(json.dumps(r)+'\n' for r in rows)); os.chmod(privatepath,0o600)
    (out/'input_manifest.jsonl').write_text(''.join(json.dumps(r)+'\n' for r in manifest))
    protocol={'schema':'cascade-experiments-dev/v1','frozen_at_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'seed':20261030,'scope':'DEVELOPMENT only; neither protected evaluation nor operational approval','cohorts':dict(collections.Counter(r['cohort'] for r in rows)), 'private_inputs_sha256':sha(privatepath.read_bytes()),'legacy_source_sha256':sha(source.read_bytes()),'authored_generator_sha256':sha(Path(PD.__file__).read_bytes()),'benchmark_ids':bench,'benchmark_repetitions':3,'fresh_process_each_model_run':True,'cold_requests_per_process':1,'warmup_requests_per_process':4,'batch_size':1,'model_concurrency':1,'percentile':'nearest rank; no trimming','determinism_ids':repeat,'determinism_repetitions':3,'thresholds_descriptive_only':[0.5,0.7,0.8,0.9,0.95,0.99,0.999],'applied_model2_threshold':0.9,'threshold_status':'unchanged preexisting LAB_EXPERIMENTAL; no selection on these data','live_cohort':'all 600 legacy_dev requests per mode, same order','live_modes':['V5_ONLY','baseline34','path-ablation32'],'load_concurrency':[1,4,8,16],'load_requests_per_level':48,'protected_sets_read':False,'git_mutations_authorized':False,'no_training':True,'limitations':['legacy DEV possibly overlaps training','authored cases are dependent within pairs/families; no IID security risk claim','V5 heldout only path_file_access; other trained categories TRAIN-only','reason taxonomies V4/V5 differ; unmappable reasons not counted incorrect by invented mapping','C2/async fast-allow audit/HTTP2/TLS/mitmproxy integration not implemented by this lab','energy/real exploit success/production FPR not measurable by this experiment']}
    (out/'protocol.json').write_text(json.dumps(protocol,indent=2)+'\n')
    print(json.dumps({'rows':len(rows),'canonical':dict(collections.Counter(str(r.get('canonical_outcome')) for r in rows)),'private_sha256':protocol['private_inputs_sha256']}))
if __name__=='__main__': main()
