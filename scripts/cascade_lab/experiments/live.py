"""Real socket DEV cascade, independent sink evidence, selective ML and load."""
import argparse,json,sys,time,hashlib,socket,urllib.request,urllib.error,collections,concurrent.futures,threading
from pathlib import Path
REPO=Path(__file__).resolve().parents[3];sys.path[:0]=[str(REPO/'data_plane'),str(REPO/'scripts/cascade_lab'),str(REPO)]
import cascade as C, cascade_runtime as RT, fast_path as FP, http1_wire as W, lab_server as L
from run_cascade import load_deciders, model2_record
from scripts.model2 import training as T
from scripts.training.hybrid_analyzer import attack_metrics, attack_metrics_group_weighted

def sha(b):return hashlib.sha256(b).hexdigest()
def request(url,text,timeout=20):
    t=time.perf_counter();record={}
    try:
        q=urllib.request.Request(url+'/classify',data=json.dumps({'canonical_request':text}).encode(),headers={'Content-Type':'application/json'})
        with urllib.request.urlopen(q,timeout=timeout) as r:record=dict(json.load(r),http_status=r.status)
    except urllib.error.HTTPError as e:record={'http_status':e.code,'status':'http_error'};e.close()
    except (OSError,ValueError) as e:record={'http_status':None,'status':'transport_error','error_type':type(e).__name__}
    record['roundtrip_ms']=(time.perf_counter()-t)*1000;return record
class MeasuredV5:
    def __init__(self,url):self.url=url;self.calls=[]
    def __call__(self,text):
        r=request(self.url,text);self.calls.append(r)
        return C.V5Reply(status=r['status'],decision=r.get('decision'),invalid_reason=r.get('invalid_reason'),detail=r.get('error_type') or (str(r.get('http_status')) if r['status'] not in ('ok','invalid') else None),generate_ms=r.get('generate_ms'))
def send(addr,wire):
    t=time.perf_counter();resp=b''
    with socket.create_connection(addr,timeout=30) as s:
        s.sendall(wire)
        while True:
            data=s.recv(8192)
            if not data:break
            resp+=data
    return int(resp.split(b' ',2)[1]),(time.perf_counter()-t)*1000

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--private',required=True);ap.add_argument('--out',required=True);ap.add_argument('--url',required=True);args=ap.parse_args();out=Path(args.out)
    protocol=json.loads((out/'protocol.json').read_text());raw=Path(args.private).read_bytes();assert sha(raw)==protocol['private_inputs_sha256'];rows=[json.loads(l) for l in raw.splitlines()];legacy=[r for r in rows if r['cohort']=='legacy_dev'];eligible=[r for r in rows if r.get('canonical_outcome')=='ACCEPT'];bench=set(protocol['benchmark_ids'])
    supplemental={'scope':'Synthetic route latency and full gateway load; independent of final quality','frozen_before_live_execution_utc':time.time(),'fast_path_requests':64,'fast_path_warmup':4,'gateway_load_concurrency':[1,4,16],'gateway_load_requests':48,'modes':protocol['live_modes'],'workload':'fixed round robin healthz benign / traversal attack / catalog benign; same wire order in every mode; no production prevalence claim','independent_receipt_scope_under_concurrency':'aggregate by wire hash per run; no fabricated individual receipt correlation'}
    (out/'supplemental_protocol.json').write_text(json.dumps(supplemental,indent=2)+'\n')
    # TRAIN only. No VALIDATION / INTERNAL_TEST / STAB / external file is opened.
    trainpath=REPO/'datasets/v5_sources/final_source_2026-10-26-v4/rows.TRAIN.jsonl'
    trainbytes=trainpath.read_bytes();train=[json.loads(l)['text'] for l in trainbytes.splitlines()]
    trainhash={sha(t.encode()) for t in train}
    def vectorhash(text,view):
        return sha(json.dumps(T.vector(text,view),sort_keys=True,separators=(',',':')).encode())
    overlap={'train_source_sha256':sha(trainbytes),'TRAIN_N':len(train),'opened_splits':['TRAIN'],'warning':'Zero exact overlap is not proof of family or source independence.'}
    for view in ('baseline_34','target-path-neutralized/v1'):
        vectors={vectorhash(t,view) for t in train}
        overlap[view]={}
        for cohort in ('legacy_dev','authored_paired_dev'):
            subset=[r for r in eligible if r['cohort']==cohort]
            overlap[view][cohort]={'N':len(subset),'canonical_text_overlap_ids':[r['id'] for r in subset if r['canonical_sha256'] in trainhash],'feature_vector_overlap_ids':[r['id'] for r in subset if vectorhash(r['canonical_text'],view) in vectors]}
    (out/'TRAIN_overlap.json').write_text(json.dumps(overlap,indent=2)+'\n')
    t=time.perf_counter();b,a=load_deciders();(out/'model2_loading.json').write_text(json.dumps({'both_load_s':time.perf_counter()-t,'baseline_status':b.artifact.get('mode'),'ablation_status':a.artifact.get('mode')})+'\n'); deciders={'baseline34':b,'path-ablation32':a}
    m2_rows=[]
    with (out/'model2_quality.jsonl').open('w') as f:
        for r in eligible:
            rec={k:r.get(k) for k in ('id','label','category','cohort','family','placement','pair_id','wire_sha256','canonical_sha256')}
            vf=T.vector(r['canonical_text'],'baseline_34')
            rec['input_features']={k:vf.get(k) for k in ('method','body_format','has_percent_encoding','percent_encoded_count','body_length','query_length','path_length')}
            for name,d in deciders.items():rec[name]=model2_record(d,'ACCEPT',r['canonical_text'])
            f.write(json.dumps(rec)+'\n');m2_rows.append(rec)
    probability={}
    for cohort in ('legacy_dev','authored_paired_dev'):
        subset=[r for r in m2_rows if r['cohort']==cohort]
        probability[cohort]={}
        for name in deciders:
            valid=[r for r in subset if r[name]['status']=='OK' and r[name]['p_block'] is not None]
            y=[int(r['label']=='BLOCK') for r in valid];p=[r[name]['p_block'] for r in valid]
            view=deciders[name].feature_view
            source_by={r['id']:r for r in eligible}
            groups=[vectorhash(source_by[r['id']]['canonical_text'],view) for r in valid]
            disjoint_ids=set(overlap[view][cohort]['feature_vector_overlap_ids'])
            disjoint=[r for r in valid if r['id'] not in disjoint_ids]
            probability[cohort][name]={
                'probability_diagnostics':attack_metrics(y,p),
                'exact_feature_vector_group_weighted_diagnostic':attack_metrics_group_weighted(y,p,groups),
                'TRAIN_feature_disjoint_diagnostic':attack_metrics([int(r['label']=='BLOCK') for r in disjoint],[r[name]['p_block'] for r in disjoint]) if disjoint else None,
                'threshold_curve_descriptive_only':[attack_metrics(y,p,threshold=t,with_bins=False) for t in protocol['thresholds_descriptive_only']],
                'warning':'Threshold .5 is a diagnostic reporting convention; deployed actions remain BLOCK/DEFER at unchanged LAB .9. No calibration fitted or operating point selected.'}
    (out/'model2_probability_metrics.json').write_text(json.dumps(probability,indent=2)+'\n')
    with (out/'model2_benchmark.jsonl').open('w') as f:
        for rep in range(1,4):
            for name,d in deciders.items():
                for r in eligible:
                    if r['id'] not in bench:continue
                    t=time.perf_counter();vector=T.vector(r['canonical_text'],d.feature_view);feature_ms=(time.perf_counter()-t)*1000
                    rec=model2_record(d,'ACCEPT',r['canonical_text']);rec.update(id=r['id'],model=name,run=rep,feature_only_ms=feature_ms,features=len(vector));f.write(json.dumps(rec)+'\n')
    policy=FP.load_policy(str(REPO/'reports/v5/hybrid/cascade-lab/policies/fast_path_lab_app.json'))
    with (out/'service_warmup.jsonl').open('w') as f:
        text=next(r['canonical_text'] for r in eligible if r['label']=='ALLOW')
        for i in range(4):
            f.write(json.dumps(dict(request(args.url,text),index=i,phase='excluded_service_warmup'))+'\n')
    sink=L.UpstreamSink();sink.start()
    try:
        for name in protocol['live_modes']:
            v5=MeasuredV5(args.url);logs=[];d=deciders.get(name,b)
            config=C.CascadeConfig(mode=C.V5_ONLY if name=='V5_ONLY' else C.CASCADE_ACTIVE,fast_path_policy=policy)
            router=C.CascadeRouter(config,fast_path_evaluate=FP.safe_evaluate,model2_decide=d.decide,v5_classify=v5,make_fast_path_input=RT.make_fast_path_input)
            gw=L.CascadeGateway(router,L.GatewayConfig((sink.host,sink.port),log_sink=logs.append));gw.start(); t_run=time.perf_counter()
            try:
                with (out/f'gateway_{name}.jsonl').open('w') as f:
                    for i,r in enumerate(legacy):
                        wire=r['wire'].encode('utf8');before=len(sink.received());calls=len(v5.calls);nlogs=len(logs)
                        status,elapsed=send((gw.host,gw.port),wire)
                        assert len(logs)==nlogs+1,('log synchronization',r['id'])
                        got=sink.received()[before:];independent=[{'wire_sha256':x.wire_sha256,'wire_bytes':x.wire_bytes,'body_len':x.body_len} for x in got]
                        trace=logs[-1];rec={k:r.get(k) for k in ('id','label','category','cohort','wire_ok','wire_sha256','canonical_outcome')}
                        rec.update(mode=name,http_status=status,client_ms=elapsed,trace=trace,v5_calls=len(v5.calls)-calls,v5_measurements=v5.calls[calls:],independent_upstream=independent,upstream_received_independent=bool(got),wire_preserved=(all(x['wire_sha256']==r['wire_sha256'] for x in independent) if independent else None))
                        f.write(json.dumps(rec)+'\n');f.flush()
                        if (i+1)%100==0:print(f'gateway {name}: {i+1}/600 ({time.perf_counter()-t_run:.1f}s)',flush=True)
                # Real bounded synthetic route cohort; all labels/expectations declared independently.
                if name!='V5_ONLY':
                    probes=[('healthz','GET /healthz HTTP/1.1\r\nHost: lab.local\r\n\r\n','FAST_ALLOW'),('status','GET /status?page=42 HTTP/1.1\r\nHost: lab.local\r\n\r\n','FAST_ALLOW'),('status-too-long','GET /status?page=12345 HTTP/1.1\r\nHost: lab.local\r\n\r\n','CONTINUE'),('health-extra-query','GET /healthz?x=%27OR%271%27%3D%271 HTTP/1.1\r\nHost: lab.local\r\n\r\n','CONTINUE'),('wrong-host','GET /healthz HTTP/1.1\r\nHost: other.local\r\n\r\n','CONTINUE'),('wrong-method','POST /healthz HTTP/1.1\r\nHost: lab.local\r\nContent-Length: 0\r\n\r\n','CONTINUE')]
                    with (out/f'fast_path_{name}.jsonl').open('w') as f:
                        for pid,wire,expected in probes:
                            before=len(sink.received());calls=len(v5.calls);status,ms=send((gw.host,gw.port),wire.encode());rec=logs[-1];actual=rec['fast_path']['decision'];f.write(json.dumps(dict(id=pid,expected_fast_path=expected,actual_fast_path=actual,pass_guard=actual==expected,client_ms=ms,http_status=status,trace=rec,v5_calls=len(v5.calls)-calls,independent_receipts=len(sink.received())-before))+'\n')
                    with (out/f'fast_path_latency_{name}.jsonl').open('w') as f:
                        for i in range(68):
                            wire=probes[i%2][1].encode();before=len(sink.received());calls=len(v5.calls);status,ms=send((gw.host,gw.port),wire)
                            assert status==200 and len(sink.received())==before+1 and len(v5.calls)==calls
                            f.write(json.dumps(dict(index=i,phase='warmup' if i<4 else 'steady',client_ms=ms,http_status=status,v5_calls=0,independent_receipts=1))+'\n')
                # The full gateway is loaded as well as the classifier API below.
                load_wires=[b'GET /healthz HTTP/1.1\r\nHost: lab.local\r\n\r\n',b'GET /download?file=..%2f..%2f..%2fetc%2fpasswd HTTP/1.1\r\nHost: files.local\r\n\r\n',b'GET /catalog/widgets HTTP/1.1\r\nHost: shop.local\r\n\r\n']
                with (out/f'gateway_load_{name}.jsonl').open('w') as f:
                    for concurrency in supplemental['gateway_load_concurrency']:
                        before=len(sink.received());nlog=len(logs);calls=len(v5.calls);t0=time.perf_counter();barrier=threading.Barrier(concurrency)
                        def gateway_job(i):
                            if i<concurrency:barrier.wait(timeout=10)
                            wire=load_wires[i%3];status,ms=send((gw.host,gw.port),wire)
                            return dict(index=i,wire_sha256=sha(wire),label='BLOCK' if i%3==1 else 'ALLOW',http_status=status,client_ms=ms)
                        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
                            clients=list(pool.map(gateway_job,range(supplemental['gateway_load_requests'])))
                        duration=time.perf_counter()-t0;traces=logs[nlog:];receipts=sink.received()[before:]
                        rec={'mode':name,'concurrency':concurrency,'duration_s':duration,'clients':clients,'traces':traces,'v5_calls':len(v5.calls)-calls,'v5_measurements':v5.calls[calls:],'independent_receipts_by_wire_sha256':dict(collections.Counter(x.wire_sha256 for x in receipts)),'independent_receipt_N':len(receipts),'scope':'real socket gateway closed-loop synthetic mixed route workload; independent aggregate receipts only'}
                        assert len(clients)==len(traces)==48
                        f.write(json.dumps(rec)+'\n');f.flush()
                        print(f'gateway load {name} concurrency={concurrency}, duration={duration:.2f}s',flush=True)
            finally:gw.stop()
        # Failure controls use injected doubles only where explicitly tagged; real V5 for recovery.
        benign='GET /catalog/widgets HTTP/1.1\r\nHost: shop.local\r\n\r\n';wire=benign.encode();failures=[]
        def broken(**kwargs):raise RuntimeError('injected Model 2 unavailable')
        def inconsistent(**kwargs):
            class R:status='SCORING_FAILED';decision='BLOCK'
            return R()
        for name,m2,v5 in [('model2_exception',broken,MeasuredV5(args.url)),('model2_non_ok_block',inconsistent,MeasuredV5(args.url)),('v5_unavailable',broken,MeasuredV5('http://127.0.0.1:1')),('v5_invalid',broken,lambda text:C.V5Reply(status='invalid',invalid_reason='no_eos'))]:
            logs=[];router=C.CascadeRouter(C.CascadeConfig(mode=C.CASCADE_ACTIVE),fast_path_evaluate=FP.safe_evaluate,model2_decide=m2,v5_classify=v5,make_fast_path_input=RT.make_fast_path_input);gw=L.CascadeGateway(router,L.GatewayConfig((sink.host,sink.port),log_sink=logs.append));gw.start()
            try:
                before=len(sink.received());status,ms=send((gw.host,gw.port),wire);trace=logs[-1];received=len(sink.received())-before
                expected_forward=name.startswith('model2_');passed=(status==200 and received==1 and trace['deciding_stage']=='v5') if expected_forward else (status==403 and received==0)
                failures.append(dict(id=name,injected=True,http_status=status,client_ms=ms,trace=trace,independent_receipts=received,passed=passed))
            finally:gw.stop()
        (out/'failure_controls.json').write_text(json.dumps(failures,indent=2)+'\n');assert all(x['passed'] for x in failures)
    finally:sink.stop()
    # Load is explicitly API-only, closed loop. No gateway throughput claim from this.
    text=next(r['canonical_text'] for r in eligible if r['label']=='ALLOW')
    for _ in range(4):request(args.url,text)
    with (out/'api_load.jsonl').open('w') as f:
        for concurrency in protocol['load_concurrency']:
            t0=time.perf_counter();barrier=threading.Barrier(concurrency)
            def job(i):
                if i<concurrency:barrier.wait(timeout=10)
                return dict(request(args.url,text),index=i,concurrency=concurrency)
            with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
                records=list(pool.map(job,range(protocol['load_requests_per_level'])))
            duration=time.perf_counter()-t0
            for rec in records:rec['run_duration_s']=duration;f.write(json.dumps(rec)+'\n')
            f.flush();print(f'API concurrency={concurrency}, statuses={dict(collections.Counter(r["http_status"] for r in records))}, wall={duration:.2f}s',flush=True)
    recovery=request(args.url,text);(out/'post_load_recovery.json').write_text(json.dumps(recovery,indent=2)+'\n');assert recovery['status']=='ok'
if __name__=='__main__':main()
