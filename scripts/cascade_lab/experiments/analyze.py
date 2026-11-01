"""Recompute measured, derived and explicitly unavailable metrics, without models."""
import sys,json,math,hashlib,csv,collections,statistics,random,time
from pathlib import Path
REPO=Path(__file__).resolve().parents[3];sys.path[:0]=[str(REPO/'scripts/cascade_lab'),str(REPO)]
from metrics import binary_confusion,dist
from scipy.stats import binomtest
OUT=REPO/'reports/v5/hybrid/experiments-2026-10-30'
def read(name):return [json.loads(x) for x in (OUT/name).read_text().splitlines() if x.strip()]
def ratio(a,b):return a/b if b else None
def wilson(k,n):
    if not n:return None
    z=1.959963984540054;p=k/n;d=1+z*z/n;c=(p+z*z/(2*n))/d;h=z*math.sqrt(p*(1-p)/n+z*z/(4*n*n))/d
    return [max(0,c-h),min(1,c+h)]
def cm(rows,getpred=lambda r:r.get('decision')):
    x=binary_confusion([(r['label'],getpred(r),r.get('invalid_reason')) for r in rows]);p=x['principal'];tp,tn,fp,fn=[p[k] for k in ('TP','TN','FP','FN')]
    d=(tp+fp)*(tp+fn)*(tn+fp)*(tn+fn)
    p.update(specificity=ratio(tn,tn+fp),negative_predictive_value=ratio(tn,tn+fn),balanced_accuracy=((tp/(tp+fn)+tn/(tn+fp))/2 if tp+fn and tn+fp else None),mcc=((tp*tn-fp*fn)/math.sqrt(d) if d else None),f2_block=ratio(5*tp,5*tp+4*fn+fp),f1_allow=ratio(2*tn,2*tn+fn+fp))
    p['f1_macro']=(p['f1_block']+p['f1_allow'])/2 if p['f1_block'] is not None and p['f1_allow'] is not None else None
    x['nominal_iid_wilson_95']={'recall':wilson(tp,tp+fn),'fpr':wilson(fp,fp+tn),'precision':wilson(tp,tp+fp),'accuracy':wilson(tp+tn,p['N']),'warning':'Descriptive nominal IID intervals ONLY. DEV rows may overlap training and have dependencies; these are NOT validated population security bounds.'}
    return x
def correctness(r):return r.get('decision')==r['label']
def paired(left,right):
    lm={r['id']:r for r in left};rm={r['id']:r for r in right};assert lm.keys()==rm.keys()
    improved=sum(not correctness(lm[k]) and correctness(rm[k]) for k in lm);regressed=sum(correctness(lm[k]) and not correctness(rm[k]) for k in lm)
    return {'N':len(lm),'right_improved':improved,'right_regressed':regressed,'accuracy_delta':(improved-regressed)/len(lm),'mcnemar_exact_nominal_iid_p':float(binomtest(min(improved,regressed),improved+regressed,.5).pvalue) if improved+regressed else 1.0,'warning':'Paired development observation; exact test assumes independent pairs, which is not established here. No generalization significance claim.'}
def writecsv(name,rows):
    if not rows:return
    with (OUT/name).open('w',newline='') as f:
        w=csv.DictWriter(f,fieldnames=sorted(set().union(*(r.keys() for r in rows))));w.writeheader();w.writerows(rows)
def main():
    protocol=json.loads((OUT/'protocol.json').read_text());manifest=read('input_manifest.jsonl');manifest_by={r['id']:r for r in manifest}
    summary={'schema':'cascade-experimental-metrics/v1','scope':'DEVELOPMENT ONLY; no deployment or protected-gate claim','protocol_sha256':hashlib.sha256((OUT/'protocol.json').read_bytes()).hexdigest(),'measured_at_utc':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'quality':{},'benchmarks':{},'determinism':{},'model2':{},'gateway':{},'load':{},'comparisons':{}}
    models={m:read(m+'_quality.jsonl') for m in ('v4','v5')};quality_csv=[];slices=[];latency_csv=[]
    summary['input_tokens']={model:{c:dist([r['measure']['prompt_tokens'] for r in rows if r['cohort']==c and r['measure']['generated_tokens']>0]) for c in ('legacy_dev','authored_paired_dev')} for model,rows in models.items()}
    for model,rows in models.items():
        assert len(rows)==len(set(r['id'] for r in rows))==1012
        summary['quality'][model]={}
        for cohort in ('legacy_dev','authored_paired_dev'):
            subset=[r for r in rows if r['cohort']==cohort];q=cm(subset);summary['quality'][model][cohort]=q;quality_csv.append(dict(system=model,cohort=cohort,scope='model_quality_E5',**q['principal'],invalid=q['invalid']['total']))
            for field in (['category'] if cohort=='legacy_dev' else ['family','placement']):
                groups=collections.defaultdict(list)
                for r in subset:groups[r.get(field) or 'unknown'].append(r)
                for key,group in groups.items():slices.append(dict(system=model,cohort=cohort,slice_type=field,slice=key,**cm(group)['principal']))
            correct_blocks=[r for r in subset if r['label']=='BLOCK' and r.get('decision')=='BLOCK']
            if model=='v4' and cohort=='legacy_dev':
                q['reason_exact_on_correct_blocks']={'matches':sum(r['reason_exact_expected'] is True for r in correct_blocks),'denominator':len(correct_blocks),'rate':ratio(sum(r['reason_exact_expected'] is True for r in correct_blocks),len(correct_blocks))}
            if model=='v5' and cohort=='legacy_dev':
                vocab={'SQL injection payload detected.','Cross-site scripting payload detected.','Path traversal attack detected.','File inclusion attack detected.','Command injection payload detected.','Server-side template injection payload detected.'}
                mapped=[r for r in correct_blocks if r['category'] in vocab];q['reason_exact_on_correct_blocks_in_vocabulary']={'matches':sum(r.get('reason')==r['category'] for r in mapped),'denominator':len(mapped),'rate':ratio(sum(r.get('reason')==r['category'] for r in mapped),len(mapped))}
                invocab=[r for r in subset if r['label']=='ALLOW' or r['category'] in vocab];q['in_vocabulary_binary']=cm(invocab);q['outside_vocabulary_attacks']=cm([r for r in subset if r['label']=='BLOCK' and r['category'] not in vocab])
        repeats=[r for r in read(model+'_run1.jsonl') if r['phase']=='determinism'];byid={r['id']:r for r in rows};diff=[]
        for r in repeats:
            if r['output_sha256']!=byid[r['id']]['output_sha256'] or r['status']!=byid[r['id']]['status']:diff.append({'id':r['id'],'repeat':r['repeat']})
        summary['determinism'][model]={'texts':len(protocol['determinism_ids']),'outputs_per_text':3,'additional_outputs':len(repeats),'byte_hash_divergences':diff,'scope':'DEV repeatability; not D77 protected G5'}
        runs=[]
        for run in range(1,4):
            allrows=read(f'{model}_run{run}.jsonl');warm=[r for r in allrows if r['phase']=='benchmark'];generated=[r for r in warm if r['measure']['generated_tokens']>0];meta=json.loads((OUT/f'{model}_run{run}_metadata.json').read_text());rec={'run':run,'N_benchmark':len(warm),'generation_N':len(generated),'load_s':meta['load_s'],'cold':[r for r in allrows if r['phase']=='cold'],'warmup_N':sum(r['phase']=='warmup' for r in allrows),'memory':{k:meta[k] for k in ['cuda_peak_allocated_bytes','cuda_peak_reserved_bytes','rss_end_bytes']}}
            for scope in ('pipeline_ms','generate_ms','wall_ms','encode_ms','prompt_build_ms','tokenize_ms','transfer_ms','decode_ms','parse_ms','prompt_tokens','generated_tokens'):
                vals=[r['measure'].get(scope) for r in generated];rec[scope]=dist(vals)
                if rec[scope]['n']:latency_csv.append(dict(system=model,run=run,scope=scope,**rec[scope]))
            rec['D36_dev_observed_p95_le_200ms']=rec['pipeline_ms']['p95']<=200;runs.append(rec)
        pooled=[r for run in range(1,4) for r in read(f'{model}_run{run}.jsonl') if r['phase']=='benchmark' and r['measure']['generated_tokens']>0]
        summary['benchmarks'][model]={'scope':'steady native inference pipeline; no HTTP/queue/network; batch1 concurrency1; three fresh processes','runs':runs,'pooled_pipeline_ms':dist([r['measure']['pipeline_ms'] for r in pooled]),'pooled_generate_ms':dist([r['measure']['generate_ms'] for r in pooled]),'run_p95_range_ms':[min(r['pipeline_ms']['p95'] for r in runs),max(r['pipeline_ms']['p95'] for r in runs)],'pooled_output_tokens_per_generate_s':ratio(sum(r['measure']['generated_tokens'] for r in pooled),sum(r['measure']['generate_ms'] for r in pooled)/1000)}
    for cohort in ('legacy_dev','authored_paired_dev'):
        summary['comparisons']['v4_to_v5_'+cohort]=paired([r for r in models['v4'] if r['cohort']==cohort],[r for r in models['v5'] if r['cohort']==cohort])
    summary['authored_pair_discrimination']={}
    for model,rows in models.items():
        pairs=collections.defaultdict(list)
        for r in rows:
            if r['cohort']=='authored_paired_dev' and r.get('pair_id'):pairs[r['pair_id']].append(r)
        complete=[group for group in pairs.values() if len(group)==2 and {r['label'] for r in group}=={'ALLOW','BLOCK'}]
        summary['authored_pair_discrimination'][model]={'complete_attack_benign_pairs_N':len(complete),'both_correct':sum(all(correctness(r) for r in group) for group in complete),'both_blocked':sum(all(r.get('decision')=='BLOCK' for r in group) for group in complete),'both_allowed':sum(all(r.get('decision')=='ALLOW' for r in group) for group in complete),'benign_errors':sum(r['label']=='ALLOW' and not correctness(r) for group in complete for r in group),'scope':'DEV attack/benign discrimination; these pairs are not invariance controls and do not accredit STAB G1/G2'}
    m2=read('model2_quality.jsonl');prob=json.loads((OUT/'model2_probability_metrics.json').read_text());m2bench=read('model2_benchmark.jsonl');threshold_csv=[]
    features_by_id={r['id']:r['input_features'] for r in m2}
    for model,rows in models.items():
        for cohort in ('legacy_dev','authored_paired_dev'):
            for field in ('method','body_format','has_percent_encoding'):
                groups=collections.defaultdict(list)
                for r in rows:
                    if r['cohort']==cohort:groups[str(features_by_id[r['id']].get(field))].append(r)
                for key,group in groups.items():slices.append(dict(system=model,cohort=cohort,slice_type='exploratory_feature_'+field,slice=key,**cm(group)['principal']))
    for name in ('baseline34','path-ablation32'):
        summary['model2'][name]={'cohorts':{}}
        summary['model2'][name]['population_confidence_interval']=None
        summary['model2'][name]['interval_reason']='No registered independent population sampling/group protocol for these DEV cohorts. Exact-feature grouping is a diagnostic, not independent families.'
        for cohort in ('legacy_dev','authored_paired_dev'):
            sub=[r for r in m2 if r['cohort']==cohort];allow=[r for r in sub if r['label']=='ALLOW'];attack=[r for r in sub if r['label']=='BLOCK'];blocks=[r for r in sub if r[name]['decision']=='BLOCK'];tp=sum(r['label']=='BLOCK' for r in blocks);fp=len(blocks)-tp
            q={'reached_N':len(sub),'benign_N':len(allow),'attack_N':len(attack),'early_block_TP':tp,'early_block_FP':fp,'early_false_block_rate':ratio(fp,len(allow)),'early_attack_block_rate':ratio(tp,len(attack)),'early_block_precision':ratio(tp,len(blocks)),'defer_N':len(sub)-len(blocks),'defer_rate':ratio(len(sub)-len(blocks),len(sub)),'non_ok':sum(r[name]['status']!='OK' for r in sub),'threshold':.9,'policy_status':'LAB_EXPERIMENTAL','probability_metrics':prob[cohort][name]}
            summary['model2'][name]['cohorts'][cohort]=q
            for t in q['probability_metrics']['threshold_curve_descriptive_only']:threshold_csv.append(dict(model=name,cohort=cohort,**t))
        for field in ('ms','feature_only_ms'):
            timings=[r[field] for r in m2bench if r['model']==name];summary['model2'][name][field]=dist(timings);latency_csv.append(dict(system=name,run='pooled3',scope=field,**dist(timings)))
    # The entire authored DEV matrix is available without pretending these were
    # additional network runs. Legacy counterfactuals can be checked against live records.
    summary['counterfactual_cascade']={}
    v5by={r['id']:r for r in models['v5']}
    for name in ('baseline34','path-ablation32'):
        summary['counterfactual_cascade'][name]={}
        for cohort in ('legacy_dev','authored_paired_dev'):
            sub=[]
            for r in m2:
                if r['cohort']!=cohort:continue
                v=v5by[r['id']];d='BLOCK' if r[name]['status']=='OK' and r[name]['decision']=='BLOCK' else v.get('decision')
                sub.append(dict(r,decision=d,invalid_reason=None if d=='BLOCK' else v.get('invalid_reason')))
            q=cm(sub);summary['counterfactual_cascade'][name][cohort]={'quality_E5':q,'scope':'DERIVED from paired real standalone scores, no Fast Path positive route in this derivation; not a measured network pass'}
            quality_csv.append(dict(system='counterfactual_'+name,cohort=cohort,scope='derived_E5',**q['principal'],invalid=q['invalid']['total']))
    for name in protocol['live_modes']:
        records=read(f'gateway_{name}.jsonl');assert len(records)==600
        eligible=[r for r in records if r['wire_ok'] and r['canonical_outcome']=='ACCEPT'];ll=[];runtime=[]
        for r in eligible:
            trace=r['trace'];d=None;reason=None
            if trace['deciding_stage']=='v5':d=(trace.get('v5') or {}).get('decision') if (trace.get('v5') or {}).get('status')=='ok' else None;reason=(trace.get('v5') or {}).get('invalid_reason')
            elif trace['deciding_stage']=='fast_path':d='ALLOW'
            elif trace['deciding_stage']=='model2':d='BLOCK'
            ll.append(dict(r,decision=d,invalid_reason=reason));runtime.append(dict(r,decision='ALLOW' if r['upstream_received_independent'] else 'BLOCK'))
        assert len(eligible)==578
        l2bad=[r['id'] for r in records if ((r['trace']['applied']=='FORWARD')!=r['upstream_received_independent']) or (r['upstream_received_independent'] and r['http_status']!=200) or (r['trace']['applied']=='DENY' and r['http_status'] not in (400,403)) or r['wire_preserved'] is False]
        q=cm(ll);e2e=cm(runtime);actualcalls=sum(r['v5_calls'] for r in records);stages=dict(collections.Counter(r['trace']['deciding_stage'] for r in records));qall=cm([dict(r,decision='ALLOW' if r['upstream_received_independent'] else 'BLOCK') for r in records]);protectedattacks=sum(r['label']=='BLOCK' and not r['upstream_received_independent'] for r in records)
        g={'N_wire':len(records),'N_semantic':len(eligible),'L1_semantic_E5':q,'L2_enforcement_mismatch_N':len(l2bad),'L2_mismatch_ids':l2bad,'independent_upstream_receipts':sum(len(r['independent_upstream']) for r in records),'forwarded_wire_hash_mismatch_N':sum(r['wire_preserved'] is False for r in records),'L3_delivery_eligible':e2e,'L3_delivery_all_wire_including_protocol':qall,'attack_forwarded_eligible':e2e['principal']['FN'],'benign_not_delivered_eligible':e2e['principal']['FP'],'actual_V5_calls':actualcalls,'actual_calls_avoided_vs_v5_only_eligible':578-actualcalls,'actual_call_avoidance_fraction_eligible':1-actualcalls/578,'deciding_stages':stages,'client_ms_all':dist([r['client_ms'] for r in records]),'client_ms_semantic':dist([r['client_ms'] for r in eligible]),'route_latency':{stage:dist([r['client_ms'] for r in records if r['trace']['deciding_stage']==stage]) for stage in stages},'scope':'real sequential TCP lab, same 600 DEV wires, independent sink hashes; not exploit success, TLS, HTTP2 or production throughput'}
        measurements=[m for r in records for m in r['v5_measurements']]
        g.update(actual_V5_generations=sum(m.get('generated_tokens',0)>0 for m in measurements),no_generation_content_rejections=sum(m.get('invalid_reason')=='content_rejected' for m in measurements),accumulated_V5_generate_ms=sum(m.get('generate_ms',0) for m in measurements),accumulated_V5_pipeline_ms=sum(m.get('pipeline_ms',0) for m in measurements),service_warmups_excluded=4)
        summary['gateway'][name]=g;quality_csv.append(dict(system='gateway_'+name,cohort='legacy_dev',scope='L1_semantic_E5',**q['principal'],invalid=q['invalid']['total']));quality_csv.append(dict(system='gateway_'+name,cohort='legacy_dev',scope='L3_delivery_eligible',**e2e['principal'],invalid=e2e['invalid']['total']))
        summary['comparisons']['standalone_v5_to_gateway_'+name]=paired([r for r in models['v5'] if r['cohort']=='legacy_dev'],ll)
        for stage,t in g['route_latency'].items():latency_csv.append(dict(system='gateway_'+name,run='sequential',scope='client_'+stage,**t))
    load=read('api_load.jsonl')
    for c in protocol['load_concurrency']:
        sub=[r for r in load if r['concurrency']==c];duration=sub[0]['run_duration_s'];ok=[r for r in sub if r['http_status']==200 and r['status']=='ok'];err=[r for r in sub if r not in ok]
        summary['load'][str(c)]={'N':len(sub),'duration_s':duration,'valid_N':len(ok),'error_or_invalid_N':len(err),'statuses':dict(collections.Counter(str(r['http_status']) for r in sub)),'throughput_responses_per_s':len(sub)/duration,'goodput_valid_classifications_per_s':len(ok)/duration,'saturation_rate':sum(r['http_status']==503 for r in sub)/len(sub),'latency_all_ms':dist([r['roundtrip_ms'] for r in sub]),'latency_valid_ms':dist([r['roundtrip_ms'] for r in ok]),'latency_errors_ms':dist([r['roundtrip_ms'] for r in err]),'queue_wait_ms_valid':dist([r['queue_wait_ms'] for r in ok]),'pipeline_ms_valid':dist([r['pipeline_ms'] for r in ok]),'scope':'API closed-loop single benign text, 48 requests; no arrival-rate/SLO/production capacity claim'}
    summary['failure_controls']=json.loads((OUT/'failure_controls.json').read_text());summary['post_load_recovery']=json.loads((OUT/'post_load_recovery.json').read_text())
    summary['TRAIN_overlap']=json.loads((OUT/'TRAIN_overlap.json').read_text())
    summary['fast_path_synthetic']={name:read(f'fast_path_{name}.jsonl') for name in ('baseline34','path-ablation32')}
    summary['fast_path_latency']={name:dist([r['client_ms'] for r in read(f'fast_path_latency_{name}.jsonl') if r['phase']=='steady']) for name in ('baseline34','path-ablation32')}
    summary['gateway_load']={}
    for name in protocol['live_modes']:
        summary['gateway_load'][name]={}
        for run in read(f'gateway_load_{name}.jsonl'):
            clients=run['clients'];traces=run['traces'];errors=[t for t in traces if t.get('v5') is not None and t['v5'].get('status')!='ok'];valid=len(traces)-len(errors)
            actual=run['independent_receipts_by_wire_sha256'];expected=dict(collections.Counter(t['wire_sha256'] for t in traces if t['applied']=='FORWARD'))
            summary['gateway_load'][name][str(run['concurrency'])]={'N':len(clients),'duration_s':run['duration_s'],'throughput_responses_per_s':len(clients)/run['duration_s'],'goodput_authoritative_decisions_per_s':valid/run['duration_s'],'fail_closed_errors_N':len(errors),'V5_http_503_N':sum(r.get('http_status')==503 for r in run['v5_measurements']),'actual_V5_calls':run['v5_calls'],'statuses':dict(collections.Counter(str(r['http_status']) for r in clients)),'client_ms_all':dist([r['client_ms'] for r in clients]),'independent_receipts_N':run['independent_receipt_N'],'aggregate_receipt_hash_counts_match_forwarded':actual==expected,'deciding_stages':dict(collections.Counter(t['deciding_stage'] for t in traces)),'scope':run['scope']}
    # Theory: linearity applies to means, never sums of percentiles. Actual stage branching measured above.
    baseline=summary['gateway']['V5_ONLY']['L1_semantic_E5']['principal'];summary['derived_tradeoffs']={}
    for name in ('baseline34','path-ablation32'):
        g=summary['gateway'][name];p=g['L1_semantic_E5']['principal'];summary['derived_tradeoffs'][name]={'delta_recall_pp':100*(p['recall_block']-baseline['recall_block']),'extra_false_blocks':p['FP']-baseline['FP'],'additional_true_blocks':p['TP']-baseline['TP'],'measured_client_mean_delta_ms':g['client_ms_semantic']['mean']-summary['gateway']['V5_ONLY']['client_ms_semantic']['mean'],'mean_identity':'E[T] = sum_route P(route)*E[T|route], within this measured workload; not a forecast for production','percentiles_not_additive':True}
    # Unavailable items are a deliverable, not silently substituted by a DEV result.
    summary['not_claimed']={'protected_INTERNAL_TEST':'NOT RUN: needs frozen selected artifact + operational threshold + final protocol, then one guarded joint evaluation','STAB_D77_G1_G2':'NOT RUN: protected controls/contrasts and own C_hi; authored DEV pairs are not the registered STAB set','STAB_D77_G3_G4':'NOT RUN as gates; DEV benign counts and per-carrier attack comparisons supplied as diagnostics','STAB_D77_G5':'NOT RUN as gate; DEV byte-hash repeatability supplied','external_E6':'NOT RUN: independent authorized post-freeze sources and labels required','FPR_1e-4_or_population_CI':'NOT ESTIMABLE from hundreds of dependent development benign cases','HTTP2_TLS_mitmproxy_D70':'NOT IMPLEMENTED/NOT TESTED by isolated HTTP1 lab','C2':'Optional stage not present, no performance invented','async_FAST_ALLOW_audit':'Not implemented; synthetic guard tests do not accredit audit','energy_CO2_training_FLOPs':'No measured power integration for isolated process or retraining; telemetry is device snapshot, not causal energy','exploit_success_ASR':'Inert sink measures request delivery only, never compromise or true exploit success','V5_probability_calibration':'No calibrated probability emitted by this LLM contract; do not invent AUC/ECE from text decisions'}
    (OUT/'summary.json').write_text(json.dumps(summary,indent=2)+'\n');writecsv('quality.csv',quality_csv);writecsv('slices.csv',slices);writecsv('latency.csv',latency_csv);writecsv('model2_thresholds_descriptive.csv',threshold_csv)
    writecsv('model2_probability.csv',[dict(cohort=cohort,model=model,**{k:v for k,v in vals['probability_diagnostics'].items() if not isinstance(v,dict)}) for cohort,models_ in prob.items() for model,vals in models_.items()])
    print(json.dumps({'quality':{m:{c:v['principal'] for c,v in q.items()} for m,q in summary['quality'].items()},'bench_p95':{m:v['pooled_pipeline_ms']['p95'] for m,v in summary['benchmarks'].items()},'gateway':{m:v['L1_semantic_E5']['principal'] for m,v in summary['gateway'].items()}},indent=2))
if __name__=='__main__':main()
