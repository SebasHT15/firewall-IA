"""Compare controlled runtime observations without running models again."""
import csv,json,math,sys
from collections import Counter
from pathlib import Path
REPO=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(REPO/'scripts/cascade_lab'))
from metrics import binary_confusion,dist
OUT=REPO/'reports/v5/successor-2026-10-30/runtime'
BASE=REPO/'reports/v5/hybrid/experiments-2026-10-30'

def rows(p):return [json.loads(x) for x in p.read_text().splitlines() if x]
def quality(rs):return binary_confusion([(r['label'],r['decision'],r.get('invalid_reason')) for r in rs])
def main():
    protocol=json.loads((OUT/'protocol.json').read_text());original={r['id']:r for r in rows(BASE/'v5_quality.jsonl')};result={'scope':'DEV controlled runtime; no weights trained or deployment approved','common_benchmark_N':len(protocol['benchmark_ids']),'configs':{}};table=[]
    for config in protocol['configs']:
        rs=[];runs=[]
        for run in (1,2,3):
            records=rows(OUT/f'{config}_run{run}.jsonl');data=[r for r in records if r['phase']=='benchmark'];assert [r['id'] for r in data]==protocol['benchmark_ids'];rs+=data
            meta=json.loads((OUT/f'{config}_run{run}_metadata.json').read_text());r={'run':run,'pipeline_ms':dist([x['measure']['pipeline_ms'] for x in data]),'generate_ms':dist([x['measure']['generate_ms'] for x in data]),'load_s':meta['load_s'],'cuda_peak_allocated_bytes':meta['peak_cuda_allocated_bytes'],'cuda_peak_reserved_bytes':meta['peak_cuda_reserved_bytes'],'actual_runtime':meta['actual_runtime'],'changed_decisions_vs_prior_nf4_dq':[x['id'] for x in data if x['decision']!=original[x['id']]['decision']],'changed_output_hashes_vs_prior_nf4_dq':[x['id'] for x in data if x['output_sha256']!=original[x['id']]['output_sha256']]};runs.append(r);table.append(dict(config=config,run=run,**r['pipeline_ms'],cuda_peak_allocated_MiB=meta['peak_cuda_allocated_bytes']/1024**2))
        byid={}
        for r in rs:byid.setdefault(r['id'],set()).add((r['output_sha256'],r['status']))
        qpath=OUT/f'{config}_run4_quality_complete.jsonl'
        q=rows(qpath) if qpath.exists() else list(original.values()) if config=='nf4_dq' else None
        full={}
        if q:
            for cohort in ('legacy_dev','authored_paired_dev'):
                sub=[r for r in q if r['cohort']==cohort];full[cohort]=quality(sub)
                if cohort=='authored_paired_dev':
                    primary=[r for r in sub if r['label']=='ALLOW' or r['family'] in {'sql_injection','xss','command_injection','path_file_access','ssti'}];full[cohort]['trained_family_binary']=quality(primary)
            changed=[r for r in q if r['decision']!=original[r['id']]['decision']]
            full['changed_cases_vs_prior']=[dict(id=r['id'],cohort=r['cohort'],family=r.get('family'),label=r['label'],prior_decision=original[r['id']]['decision'],new_decision=r['decision'],status=r['status']) for r in changed]
        result['configs'][config]={'runs':runs,'pooled_pipeline_ms':dist([r['measure']['pipeline_ms'] for r in rs]),'three_process_byte_hash_divergences':[cid for cid,v in byid.items() if len(v)>1],'full_quality':full or 'PENDING','quality_reference_warning':'legacy_dev labels are rejected historical corpus references, not validated attack truth; see coverage/REFERENCE_AUDIT.md'}
    (OUT/'summary.json').write_text(json.dumps(result,indent=2)+'\n')
    with (OUT/'latency.csv').open('w',newline='') as f:w=csv.DictWriter(f,fieldnames=list(table[0]));w.writeheader();w.writerows(table)
    print(json.dumps({c:{'p95':v['pooled_pipeline_ms']['p95'],'run_p95':[r['pipeline_ms']['p95'] for r in v['runs']],'byte_divergences':v['three_process_byte_hash_divergences'],'quality_complete':isinstance(v['full_quality'],dict)} for c,v in result['configs'].items()},indent=2))
if __name__=='__main__':main()
