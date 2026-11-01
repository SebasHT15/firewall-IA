"""Standalone scientific figures; source predictions contain no request payloads."""
import json,sys,math,csv,collections
from pathlib import Path
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
REPO=Path(__file__).resolve().parents[3];OUT=REPO/'reports/v5/hybrid/experiments-2026-10-30';FIG=OUT/'figures'
def read(n):return [json.loads(x) for x in (OUT/n).read_text().splitlines() if x]
def save(fig,name):
    fig.savefig(FIG/(name+'.png'),dpi=180,bbox_inches='tight');fig.savefig(FIG/(name+'.pdf'),bbox_inches='tight');plt.close(fig)
def main():
    FIG.mkdir(exist_ok=True,parents=True)
    s=json.loads((OUT/'summary.json').read_text());plt.rcParams.update({'font.size':10,'axes.grid':True,'grid.alpha':.22,'figure.dpi':130})
    fig,axes=plt.subplots(1,2,figsize=(12,4.2))
    for ax,cohort,title in zip(axes,['legacy_dev','authored_paired_dev'],['Legacy DEV: matched wire requests','Authored diagnostic DEV: dependent pairs']):
        points=[('V4',s['quality']['v4'][cohort]['principal']),('V5',s['quality']['v5'][cohort]['principal'])]
        if cohort=='legacy_dev':points += [(name,s['gateway'][name]['L1_semantic_E5']['principal']) for name in ['baseline34','path-ablation32']]
        else:points += [(name+' (derived)',s['counterfactual_cascade'][name][cohort]['quality_E5']['principal']) for name in ['baseline34','path-ablation32']]
        for name,p in points:ax.scatter(p['fpr']*100,p['recall_block']*100,s=65,label=name)
        ax.legend(loc='lower left',fontsize=8)
        ax.set(xlabel='False-block rate on benign requests (%)',ylabel='Attack recall (%)',title=title);ax.set_ylim(0,105);ax.margins(x=.3)
    fig.suptitle('Development trade-offs — E5 invalids count as errors; not population security estimates',fontsize=11);fig.tight_layout();save(fig,'quality_tradeoffs')
    fig,ax=plt.subplots(figsize=(8,4.6))
    for m in ['v4','v5']:
        values=np.sort([r['measure']['pipeline_ms'] for run in range(1,4) for r in read(f'{m}_run{run}.jsonl') if r['phase']=='benchmark' and r['measure']['generated_tokens']>0]);ax.step(values,np.arange(1,len(values)+1)/len(values),where='post',label=f'{m.upper()} native pipeline, N={len(values)}')
    ax.axvline(200,color='black',ls='--',label='D36 objective: P95 ≤ 200 ms');ax.axhline(.95,color='grey',ls=':');ax.set(xlabel='Steady native inference pipeline (ms)',ylabel='Empirical cumulative fraction',title='Three fresh processes per model; batch 1; no API queue or network');ax.legend(loc='lower right');save(fig,'native_latency_ecdf')
    m2=read('model2_quality.jsonl');fig,axes=plt.subplots(2,3,figsize=(13,8))
    for row,cohort in enumerate(['legacy_dev','authored_paired_dev']):
        for name in ['baseline34','path-ablation32']:
            rs=[r for r in m2 if r['cohort']==cohort];y=np.array([r['label']=='BLOCK' for r in rs]);p=np.array([r[name]['p_block'] for r in rs]);order=np.argsort(-p,kind='stable');yy=y[order];pp=p[order];cuts=np.r_[np.flatnonzero(np.diff(pp)),len(pp)-1];tp=np.cumsum(yy)[cuts];fp=np.cumsum(~yy)[cuts];rec=np.r_[0,tp/y.sum()];fpr=np.r_[0,fp/(~y).sum()];precision=np.r_[1,tp/(tp+fp)]
            metrics=s['model2'][name]['cohorts'][cohort]['probability_metrics']['probability_diagnostics'];axes[row,0].plot(fpr,rec,label=f'{name}: AUC={metrics["roc_auc"]:.3f}');axes[row,1].step(rec,precision,where='pre',label=f'{name}: AP={metrics["pr_auc"]:.3f}')
            bins=[b for b in metrics['reliability']['bins'] if b['n']];axes[row,2].plot([b['mean_predicted'] for b in bins],[b['observed_frequency'] for b in bins],'o-',label=f'{name}: ECE={metrics["ece"]:.3f}')
        axes[row,0].plot([0,1],[0,1],'k:',alpha=.5);axes[row,2].plot([0,1],[0,1],'k:',alpha=.5)
        for col,(x,ylabel,title) in enumerate([('FPR','TPR','ROC'),('Recall','Precision','Precision / recall'),('Mean predicted attack probability','Observed attack fraction','Reliability: 15 fixed bins')]):
            axes[row,col].set(xlabel=x,ylabel=ylabel,title=f'{title} — {cohort}',xlim=(0,1),ylim=(0,1.03));axes[row,col].legend(fontsize=7)
    fig.suptitle('Model 2 probability diagnostics on DEVELOPMENT data; no calibrator fitted or threshold selected',fontsize=11);fig.tight_layout();save(fig,'model2_probability_diagnostics')
    fig,axes=plt.subplots(1,3,figsize=(13,4.2));cs=[1,4,8,16];vals=[s['load'][str(c)] for c in cs]
    axes[0].plot(cs,[v['throughput_responses_per_s'] for v in vals],'o-',label='All responses');axes[0].plot(cs,[v['goodput_valid_classifications_per_s'] for v in vals],'s-',label='Valid classifications');axes[0].set(xlabel='Concurrent clients',ylabel='Responses per second',title='API throughput vs useful work');axes[0].legend(fontsize=8)
    axes[1].plot(cs,[v['latency_all_ms']['p95'] for v in vals],'o-',label='Client P95, all responses');axes[1].plot(cs,[v['queue_wait_ms_valid']['p95'] for v in vals],'s-',label='GPU queue P95, valid responses');axes[1].set(xlabel='Concurrent clients',ylabel='Milliseconds',title='Latency includes waiting');axes[1].legend(fontsize=8)
    axes[2].bar([str(c) for c in cs],[100*v['saturation_rate'] for v in vals]);axes[2].set(xlabel='Concurrent clients',ylabel='HTTP 503 (%)',title='Saturation is not a valid classification')
    fig.suptitle('API closed-loop stress: 48 requests per level, one benign text; not sustained capacity',fontsize=11);fig.tight_layout();save(fig,'api_load')
    fig,axes=plt.subplots(1,2,figsize=(11,4.2))
    for name,data in s['gateway_load'].items():
        cs=sorted(map(int,data));axes[0].plot(cs,[data[str(c)]['goodput_authoritative_decisions_per_s'] for c in cs],'o-',label=name);axes[1].plot(cs,[data[str(c)]['client_ms_all']['p95'] for c in cs],'o-',label=name)
    for ax in axes:ax.set_xlabel('Concurrent clients');ax.legend(fontsize=8)
    axes[0].set(ylabel='Authoritative decisions / second',title='Full gateway useful work');axes[1].set(ylabel='Client latency P95 (ms)',title='Full gateway client latency');fig.suptitle('Synthetic workload: 1/3 healthz, 1/3 traversal, 1/3 catalog — controlled local sink',fontsize=11);fig.tight_layout();save(fig,'gateway_load')
    fig,axes=plt.subplots(1,2,figsize=(10,4));names=['V5_ONLY','baseline34','path-ablation32'];stages=['wire','protocol','fast_path','model2','v5'];bottom=np.zeros(3)
    for stage in stages:
        counts=np.array([s['gateway'][n]['deciding_stages'].get(stage,0) for n in names]);axes[0].bar(names,counts,bottom=bottom,label=stage);bottom+=counts
    axes[0].set(ylabel='Requests (N=600 per mode)',title='Actual deciding stages');axes[0].legend(fontsize=8)
    axes[1].bar(names,[s['gateway'][n]['actual_V5_calls'] for n in names]);axes[1].set(ylabel='Observed classifier API calls',title='Actual V5 calls, same wire workload');fig.suptitle('Measured sequential gateway traffic; no positive Fast Path match in legacy DEV',fontsize=11);fig.tight_layout();save(fig,'routes_and_actual_calls')
    print('Saved',len(list(FIG.glob('*.png'))),'PNG + PDF figures')
if __name__=='__main__':main()
