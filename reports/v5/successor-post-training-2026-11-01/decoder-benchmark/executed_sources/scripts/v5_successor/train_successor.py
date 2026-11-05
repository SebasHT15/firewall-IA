"""CPU review/gates and owner-admitted EXPERIMENTAL training of the successor.

No FINAL mode and no permission override. Reuses the existing tokenizer,
completion masks, schedule, fitting and adapter verification unchanged.
"""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import subprocess
import sys
import time

from successor_contract import REPO,D,Refused,prepare,sha

GPU_STATUS=Path('/home/sebas/Documents/Codex/2026-10-26/ta/outputs/Coordinacion_modelos_arquitectura/GPU_STATUS.json')


def gpu_available(status,process_lines):
    if status.get('owner') not in (None,'Codex'):
        raise Refused('GPU reserved by '+str(status.get('owner'))+'; do not interrupt that work')
    if any(line.strip() and '/usr/bin/ptyxis' not in line for line in process_lines):
        raise Refused('another GPU compute process is running')


def claim_gpu():
    status=json.loads(GPU_STATUS.read_text())
    lines=subprocess.check_output(['nvidia-smi','--query-compute-apps=pid,process_name','--format=csv,noheader'],text=True).splitlines()
    gpu_available(status,lines)
    GPU_STATUS.write_text(json.dumps(dict(owner='Codex',state='IN_USE_BY_CODEX',pid=os.getpid(),UTC=time.time(),
        note='Owner-admitted V51 experimental training. Do not run architecture GPU work concurrently.'),indent=2)+'\n')


def release_gpu():
    current=json.loads(GPU_STATUS.read_text())
    if current.get('pid')==os.getpid() and current.get('owner')=='Codex':
        GPU_STATUS.write_text(json.dumps(dict(owner=None,state='AVAILABLE',UTC=time.time(),
            note='V51 training process ended; inspect its report for outcome.'),indent=2)+'\n')


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--manifest',type=Path,required=True)
    parser.add_argument('--authorization',type=Path)
    parser.add_argument('--mode',choices=['review','gate','train'],default='review')
    parser.add_argument('--report-dir',type=Path,required=True)
    parser.add_argument('--run-id')
    args=parser.parse_args()
    if args.report_dir.exists():raise Refused('report directory exists; use a new one')
    if args.mode!='train':
        for key in ('OMP_NUM_THREADS','OPENBLAS_NUM_THREADS','MKL_NUM_THREADS','TOKENIZERS_PARALLELISM'):
            os.environ[key]='false' if key=='TOKENIZERS_PARALLELISM' else '1'
    args.report_dir.mkdir(parents=True)
    record=dict(mode=args.mode,scope='EXPERIMENTAL_V5_SUCCESSOR_NOT_FINAL',training_started=False,
                started_utc=dt.datetime.now(dt.timezone.utc).isoformat(),
                reserve_opened=False,protected_evaluation_used=False)
    def save():
        (args.report_dir/'run_record.json').write_text(json.dumps(record,indent=2)+'\n')
    started=time.perf_counter()
    try:
        manifest,msha,rows,recipe,protocol=prepare(args.manifest,authorization=args.authorization,
                                                  training=args.mode!='review')
        import finetune_v5 as F
        versions=F.installed_versions()
        mismatched={k:dict(expected=v,installed=versions.get(k)) for k,v in recipe['library_pins'].items()
                    if k not in ('status','source') and not str(versions.get(k,'')).startswith(str(v))}
        if mismatched:raise Refused('library pin mismatch: '+json.dumps(mismatched))
        # Tokenizer only: no base weights, CUDA allocation or model fitting in
        # review/gate mode. Template-safe complete sequences, never truncation.
        from transformers import AutoTokenizer
        bm=recipe['base_model']
        tok=AutoTokenizer.from_pretrained(bm['name'],revision=bm['revision'],local_files_only=True)
        contract,diags=D.measure_contract(tok,recipe)
        train_ex,d1=D.build_examples(tok,recipe,contract,rows['TRAIN'])
        val_ex,d2=D.build_examples(tok,recipe,contract,rows['VALIDATION'])
        if diags+d1+d2:raise Refused('tokenization: '+','.join(d.code for d in diags+d1+d2))
        record.update(manifest_sha256=msha,recipe_sha256=manifest['recipe']['sha256'],
                      source_sha256=manifest['source_sha256'],versions=versions,git=D.git_state(),
                      token_contract=contract.__dict__,schedule=F.compute_schedule(recipe,len(train_ex)),
                      examples=dict(train=len(train_ex),validation=len(val_ex),rejected=0,truncated=0,
                                    max_sequence_tokens=max(len(e['input_ids']) for e in train_ex+val_ex),
                                    max_content_tokens=max(e['content_tokens'] for e in train_ex+val_ex),
                                    completion_token_lengths=sorted({e['completion_tokens'] for e in train_ex+val_ex})),
                      technical_checks_passed=True,owner_admission_passed=args.mode!='review')
        if args.mode!='train':
            record.update(outcome='TECHNICAL_REVIEW_PASSED_PENDING_OWNER_AND_COMMIT' if args.mode=='review' else 'TRAINING_GATES_PASSED_NO_TRAINING',
                          duration_s=time.perf_counter()-started)
            save();print(json.dumps(record,indent=2));return 0
        run_id=args.run_id or 'v51-'+dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+msha[:12]
        if '/' in run_id or run_id in ('.','..'):raise Refused('run-id must be one directory name')
        out=REPO/'model-output-v5/experimental'/run_id
        if out.exists():raise Refused('training output already exists')
        claim_gpu()
        try:
            record.update(training_started=True,outcome='TRAINING',output_dir=str(out),
                          evidence_class='OWNER_ADMITTED_EXPERIMENTAL_COMPOSITION')
            save()
            prep=D.PreparedData(D.EXPERIMENTAL,manifest,msha,rows['TRAIN'],rows['VALIDATION'],
                                gate_evidence=dict(owner_admission=True,parent_source_bound=True,policy_proof_bound=True))
            # Call the existing fitter only AFTER the new composition admission,
            # committed-code, lineage, token and GPU coordination gates passed.
            fit_args=argparse.Namespace(max_steps=None,report_dir=str(args.report_dir))
            return F.train_and_verify(fit_args,D.EXPERIMENTAL,recipe,prep,tok,contract,train_ex,val_ex,str(out),record,started)
        finally:release_gpu()
    except (Refused,OSError,ValueError) as exc:
        record.update(outcome='REFUSED',refusal=str(exc),duration_s=time.perf_counter()-started)
        save();print('REFUSED: '+str(exc),file=sys.stderr);return 3


if __name__=='__main__':raise SystemExit(main())
