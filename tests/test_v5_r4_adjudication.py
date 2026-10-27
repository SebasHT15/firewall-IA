"""Frozen-r4 precedence, coverage, Wilson boundaries and sealed input collection."""
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts/dataset'))
import adjudicate_v5_r4_continuation as A
from tests.v5_audit_fixture import make_bundle
from tests.test_v5_postfilter_collect import transcript

PREREG={'schema':'v5-postfilter-preregistration/r4','status':'FROZEN',
        'acceptance_criteria':{'C1':{'limit':.20},'C2':{'limit':.35}},'wilson':{'z':1.96}}


def write_json(path,obj):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(obj,ensure_ascii=False)+'\n')


def write_rows(path,items):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(''.join(json.dumps(r,ensure_ascii=False)+'\n' for r in items))


class Rules(unittest.TestCase):
    def test_all_vote_combinations_match_original_frozen_execution(self):
        path=ROOT/'reports/v5/postfilter-audit/r3-execution-2026-10-23/adjudicate.py'
        spec=importlib.util.spec_from_file_location('original_r4',path)
        original=importlib.util.module_from_spec(spec);spec.loader.exec_module(original)
        for l1 in (*A.LABELS,None):
            for l2 in (*A.LABELS,None):
                for l3 in (*A.LABELS,None):
                    self.assertEqual(A.adjudicate(l1,l2,l3),original.adjudicate(l1,l2,l3))

    def trace(self,incorrect=0,uncertain=0):
        return [{'sample_id':str(i),'category':'fixture','r3':'VERIFIABLE',
                 'adjudicated_label':'INCORRECT' if i<incorrect else 'UNCERTAIN' if i<incorrect+uncertain else 'VERIFIABLE'} for i in range(50)]

    def test_wilson_limits_at_full_denominator(self):
        for incorrect,uncertain,expected in ((4,6,'PASS_AI_AUDITED'),(5,0,'NOT_SUPPORTED'),(0,11,'NOT_SUPPORTED')):
            got=A.summarize(self.trace(incorrect,uncertain),PREREG)['fixture']
            self.assertEqual(got['status'],expected)
            self.assertEqual(got['frame_n'],50)

    def test_missing_r3_blocks_even_concordant_pair_and_unresolved_not_scored(self):
        trace=self.trace();trace[0]['r3']=None
        got=A.summarize(trace,PREREG)['fixture']
        self.assertEqual(got['status'],'INSUFFICIENT_EVIDENCE')
        self.assertIsNone(got['wilson_incorrect_upper'])
        trace=self.trace();trace[0]['adjudicated_label']=None
        got=A.summarize(trace,PREREG)['fixture']
        self.assertEqual(got['adjudicated_counts'].get('INCORRECT',0),0)
        self.assertEqual(got['unresolved_ids'],['0'])


class SealedInputs(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.round=self.root/'round-2';self.round.mkdir()
        self.r3=self.root/'r3';self.r3.mkdir()
        self.frame=[{'sample_id':f'PF2-{i:04d}','category':'fixture','payload_wire':f'fixture_synthetic {i}',
                     'payload_logical':f'fixture_synthetic {i}','source_file':'fixture.txt'} for i in range(50)]
        write_rows(self.round/'sample.jsonl',self.frame)
        sample_sha=A.AE.sha256((self.round/'sample.jsonl').read_bytes())
        prior=make_bundle(self.root/'prior',outcomes={'fixture':'FAIL'})
        prereg=self.root/'prereg.json';write_json(prereg,PREREG)
        state={'review_method':'D67_R4_AI_ONLY_CONTINUATION','round':2,'prior_r4_evidence':prior,
               'sample':{'sha256':sample_sha},'r3_preselected_sample':{'sha256':sample_sha,'rows':50},
               'categories_audited':['fixture'],'per_category':{'fixture':{'sample':50}},
               'r4_preregistration':{'path':str(prereg),'sha256':A.AE.sha256(prereg.read_bytes())}}
        write_json(self.round/'audit_state.json',state)
        write_json(self.round/'annotators.json',{'a1':{'model':'fixture-model1'},'a2':{'model':'fixture-model2'}})
        for who,model in (('a1','fixture-model1'),('a2','fixture-model2')):
            base=self.round/f'annotation_{who}';base.mkdir()
            (base/'README.md').write_text('fixture instructions')
            write_rows(base/'packet.jsonl',self.frame)
            man=A.K.make_batches(str(self.round),who,25)
            for b in man['batches']:
                handback='\n'.join(json.dumps({'sample_id':sid,'label_class':'VERIFIABLE','failure_mode':None,
                           'better_category':None,'note':'synthetic fixture'}) for sid in b['sample_ids'])
                tr=transcript(str(self.root/f"{who}-{b['batch']}.jsonl"),[str(base/'README.md'),str(base/b['file'])],handback,model=model)
                rec=A.K.collect(str(self.round),who,b['batch'],tr,model,1,f"fixture-{who}-{b['batch']}")
                self.assertEqual(rec['status'],'ACCEPTED')
            A.K.assemble(str(self.round),who)
        outputs=[{'sample_id':r['sample_id'],'label':'VERIFIABLE','failure_mode':None,'better_category':None,
                  'rationale':'synthetic fixture'} for r in self.frame]
        write_rows(self.r3/'reviewer/batch_01.jsonl',self.frame)
        write_rows(self.r3/'raw/batch_01.jsonl',outputs)
        write_rows(self.r3/'responses.jsonl',outputs)
        write_json(self.r3/'execution-record.json',{'sample_sha256':sample_sha,'fork_turns':'none','requested_model':'gpt-6-sol',
                   'aggregate_sha256':A.AE.sha256((self.r3/'responses.jsonl').read_bytes()),
                   'batches':[{'batch':1,'packet_sha256':A.AE.sha256((self.r3/'reviewer/batch_01.jsonl').read_bytes()),
                               'response_sha256':A.AE.sha256((self.r3/'raw/batch_01.jsonl').read_bytes())}]})
        self.seal()

    def seal(self):
        files=sorted(p for p in self.r3.rglob('*') if p.is_file() and p.name!='SHA256SUMS')
        (self.r3/'SHA256SUMS').write_text(''.join(A.AE.sha256(p.read_bytes())+'  '+str(p.relative_to(self.r3))+'\n' for p in files))

    def test_full_capture_collects_validated_raw_without_authorizing_training(self):
        report,trace=A.run(self.round,self.r3)
        self.assertEqual(report['category_outcomes']['fixture']['status'],'PASS_AI_AUDITED')
        self.assertEqual((report['frame_rows'],report['r3_rows']), (50,50))
        self.assertFalse(report['training_authorized']);self.assertFalse(report['human_validation'])
        self.assertEqual(len(trace),50)
        self.assertTrue(any(p.endswith('/sample.jsonl') for p in report['source_sha256']))

    def test_relabelled_official_annotations_refused(self):
        path=self.round/'annotations_a1.jsonl';items=A.rows(path.read_bytes())
        items[0]['label_class']='UNCERTAIN';write_rows(path,items)
        with self.assertRaisesRegex(ValueError,'differ from collected'):A.run(self.round,self.r3)

    def test_raw_r3_integrity_and_model_identity_refused(self):
        path=self.r3/'raw/batch_01.jsonl';path.write_bytes(path.read_bytes()+b' ')
        with self.assertRaisesRegex(ValueError,'integrity'):A.run(self.round,self.r3)
        # Restore the raw bytes and change the declared annotation model instead.
        path.write_bytes(path.read_bytes()[:-1])
        write_json(self.round/'annotators.json',{'a1':{'model':'other'},'a2':{'model':'fixture-model2'}})
        with self.assertRaisesRegex(ValueError,'model mismatch'):A.run(self.round,self.r3)

    def test_missing_annotations_do_not_produce_an_outcome(self):
        (self.round/'annotations_a2.jsonl').unlink()
        with self.assertRaises(FileNotFoundError):A.run(self.round,self.r3)


if __name__=='__main__':unittest.main()
