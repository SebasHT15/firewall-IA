"""Preparation never transfers category admission; synthetic chain and candidate only."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts/dataset'))
import v5_source_readmission as R
from tests.v5_audit_fixture import make_bundle


class SourcePreparationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.candidate=self.root/'candidate';self.candidate.mkdir()
        self.records=[{'record_id':cat,'category_v4':cat,'dedup_scope':cat,'payload_wire':'synthetic '+cat,
                       'source_file':'synthetic','status':R.C.ACCEPTED,'label_status':R.C.LABEL_PENDING}
                      for cat in sorted(R.M.FOCUS|{'path_file_access'})]
        outcomes={cat:('PASS_AI_AUDITED' if cat=='path_file_access' else 'INSUFFICIENT_EVIDENCE')
                  for cat in R.M.FOCUS|{'path_file_access'}}
        self.binding=make_bundle(self.root/'baseline',records=self.records,outcomes=outcomes)
        self.manifest={'schema':'v5-remediation-candidate-pool/proposal-v1','training_eligible':False,
                       'audit_outcomes_inherited':False,'implementation_sha256':{},'artifacts':[]}
        for name in sorted(R.ARTIFACTS):
            raw=(''.join(json.dumps(r)+'\n' for r in self.records) if name=='candidate_pool.jsonl' else '').encode()
            (self.candidate/name).write_bytes(raw)
            self.manifest['artifacts'].append({'path':name,'sha256':hashlib.sha256(raw).hexdigest(),
                                              'bytes':len(raw),'rows':len(self.records) if raw else 0})
        self.save()

    def save(self):
        (self.candidate/'proposal_manifest.json').write_text(json.dumps(self.manifest))

    def reseal(self):
        for art in self.manifest['artifacts']:
            raw=(self.candidate/art['path']).read_bytes();art.update(sha256=hashlib.sha256(raw).hexdigest(),bytes=len(raw))
        self.save()

    def test_continuity_is_reported_without_admission_or_sample(self):
        report=R.prepare(self.candidate,self.binding)
        self.assertEqual(report['status'],'PREPARED_NOT_ADMITTED')
        self.assertFalse(report['training_authorized']);self.assertFalse(report['sample_drawn'])
        self.assertFalse(report['audit_results_transferred'])
        self.assertEqual(report['out_of_scope_continuity']['records'],1)
        self.assertTrue(all(r['new_outcome'] is None for r in report['categories'].values()))

    def test_tampered_artifact_and_duplicate_descriptors_refused(self):
        path=self.candidate/'candidate_pool.jsonl';raw=path.read_bytes();path.write_bytes(raw+b' ')
        with self.assertRaisesRegex(ValueError,'hash mismatch'):R.prepare(self.candidate,self.binding)
        path.write_bytes(raw)
        self.manifest['artifacts'].append(copy.deepcopy(self.manifest['artifacts'][0]));self.save()
        with self.assertRaisesRegex(ValueError,'duplicate'):R.prepare(self.candidate,self.binding)

    def test_resealed_non_pending_labels_and_out_of_scope_drift_refused(self):
        path=self.candidate/'candidate_pool.jsonl'
        for field,value in [('label_status','VERIFIED'),('payload_wire','changed out of scope')]:
            changed=copy.deepcopy(self.records)
            changed[-1][field]=value
            path.write_text(''.join(json.dumps(r)+'\n' for r in changed));self.reseal()
            with self.assertRaises(ValueError):R.prepare(self.candidate,self.binding)

    def test_false_prior_exchange_and_training_flags_refused(self):
        binding=copy.deepcopy(self.binding);binding['exchange']['sha256']='0'*64
        with self.assertRaises(ValueError):R.prepare(self.candidate,binding)
        self.manifest['training_eligible']=True;self.save()
        with self.assertRaisesRegex(ValueError,'non-trainable'):R.prepare(self.candidate,self.binding)


if __name__=='__main__':unittest.main()
