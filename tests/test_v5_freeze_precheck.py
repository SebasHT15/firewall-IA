"""A5: isolated mutation accreditation for precheck's numeric blocking checks.

Synthetic fixtures only; never re-runs A2/I7/A6 on the real dataset.
"""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from scripts.dataset.v5_freeze_precheck import check


class NumericMutationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.ds=self.root/'ds';self.ds.mkdir()
        self.manifest={'artifacts':[],'counts':{'by_split_disposition':{},'quota_shortfalls':[]},
          'gates':{'ok':True},'i9_rebalance':{'converged':True,'owner_rulings_applied':[
              {'split':'VALIDATION','cluster':'path-media'},{'split':'INTERNAL_TEST','cluster':'path-export'}]},
          'pilot_inputs':{'value_dedup':{'probe_overlap':{'remaining_overlap':0,'excluded_total':1}}},
          'diagnostics':{'over_limit_by_category_role':[{'rows':100,'over_limit':0}],
             'class_balance_C-M3':{s:{'block_share':'.5'}for s in ('TRAIN','VALIDATION','INTERNAL_TEST')}}}
        for split in ('TRAIN','VALIDATION','INTERNAL_TEST'):
            for suffix in ('.jsonl','.meta.jsonl'):
                p=self.ds/('rows.'+split+suffix);raw=b'{}\n{}\n';p.write_bytes(raw)
                self.manifest['artifacts'].append({'path':p.name,'sha256':hashlib.sha256(raw).hexdigest(),'bytes':len(raw)})
            self.manifest['counts']['by_split_disposition'][split+'|split']=2
        self.pool=self.root/'attack.jsonl';self.pool.write_text(''.join(json.dumps({'dedup_scope':'category','source_file':str(i)})+'\n'for i in range(2)))
        self.collisions=self.root/'collisions.json'
        self.assertTrue(self.run_check()['checks_run_pass'])

    def run_check(self):
        raw=(json.dumps(self.manifest)+'\n').encode();(self.ds/'manifest.json').write_bytes(raw)
        # Keep unrelated evidence bindings valid so each negative isolates its own checker.
        self.collisions.write_text(json.dumps({'blocking_pass':True,'dataset_manifest_sha256':hashlib.sha256(raw).hexdigest(),'entries':[]}))
        return check(self.ds,self.pool,self.collisions)

    def test_cm3_each_split_rejects_injected_imbalance(self):
        for split in ('TRAIN','VALIDATION','INTERNAL_TEST'):
            for share in ('.10','.90'):
                with self.subTest(split=split,share=share):
                    self.manifest['diagnostics']['class_balance_C-M3'][split]['block_share']=share
                    r=self.run_check();self.assertFalse(r['checks']['C-M3']['ok']);self.assertFalse(r['checks_run_pass'])
                    self.manifest['diagnostics']['class_balance_C-M3'][split]['block_share']='.5'
        self.assertTrue(self.run_check()['checks']['C-M3']['ok'])

    def test_source_cap_rejects_concentrated_source(self):
        self.pool.write_text(''.join(json.dumps({'dedup_scope':'category','source_file':'same'})+'\n'for i in range(2)))
        r=self.run_check();self.assertFalse(r['checks']['source_file_cap']['ok']);self.assertFalse(r['checks_run_pass'])

    def test_over_limit_rejects_excess(self):
        self.manifest['diagnostics']['over_limit_by_category_role'][0]['over_limit']=2
        r=self.run_check();self.assertFalse(r['checks']['over_limit']['ok']);self.assertFalse(r['checks_run_pass'])

    def test_l8_report_nonzero_cannot_pass(self):
        self.manifest['pilot_inputs']['value_dedup']['probe_overlap']['remaining_overlap']=1
        r=self.run_check();self.assertFalse(r['checks']['L8']['ok']);self.assertFalse(r['checks_run_pass'])


class LabelMutationTests(unittest.TestCase):
    def test_m1_to_m7_detect_their_injected_violation(self):
        from scripts.dataset import v5_labels as L
        table=L.load_policy_table()
        clean={'label_status':L.VERIFIED,'exclusion_reason':None,'policy_id':None,
               'label':L.ALLOW,'output':L.ALLOW_OUTPUT,'payload_family_id':None,'payload_record_id':None}
        self.assertTrue(L.check_m_invariants([clean],table,True)['ok'])
        changes={'M-1':{'label_status':'UNKNOWN'},'M-2':{'exclusion_reason':'UNKNOWN'},
                 'M-3':{'policy_id':'UNKNOWN'},'M-4':{'label_status':L.EXCLUDED,'label':None,'exclusion_reason':L.AMBIGUOUS},
                 'M-5':{'payload_family_id':'attack-family'},'M-6':{'payload_record_id':'attack-record'},
                 'M-7':{'output':'invalid-output'}}
        for invariant,change in changes.items():
            with self.subTest(invariant=invariant):
                result=L.check_m_invariants([{**clean,**change}],table,True)
                self.assertFalse(result[invariant]['ok']);self.assertFalse(result['ok'])

    def test_m8_detects_a_field_name_parameter(self):
        from unittest.mock import patch
        from scripts.dataset import v5_labels as L
        self.assertTrue(L.check_m8_signature()['ok'])
        def forbidden(field_name):return False
        with patch.object(L,'is_addr_data',forbidden):
            self.assertFalse(L.check_m8_signature()['ok'])
