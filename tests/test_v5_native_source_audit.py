"""Integration checks using the actual sealed native-source evidence bundles."""
import copy
import hashlib
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts/dataset'))
import v5_audit_evidence as AE
import v5_component_binding as CB

def sha(raw):return hashlib.sha256(raw).hexdigest()

class NativeSourceAudit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.components=json.loads((ROOT/'reports/v5/postfilter-audit/final-component-bindings.json').read_bytes())['components']

    def test_real_three_component_binding(self):
        rows=[]
        for comp in self.components:
            declared=set(comp['categories'])
            AE.verify(comp['audit_evidence'],expected_outcomes=comp['category_outcomes'])
            for line in (ROOT/comp['audit_evidence']['pool']['path']).read_text().splitlines():
                rec=json.loads(line)
                cat=next((rec.get(k) for k in ('category_v4','d47_category','dedup_scope')
                          if rec.get(k) in declared),None)
                if cat is not None:
                    rows.append({'meta':{'label':'BLOCK','attack_category':cat,
                                         'payload_record_id':rec['record_id'],
                                         'payload_wire':rec['payload_wire']}})
        got=CB.resolve_components(rows,self.components)
        self.assertEqual(got['diags'],[])
        self.assertEqual(len(rows),1816)
        self.assertEqual(set(got['merged_outcomes'].values()),{'PASS_AI_AUDITED'})

    def test_owner_result_vote_tampering_is_rejected(self):
        binding=copy.deepcopy(self.components[1]['audit_evidence'])
        result=json.loads((ROOT/binding['result']['path']).read_bytes())
        result['traces'][0]['a1']='INCORRECT'
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'tampered.json'
            raw=(json.dumps(result,ensure_ascii=False,sort_keys=True)+'\n').encode()
            path.write_bytes(raw)
            binding['result']={'path':str(path),'sha256':sha(raw)}
            with self.assertRaisesRegex(ValueError,'vote or label modified'):
                AE.verify(binding)

    def test_sqli_result_tampering_is_rejected(self):
        binding=copy.deepcopy(self.components[2]['audit_evidence'])
        result=json.loads((ROOT/binding['result']['path']).read_bytes())
        result['traces'][0]['adjudicated_label']='INCORRECT'
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'tampered.json'
            raw=(json.dumps(result,ensure_ascii=False,sort_keys=True)+'\n').encode()
            path.write_bytes(raw)
            binding['result']={'path':str(path),'sha256':sha(raw)}
            with self.assertRaisesRegex(ValueError,'differs from frozen votes'):
                AE.verify(binding)

if __name__=='__main__':unittest.main()
