"""Authoritative r4 continuation selection, preserving history/seed/round limits."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts/dataset'))
import audit_v5_postfilter as A
import v5_audit_evidence as AE
from tests.v5_audit_fixture import make_bundle


class R4ContinuationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.history=self.root/'history';prior=self.history/'round-1';prior.mkdir(parents=True)
        outcomes={'SQL Injection':'FAIL','XSS Injection':'INSUFFICIENT_EVIDENCE',
                  'path_file_access':'PASS_AI_AUDITED'}
        self.binding=make_bundle(self.root/'evidence',outcomes=outcomes)
        state=json.loads(Path(self.binding['state']['path']).read_bytes())
        state.update(seed='used-seed',human_seed='used-seed/human',round=1)
        path=prior/'audit_state.json';path.write_text(json.dumps(state))
        self.binding['state']={'path':str(path),'sha256':AE.sha256(path.read_bytes())}
        # The stale report deliberately contradicts the authoritative R3 result.
        (prior/'report.json').write_text(json.dumps({'categories':{c:{'status':'PASS'} for c in outcomes}}))
        self.doc=self.root/'change.md';self.doc.write_text('Synthetic documented filter correction')
        self.pool_sha=state['pool']['sha256']

    def check(self,**kwargs):
        kw={'prior_r4_binding':self.binding,'categories':['SQL Injection','XSS Injection']};kw.update(kwargs)
        return A.check_round(str(self.history),2,'new-seed','f'*64,str(self.doc),**kw)

    def test_authoritative_fail_and_insufficient_both_selected(self):
        self.assertEqual(self.check(),['SQL Injection','XSS Injection'])

    def test_pass_unknown_empty_and_duplicate_selection_refused(self):
        for selection in (['path_file_access'],['unknown'],[],['XSS Injection']*2):
            with self.subTest(selection=selection),self.assertRaises(A.AuditError):
                self.check(categories=selection)

    def test_tampered_binding_and_unrelated_history_refused(self):
        wrong=copy.deepcopy(self.binding);wrong['report']['sha256']='0'*64
        with self.assertRaises(A.AuditError):self.check(prior_r4_binding=wrong)
        path=self.history/'round-1/audit_state.json';state=json.loads(path.read_bytes())
        state['seed']='different-history';path.write_text(json.dumps(state))
        with self.assertRaises(A.AuditError):self.check()

    def test_round_seed_pool_and_change_limits_still_apply(self):
        for seed in ('used-seed','used-seed/human'):
            with self.assertRaises(A.AuditError):
                A.check_round(str(self.history),2,seed,'f'*64,str(self.doc),prior_r4_binding=self.binding,categories=['SQL Injection'])
        with self.assertRaises(A.AuditError):
            A.check_round(str(self.history),2,'new-seed',self.pool_sha,str(self.doc),prior_r4_binding=self.binding,categories=['SQL Injection'])
        self.doc.write_text('')
        with self.assertRaises(A.AuditError):self.check()
        with self.assertRaises(A.AuditError):
            A.check_round(str(self.history),3,'new-seed','f'*64,str(self.doc),prior_r4_binding=self.binding,categories=['SQL Injection'])

    def test_legacy_human_report_refuses_r4_continuation_before_reading_labels(self):
        d=self.history/'round-2';d.mkdir()
        (d/'audit_state.json').write_text(json.dumps({'review_method':'D67_R4_AI_ONLY_CONTINUATION'}))
        with self.assertRaisesRegex(A.AuditError,'legacy human-review report is inapplicable'):
            A.report(str(self.history),2)

    def test_existing_round_cannot_be_redrawn(self):
        (self.history/'round-2').mkdir()
        with self.assertRaises(A.AuditError):self.check()


if __name__=='__main__':unittest.main()
