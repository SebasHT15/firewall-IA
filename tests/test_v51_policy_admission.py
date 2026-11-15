"""Negative scope tests: a source-specific proposal is never a global exception."""
import hashlib,sys,unittest
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'scripts/v5_successor'),str(ROOT/'scripts/dataset')]
import policy_admission_proposal as A
import v5_labels as L
class AdmissionScopeTests(unittest.TestCase):
    def setUp(self):
        self.table=L.load_policy_table();self.value='http://169.254.169.254/latest/metadata/'
        self.row=dict(payload_sha256=hashlib.sha256(self.value.encode()).hexdigest(),label_status='POLICY_DEFINED',label_status_basis='policy_defined',source_category='Server Side Request Forgery',policy_id='POL-URL-META',attack_category='Server Side Request Forgery',special_use_numeric_addresses=['169.254.169.254'])
        self.args=dict(registry={'registered':self.row},slot_type='url',label='BLOCK',category='Server Side Request Forgery',role=L.DATA,table=self.table)
    def call(self,**kwargs):
        args=dict(self.args);args.update(kwargs);return A.validate_registered_url('registered',self.value,**args)
    def test_registered_policy_context_is_only_a_draft_pass(self):
        result=self.call();self.assertFalse(result['owner_approved']);self.assertFalse(result['training_authorized'])
    def test_same_address_unknown_source_rejected(self):
        with self.assertRaisesRegex(A.AdmissionError,'unregistered'):self.call(registry={})
    def test_same_address_allow_row_rejected(self):
        with self.assertRaisesRegex(A.AdmissionError,'context'):self.call(label='ALLOW')
    def test_same_address_non_url_slot_rejected(self):
        with self.assertRaisesRegex(A.AdmissionError,'context'):self.call(slot_type='free_string')
    def test_actual_navigation_role_replays_same_block_policy(self):
        self.assertEqual(self.call(role=L.NAVIGATION)['policy_id'],'POL-URL-META')
    def test_undefined_role_is_rejected(self):
        with self.assertRaisesRegex(A.AdmissionError,'role'):self.call(role='fetch')
    def test_registered_value_cannot_pass_under_a_different_policy(self):
        self.row['policy_id']='POL-URL-SCHEME'
        with self.assertRaisesRegex(A.AdmissionError,'policy replay'):self.call()
    def test_value_cannot_be_changed(self):
        self.row['payload_sha256']='f'*64
        with self.assertRaisesRegex(A.AdmissionError,'value changed'):self.call()
    def test_category_cannot_be_changed(self):
        with self.assertRaisesRegex(A.AdmissionError,'category'):self.call(category='SQL Injection')
    def test_global_address_is_never_admitted(self):
        self.row['special_use_numeric_addresses']=['8.8.8.8']
        with self.assertRaisesRegex(A.AdmissionError,'bounded'):self.call()
    def test_provenance_cannot_be_upgraded_to_verified(self):
        self.row['label_status']='VERIFIED'
        with self.assertRaisesRegex(A.AdmissionError,'evidence'):self.call()
if __name__=='__main__':unittest.main()
