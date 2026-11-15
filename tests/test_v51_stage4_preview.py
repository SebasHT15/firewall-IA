"""Representation and reserve-boundary negatives for the proposed dataset."""
import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.parse import quote_plus

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts/v5_successor'))
import audit_stage4_preview as A


class PreviewBoundaryTests(unittest.TestCase):
    def row(self,value,*,carrier='query',kind='url',role='benign'):
        encoded=json.dumps(value) if carrier=='json' else quote_plus(value)
        text=('POST /inspect HTTP/1.1\nContent-Type: application/json\n\n{"token":'+encoded+'}'
              if carrier=='json' else 'GET /inspect?token='+encoded+' HTTP/1.1\n\n')
        start=text.index(encoded)
        meta=dict(pair_id='pair',pair_role=role,template_id='tpl',carrier=carrier,
                  payload_record_id='src' if role=='twin' else None,
                  attacked_slot='value',attacked_slot_type='url',label='BLOCK' if role=='twin' else 'ALLOW',
                  attack_category='Server Side Request Forgery',attacked_slot_role=A.L.DATA,
                  leaf_spans={'value':[start,start+len(encoded)]})
        catalog=SimpleNamespace(by_id={'tpl':SimpleNamespace(slots=[SimpleNamespace(
            slot_id='value',location=carrier,value_type=kind)])})
        return dict(meta=meta,text=text),catalog

    def check_identity(self,value,**kwargs):
        row,catalog=self.row(value,**kwargs)
        registry={'src':dict(payload_sha256=hashlib.sha256(value.encode()).hexdigest(),
                            payload_logical=value,label_status='POLICY_DEFINED',label_status_basis='policy_defined',
                            source_category='Server Side Request Forgery',policy_id='POL-URL-META',
                            attack_category='Server Side Request Forgery',special_use_numeric_addresses=['169.254.169.254'])}
        return A.identity_audit([row],registry,A.L.load_policy_table(),catalog)

    def test_reserve_rejected_before_any_input_is_opened(self):
        with patch.object(A,'read_bound',side_effect=AssertionError('opened')) as read:
            with self.assertRaisesRegex(ValueError,'reserve'):
                A.read_preview_splits([{'split':'RESERVE_CANDIDATE','path':'do-not-open'}])
            read.assert_not_called()

    def test_carrier_token_name_is_not_a_real_credential(self):
        self.assertEqual(self.check_identity('https://docs.example/page')['failures'],[])

    def test_credentials_inside_value_are_still_rejected(self):
        result=self.check_identity('https://docs.example/?token=not-a-real-secret')
        self.assertEqual(result['failures'][0]['reason'],'CREDENTIAL_KEY')

    def test_standalone_email_is_rejected(self):
        self.assertEqual(self.check_identity('person@unreserved-host.com')['failures'][0]['reason'],'EMAIL_SHAPED_TEXT')

    def test_global_address_is_not_a_special_use_exception(self):
        self.assertEqual(self.check_identity('https://8.8.8.8/path',role='twin')['failures'][0]['reason'],'GLOBAL_LITERAL_ADDRESS')

    def test_numeric_policy_source_requires_exact_context(self):
        value='http://169.254.169.254/latest/metadata/'
        self.assertEqual(self.check_identity(value,role='twin')['scoped_numeric_rows'],1)
        self.assertEqual(self.check_identity(value)['failures'][0]['reason'],'NUMERIC_HOST_OUTSIDE_BOUND_ATTACK')

    def test_json_roundtrip_preserves_url_delimiters(self):
        value='https://docs.example/a?q=one&next=two'
        row,_=self.row(value,carrier='json')
        self.assertEqual(A.logical_from_span(row),value)
        self.assertFalse(self.check_identity(value,carrier='json')['failures'])

    def test_query_roundtrip_preserves_literal_plus(self):
        value='https://docs.example/a+b?q=one&next=two'
        row,_=self.row(value)
        self.assertEqual(A.logical_from_span(row),value)

    def test_generated_scalar_token_cannot_hide_other_text(self):
        result=self.check_identity('arbitrary-value',kind='token')
        self.assertEqual(result['failures'][0]['reason'],'SYNTHETIC_TOKEN_PROVENANCE_MISMATCH')


if __name__=='__main__':unittest.main()
