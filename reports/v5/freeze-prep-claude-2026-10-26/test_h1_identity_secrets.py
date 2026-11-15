"""H1 positive/negative tests; fixtures only, no production secrets or v3 mutation."""
import contextlib
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parent))
import h1_identity_secrets_scan as H


class H1Tests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.pins={}
        self.safe='synthetic-P@ss!abc123XYZ'
        for pool,values in {'passwords':[self.safe,'x_@ru1oj.Bj!tIy!-g'],'prose_en':['An apple is on the table.']}.items():
            folder=self.root/pool;folder.mkdir()
            raw=b''.join((json.dumps({'pool_id':pool,'value':v,'value_entry_id':H.value_id(pool,v),
               'status':'ACCEPTED','exclusion_reason':None,'source_ref':'synthetic-test', 'constructed':True})+'\n').encode() for v in values)
            (folder/(pool+'.jsonl')).write_bytes(raw)
            man=(json.dumps({'artifacts':[{'path':pool+'.jsonl','sha256':H.digest(raw),'bytes':len(raw)}]})+'\n').encode()
            (folder/'manifest.json').write_bytes(man);self.pins[pool]=(str(folder),H.digest(man))
        self.marker_meta={'label':'BLOCK','attack_category':'XSS Injection','payload_record_id':H.MARKER_PAYLOAD_RECORD_ID}

    def scan(self,text,meta=None,*,proof=None):
        meta=copy.deepcopy(meta or {'label':'ALLOW'})
        meta['text_sha256']=H.digest(text.encode())
        if proof:
            pool,value=proof;start=text.index(value)
            meta.update(values=[value],value_entries=[[pool,H.value_id(pool,value)]],leaf_spans={'s0':[start,start+len(value)]})
        for split in ('TRAIN','VALIDATION','INTERNAL_TEST'):
            (self.root/f'rows.{split}.jsonl').write_text(json.dumps({'text':text})+'\n' if split=='TRAIN' else '')
            (self.root/f'rows.{split}.meta.jsonl').write_text(json.dumps(meta)+'\n' if split=='TRAIN' else '')
        return H.scan(self.root,pool_pins=self.pins)

    def test_reserved_hosts_pass(self):
        self.assertTrue(self.scan('GET http://sub.example.com/x HTTP/1.1\nHost: localhost')['H1_pass_on_v3'])

    def test_marker_exact_context(self):
        self.assertTrue(self.scan('GET / HTTP/1.1\n\n'+H.MARKER_PAYLOAD,self.marker_meta)['H1_pass_on_v3'])

    def test_marker_form_encoded(self):
        self.assertTrue(self.scan('GET /?x=%3Cbase+href%3Dhttp://%5BATTACKER.DOMAIN.TLD%5D%3E HTTP/1.1',self.marker_meta)['H1_pass_on_v3'])

    def test_marker_double_encoded(self):
        p=H.urllib.parse.quote(H.urllib.parse.quote(H.MARKER_PAYLOAD))
        self.assertTrue(self.scan('GET /?x='+p+' HTTP/1.1',self.marker_meta)['H1_pass_on_v3'])

    def test_marker_same_host_elsewhere(self):
        self.assertFalse(self.scan('GET http://attacker.domain.tld/x HTTP/1.1',self.marker_meta)['H1_pass_on_v3'])

    def test_marker_plus_second_occurrence_same_row(self):
        self.assertFalse(self.scan('GET / HTTP/1.1\n\n'+H.MARKER_PAYLOAD+' http://attacker.domain.tld/x',self.marker_meta)['H1_pass_on_v3'])

    def test_marker_wrong_category(self):
        self.assertFalse(self.scan(H.MARKER_PAYLOAD,{**self.marker_meta,'attack_category':'SQL Injection'})['H1_pass_on_v3'])

    def test_marker_wrong_id(self):
        self.assertFalse(self.scan(H.MARKER_PAYLOAD,{**self.marker_meta,'payload_record_id':'wrong'})['H1_pass_on_v3'])

    def test_marker_wrong_label(self):
        self.assertFalse(self.scan(H.MARKER_PAYLOAD,{**self.marker_meta,'label':'ALLOW'})['H1_pass_on_v3'])

    def test_authority_complete_userinfo_port(self):
        r=self.scan('GET http://user:pw@sub.evil-corp.example123.com:8443/p?q=1 HTTP/1.1')
        self.assertIn('sub.evil-corp.example123.com',r['distinct_hosts']);self.assertFalse(r['H1_pass_on_v3'])

    def test_ipv6_not_silently_dropped(self):
        r=self.scan('GET http://[2001:db8::1]/ HTTP/1.1')
        self.assertIn('2001:db8::1',r['distinct_hosts']);self.assertFalse(r['H1_pass_on_v3'])

    def test_single_label_not_silently_dropped(self):
        self.assertFalse(self.scan('GET http://intranet/ HTTP/1.1')['H1_pass_on_v3'])

    def test_invalid_authority_fails_closed(self):
        for a in ['example.com%00.evil','[not.an.ip]','[2001:db8::1','example.com:wrong','example.com:70000','example.com&bad=x']:
            with self.subTest(a=a):self.assertFalse(self.scan('GET http://'+a+'/ HTTP/1.1')['H1_pass_on_v3'])

    def test_external_email_fails(self):
        self.assertFalse(self.scan('POST / HTTP/1.1\n\n{"contact":"person@sample-mail.com"}')['H1_pass_on_v3'])

    def test_email_in_comment_not_automatically_exempt(self):
        self.assertFalse(self.scan('POST / HTTP/1.1\n\n{"comment":"person@sample-mail.com"}')['H1_pass_on_v3'])

    def test_email_prefix_without_provenance_fails(self):
        self.assertFalse(self.scan('POST / HTTP/1.1\n\n{"passphrase":"x_@ru1oj.Bj!tIy!-g"}')['H1_pass_on_v3'])

    def test_email_prefix_with_exact_provenance(self):
        value='x_@ru1oj.Bj!tIy!-g'
        r=self.scan('POST / HTTP/1.1\n\n{"passphrase":"'+value+'"}',proof=('passwords',value))
        self.assertTrue(r['H1_pass_on_v3']);self.assertTrue(r['subcontrols']['email']['candidates'][0]['provenance'])

    def test_unknown_credential_is_unresolved_not_pass(self):
        r=self.scan('POST / HTTP/1.1\n\n{"password":"not-in-controlled-pool-123XYZ"}')
        self.assertTrue(r['subcontrols']['credential']['unresolved']);self.assertFalse(r['H1_pass_on_v3'])

    def test_credential_exact_pinned_provenance(self):
        r=self.scan('POST / HTTP/1.1\n\n{"password":"'+self.safe+'"}',proof=('passwords',self.safe))
        self.assertTrue(r['H1_pass_on_v3']);self.assertTrue(r['subcontrols']['credential']['candidates'][0]['provenance'])

    def test_credential_fake_metadata_not_provenance(self):
        self.assertFalse(self.scan('POST / HTTP/1.1\n\n{"password":"new-secret"}',proof=('passwords','new-secret'))['H1_pass_on_v3'])

    def test_known_value_outside_leaf_is_not_exempt(self):
        text='POST / HTTP/1.1\n\n{"safe":"'+self.safe+'","password":"'+self.safe+'"}'
        self.assertFalse(self.scan(text,proof=('passwords',self.safe))['H1_pass_on_v3'])

    def test_secret_format_outside_credential_key(self):
        self.assertFalse(self.scan('POST / HTTP/1.1\n\n{"q":"sk_live_'+('A1'*12)+'"}')['H1_pass_on_v3'])

    def test_query_credential_without_provenance(self):
        self.assertFalse(self.scan('GET /?password=unexplained-value HTTP/1.1')['H1_pass_on_v3'])

    def test_vendor_host_fails(self):
        self.assertFalse(self.scan('GET http://www.google.com/x HTTP/1.1')['H1_pass_on_v3'])

    def test_vendor_word_without_attribution_fails(self):
        self.assertFalse(self.scan('POST / HTTP/1.1\n\nGoogle')['H1_pass_on_v3'])

    def test_plain_word_in_pinned_prose_is_attributed(self):
        value='An apple is on the table.'
        self.assertTrue(self.scan('POST / HTTP/1.1\n\n'+value,proof=('prose_en',value))['H1_pass_on_v3'])

    def test_protocol_relative_real_domain_is_detected(self):
        r=self.scan('POST / HTTP/1.1\n\n<script src=//google.com/x>')
        self.assertIn('google.com',r['distinct_hosts']);self.assertFalse(r['H1_pass_on_v3'])

    def test_protocol_relative_reserved_domain_passes(self):
        self.assertTrue(self.scan('POST / HTTP/1.1\n\n<script src=//cdn.example.org/x>')['H1_pass_on_v3'])

    def test_recognized_secret_is_confirmed(self):
        r=self.scan('POST / HTTP/1.1\n\n'+('sk_live_'+('A1'*12)))
        self.assertTrue(r['subcontrols']['credential']['confirmed']);self.assertFalse(r['H1_pass_on_v3'])

    def test_json_key_meta_is_not_company_identity(self):
        self.assertTrue(self.scan('POST / HTTP/1.1\n\n{"meta":{"q":"plain"}}')['H1_pass_on_v3'])

    def test_pool_manifest_tamper_fails(self):
        Path(self.pins['passwords'][0],'manifest.json').write_text('{}')
        with self.assertRaisesRegex(ValueError,'hash mismatch'):self.scan('GET / HTTP/1.1')

    def test_pool_bytes_tamper_fails(self):
        Path(self.pins['passwords'][0],'passwords.jsonl').write_text('{}')
        with self.assertRaisesRegex(ValueError,'hash/size mismatch'):self.scan('GET / HTTP/1.1')

    def test_meta_alignment_fails(self):
        self.scan('GET / HTTP/1.1')
        (self.root/'rows.TRAIN.meta.jsonl').write_text('')
        self.assertFalse(H.scan(self.root,pool_pins=self.pins)['H1_pass_on_v3'])

    def test_meta_text_hash_tamper_fails(self):
        self.scan('GET / HTTP/1.1');p=self.root/'rows.TRAIN.meta.jsonl'
        m=json.loads(p.read_text());m['text_sha256']='0'*64;p.write_text(json.dumps(m)+'\n')
        self.assertFalse(H.scan(self.root,pool_pins=self.pins)['H1_pass_on_v3'])


if __name__=='__main__':unittest.main(verbosity=2)
