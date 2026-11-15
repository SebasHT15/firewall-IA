"""Candidate contract tests; no network services, Docker, GPU or ML dependencies."""
from pathlib import Path
import json,sys,tempfile,unittest,hashlib
from unittest.mock import patch
from types import SimpleNamespace as NS
R=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(R/'data_plane'),str(R/'scripts/local_stack/challenges'),str(R/'scripts/gateway_ops')]
import cascade as C
import canonical_request as CR
import fast_path as F
import cascade_runtime as RT
import static_contract as SC
import request_guard as RG
import launch

class StaticContractTests(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory();self.addCleanup(self.t.cleanup)
        self.root=Path(self.t.name);self.app=self.root/'Web/An0nB0ard'
        self.asset=self.app/'static/css/style.css';self.asset.parent.mkdir(parents=True);self.asset.write_text('body {}')
        self.mock=patch.object(SC,'source_identity',return_value=(self.app,'a'*64,{'Web/An0nB0ard/static/css/style.css':'b'*64}));self.mock.start();self.addCleanup(self.mock.stop)
        self.policy=F.parse_policy(SC.policy('An0nB0ard',self.root))
    def evaluate(self,headers=(),target='/static/css/style.css',method='GET',body=b''):
        parts=CR.RequestParts(method=method.encode(),target=target.encode(),http_version='HTTP/1.1',headers=tuple((k.encode(),v.encode())for k,v in headers),body=body)
        snap=RT.build_snapshot(parts,F.FramingEvidence(F.FRAMING_VERIFIED,'unit'),CR.Limits(max_decoded_body=19920,token_budget=415,max_bytes_per_token=48))
        return F.safe_evaluate(RT.make_fast_path_input(snap),self.policy)
    def test_normal_browser_headers_and_head_match(self):
        hs=(('Host','an0nb0ard.fwlab.test'),('User-Agent',SC.BROWSER_UA[0]),('Accept','text/css,*/*;q=0.1'),('Referer','https://an0nb0ard.fwlab.test:8443/'))
        self.assertEqual(self.evaluate(hs).decision,F.FAST_ALLOW)
        self.assertEqual(self.evaluate(hs,method='HEAD').decision,F.FAST_ALLOW)
    def test_missing_host_wrong_host_duplicates_and_credential_headers_continue(self):
        self.assertEqual(self.evaluate().decision,F.CONTINUE)
        self.assertEqual(self.evaluate((('Host','other.test'),)).decision,F.CONTINUE)
        host=('Host','an0nb0ard.fwlab.test')
        for h in (host,('Cookie','sid=1'),('Authorization','Bearer value'),('Range','bytes=0-1'),('X-Note','{{7*7}}'),('User-Agent','unknown version')):
            self.assertEqual(self.evaluate((host,h)).decision,F.CONTINUE,h)
    def test_query_encoding_dynamic_post_and_body_never_fast_allow(self):
        hs=(('Host','an0nb0ard.fwlab.test'),)
        for target in ('/static/css/style.css?x=1','/static/css/%73tyle.css','/static/css/../style.css','/login','/static/css/style.css/extra'):
            self.assertEqual(self.evaluate(hs,target).decision,F.CONTINUE)
        self.assertEqual(self.evaluate(hs,method='POST').decision,F.CONTINUE)
        self.assertEqual(self.evaluate(hs,body=b'payload').decision,F.CONTINUE)

    def test_public_document_is_get_only_and_conditionals_are_explicit(self):
        host=(('Host','an0nb0ard.fwlab.test'),)
        self.assertEqual(self.evaluate(host,'/').decision,F.FAST_ALLOW)
        self.assertEqual(self.evaluate(host,'/',method='POST').decision,F.CONTINUE)
        self.assertEqual(self.evaluate(host+(('If-None-Match','"opaque-etag"'),)).decision,F.FAST_ALLOW)
        self.assertEqual(self.evaluate(host+(('If-None-Match','"opaque-etag"'),),'/').decision,F.CONTINUE)
    def test_named_profiles_require_v2_and_validate_bounded_syntax(self):
        doc=SC.policy('An0nB0ard',self.root)
        doc['schema']='fast-path-policy/v1'
        with self.assertRaises(F.PolicyError):F.parse_policy(doc)
        samples={
            'language_preferences':(['es-CR,es;q=0.9,en;q=0.7'],['es; q=0.9','xx','en,en','en;q=1.2']),
            'client_hints':(['"Chromium";v="132", "Not_A Brand";v="24", "Google Chrome";v="132"','"Not:A-Brand";v="99", "Not;A=Brand";v="24", "Chromium";v="141"'],['"{{x}}";v="1"','x'*600]),
            'entity_tag':(['"1793895643.0-35-2017921399"','W/"tag"','*'],['"bad,tag"','"tag", "tag2"']),
            'http_date':(['Thu, 05 Nov 2026 16:20:43 GMT'],['Wed, 05 Nov 2026 16:20:43 GMT','Thu, 99 Nov 2026 16:20:43 GMT']),
            'question_cookie':(['question=What is your name, please?'],['sid=1','question=x; sid=y','question={{7}}']),
        }
        for name,(good,bad) in samples.items():
            for value in good:self.assertTrue(F._header_profile_matches(name,value),(name,value))
            for value in bad:self.assertFalse(F._header_profile_matches(name,value),(name,value))

    def test_favicon_is_one_exact_get_404_contract_not_a_general_unknown_route(self):
        h=(('Host','an0nb0ard.fwlab.test'),)
        out=self.evaluate(h,'/favicon.ico')
        self.assertEqual(out.decision,F.FAST_ALLOW);self.assertEqual(out.rule_id,'constant-favicon-404')
        for target in ('/favicon.ico?x=1','/Favicon.ico','/favicon.ico/','/other-missing','/%66avicon.ico'):
            self.assertEqual(self.evaluate(h,target).decision,F.CONTINUE,target)
        self.assertEqual(self.evaluate(h,'/favicon.ico',method='HEAD').decision,F.CONTINUE)
    def test_referer_grammar_does_not_expand_request_query_or_accept_foreign_origins(self):
        h=(('Host','an0nb0ard.fwlab.test'),)
        for ref in ('/','https://an0nb0ard.fwlab.test/post?id=104','https://an0nb0ard.fwlab.test:8443/messages'):
            self.assertEqual(self.evaluate(h+(('Referer',ref),)).decision,F.FAST_ALLOW,ref)
        for ref in ('https://evil.test/post?id=1','https://an0nb0ard.fwlab.test.evil.test/',
                    'https://evil@an0nb0ard.fwlab.test/','https://an0nb0ard.fwlab.test/post?id=1&id=2',
                    'https://an0nb0ard.fwlab.test/post?id=%31','https://an0nb0ard.fwlab.test/post?id=1#x',
                    'https://an0nb0ard.fwlab.test/unknown','https://an0nb0ard.fwlab.test/../messages',
                    'https://an0nb0ard.fwlab.test/post?id=1&x=2'):
            self.assertEqual(self.evaluate(h+(('Referer',ref),)).decision,F.CONTINUE,ref)
        self.assertEqual(self.evaluate(h+(('Referer','https://an0nb0ard.fwlab.test/post?id=1'),),'/static/css/style.css?x=1').decision,F.CONTINUE)
    def test_referer_profile_parameters_are_strict_and_v2_only(self):
        doc=SC.policy('An0nB0ard',self.root)
        spec=doc['rules'][0]['headers']['referer']
        for key,value in (('origins',['https://host.test/path']),('paths',['/../x']),('queries',{'/':'arbitrary'}),('relative_root',1)):
            changed=json.loads(json.dumps(doc));changed['rules'][0]['headers']['referer'][key]=value
            with self.assertRaises(F.PolicyError):F.parse_policy(changed)

    def test_public_cat_referer_query_is_a_bounded_basename_only(self):
        spec={'type':'public_referer','origins':['https://catp1cs.fwlab.test'],
              'paths':['/','/show'],'queries':{'/show':'basename-img'},'relative_root':True}
        g=F._grammar(spec,header=True,profiles=True,where='unit')
        self.assertTrue(g.matches('https://catp1cs.fwlab.test/show?img=sketch.jpg'))
        for ref in ('https://catp1cs.fwlab.test/show?img=../flag.txt',
                    'https://catp1cs.fwlab.test/show?img=x.jpg&img=y.jpg',
                    'https://catp1cs.fwlab.test/show?img=%61.jpg',
                    'https://catp1cs.fwlab.test/show?img='+'a'*129):
            self.assertFalse(g.matches(ref),ref)

class HeaderGuardTests(unittest.TestCase):
    def setUp(self):
        self.t=tempfile.TemporaryDirectory();self.addCleanup(self.t.cleanup)
        self.path=Path(self.t.name)/'guard.json';self.doc={'schema':RG.SCHEMA,'policy_id':'unit','application_contract_ref':'app-sha','methods':['POST'],'sink':'jinja_template_headers'}
        self.path.write_text(json.dumps(self.doc));self.policy=RG.load(self.path)
    def snapshot(self,value,method=b'POST'):
        return C.Snapshot(method,b'/', 'HTTP/1.1',((b'X-Note',value),),b'msg=Hello',NS(outcome='ACCEPT',text='POST / HTTP/1.1\n\nmsg=Hello'),None)
    def test_template_families_are_app_guard_blocks_without_model_calls(self):
        for value in (b'{{2*3}}',b'{% print(2) %}',b'{# comment #}'):
            def forbidden(*a,**k):raise AssertionError('guard must short circuit')
            router=C.CascadeRouter(C.CascadeConfig(C.FAST_PATH_V5,request_guard_policy=self.policy),v5_classify=forbidden,model2_decide=forbidden,fast_path_evaluate=forbidden)
            out=router.route(self.snapshot(value))
            self.assertEqual((out.applied,out.deciding_stage),(C.DENY,C.STAGE_REQUEST_GUARD))
            self.assertIsNone(out.v5);self.assertIsNone(out.model2)
            self.assertNotIn(value.decode(),json.dumps(out.request_guard))
    def test_method_aliases_cannot_bypass_the_normalized_post_sink(self):
        for method in (b'post',b'PoSt'):
            self.assertEqual(RG.evaluate(self.snapshot(b'{{2*3}}',method),self.policy)['status'],'MATCH')
            self.assertEqual(RG.evaluate(self.snapshot(b'Browser/1',method),self.policy)['status'],'CLEAR')
        self.doc['schema']=RG.SCHEMA_V1;self.path.write_text(json.dumps(self.doc))
        historical=RG.load(self.path)
        self.assertEqual(RG.evaluate(self.snapshot(b'{{2*3}}',b'post'),historical)['status'],'CLEAR')
        self.assertEqual(RG.evaluate(self.snapshot(b'{{2*3}}'),historical)['contract'],RG.SCHEMA_V1)

    def test_normal_headers_get_and_encoded_literal_are_not_matched(self):
        for value,method in ((b'Browser/1.0',b'POST'),(b'%7b%7b2*3%7d%7d',b'POST'),(b'{{2*3}}',b'GET')):
            self.assertEqual(RG.evaluate(self.snapshot(value,method),self.policy)['status'],'CLEAR')
    def test_policy_binding_and_digest_must_match(self):
        with self.assertRaises(ValueError):RG.load(self.path,'0'*64)
        with self.assertRaises(ValueError):RG.load(self.path,expected_contract='different-app')
        self.doc['methods']=['GET'];self.path.write_text(json.dumps(self.doc))
        with self.assertRaises(ValueError):RG.load(self.path)
    def test_v5_only_preserves_original_canonical_request(self):
        seen=[]
        r=C.CascadeRouter(C.CascadeConfig(C.V5_ONLY,request_guard_policy=self.policy),v5_classify=lambda t:(seen.append(t)or C.V5Reply('ok','ALLOW')))
        out=r.route(self.snapshot(b'{{2*3}}'))
        self.assertEqual(out.applied,C.FORWARD);self.assertIsNone(out.request_guard)
        self.assertEqual(seen,['POST / HTTP/1.1\n\nmsg=Hello'])

class NoModel2LaunchTests(unittest.TestCase):
    def test_new_mode_does_not_require_model2_interpreter(self):
        manifest=NS(manifest_id='unit',status='EXPERIMENTAL',schema='fixture',sha256='a'*64,canonical=NS(token_budget_B=415),model2=None)
        cfg=NS(mode=C.FAST_PATH_V5,deployment_profile='lab',framing=NS(contract=launch.GF.CONTRACT_ID),manifest_path='unused',fast_path=NS(activation='experimental_fixture'),canonical=NS(bounds=NS(python=sys.executable)),model2=NS(python='/missing/unused/model2/python'))
        with patch.object(launch.CM,'load_manifest',return_value=manifest),patch.object(launch.CM,'resolve_fast_path_policy',return_value=NS(status='PROPOSED')),patch.object(launch.CM,'validate_consistency',return_value=()),patch.object(launch.CM,'candidate_file_problems',return_value=()):
            self.assertEqual(launch.check(cfg)['problems'],[])

if __name__=='__main__':unittest.main()
