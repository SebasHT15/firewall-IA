"""Pin/report/pool agreement tests on synthetic files only."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts/dataset'))
import v5_audit_evidence as AE
import v5_fixture as F
import v5_generator as G
from tests.v5_audit_fixture import make_bundle


class AuditEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)
        self.row={'record_id':'synthetic-id','payload_wire':"' OR 1=1 --",'dedup_scope':'SQL Injection',
                  'category_v4':'SQL Injection','source_file':'synthetic'}
        self.binding=make_bundle(self.root/'evidence',records=[self.row])

    def edit(self,name,update,*,repin=False):
        path=Path(self.binding[name]['path']);doc=json.loads(path.read_bytes());update(doc)
        path.write_text(json.dumps(doc))
        if repin:self.binding[name]['sha256']=AE.sha256(path.read_bytes())

    def test_valid_chain_and_record_membership(self):
        evidence=AE.verify(self.binding,records=[self.row],expected_pool_sha256=self.binding['pool']['sha256'])
        self.assertEqual(evidence['category_outcomes'],{'SQL Injection':'PASS_AI_AUDITED'})

    def test_each_modified_artifact_is_rejected(self):
        for name in AE.FILES:
            p=Path(self.binding[name]['path']);raw=p.read_bytes();p.write_bytes(raw+b' ')
            with self.subTest(name=name),self.assertRaisesRegex(ValueError,'hash mismatch'):AE.verify(self.binding)
            p.write_bytes(raw)

    def test_report_outcome_cannot_be_overridden_in_exchange(self):
        self.edit('exchange',lambda d:d['category_outcomes'].update({'SQL Injection':'FAIL'}),repin=True)
        with self.assertRaisesRegex(ValueError,'outcomes differ'):AE.verify(self.binding)

    def test_state_must_name_the_same_sample_and_pool(self):
        original=copy.deepcopy(self.binding);p=Path(self.binding['state']['path']);raw=p.read_bytes()
        for field in ('sample','pool'):
            self.edit('state',lambda d:d[field].update(sha256='0'*64),repin=True)
            with self.subTest(field=field),self.assertRaises(ValueError):AE.verify(self.binding)
            p.write_bytes(raw);self.binding=copy.deepcopy(original)

    def test_world_record_drift_and_missing_membership_refused(self):
        for change in ({'payload_wire':'changed'},{'record_id':'not-in-audit'},{'dedup_scope':'XSS Injection'}):
            with self.subTest(change=change),self.assertRaises(ValueError):AE.verify(self.binding,records=[{**self.row,**change}])

    def test_consumers_can_require_committed_audit_metadata(self):
        with self.assertRaisesRegex(ValueError,'committed'):
            AE.verify(self.binding,committed_checker=lambda path:False)
        self.assertTrue(AE.verify(self.binding,committed_checker=lambda path:True)['category_outcomes'])

    def test_reserved_sources_never_opened(self):
        for role in ('E6_RESERVE','STAB-HELD','INTERNAL_TEST','external_v2'):
            binding=copy.deepcopy(self.binding);binding['pool']['path']=str(self.root/role/'file.json')
            with self.subTest(role=role),self.assertRaisesRegex(ValueError,'protected'):AE.verify(binding)


class AuthorizedBuildRegression(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.world=F.build_world()
        self.cats=self.world.gen_cfg['trained_categories']['categories']
        for k in self.world.gen_cfg['_statuses']:self.world.gen_cfg['_statuses'][k]='RATIFIED'
        self.world.pool_values['names_family']={}
        self.world.gen_cfg['i9']['cap']='warn'
        self.binding=make_bundle(self.root/'evidence',records=list(self.world.records.values()),
                                 outcomes={c:G.OUTCOME_PASS for c in self.cats})
        self.auth={'schema':G.PROPOSED_REAL_BUILD_AUTH_SCHEMA,'scope':'REAL_BUILD',
                   'preregistration_sha256':'synthetic-pre','authorized_by':'test-only','date':'synthetic',
                   'owner_decision':'synthetic-only','audit_evidence':self.binding}
        self.ap=self.root/'auth.json';self.ap.write_text(json.dumps(self.auth))
        self.kw=dict(authorization_path=str(self.ap),audit_exchange_path=self.binding['exchange']['path'],
                     out_dir=str(self.root/'output'),preregistration_sha256='synthetic-pre',category_selection=self.cats,
                     pool_values_list=F.fixture_pool_value_lists())
        for target,name,value in ((G,'REAL_BUILD_AUTH_SCHEMA',G.PROPOSED_REAL_BUILD_AUTH_SCHEMA),(AE,'is_committed',lambda p:True)):
            p=patch.object(target,name,value);p.start();self.addCleanup(p.stop)

    def build(self,**kwargs):return G.authorized_build(self.world,**{**self.kw,**kwargs})

    def test_real_authorization_cannot_promote_a_fixture_world(self):
        res=self.build();self.assertEqual(res['status'],'REFUSED',res)
        self.assertIn('REAL_BUILD_MODE_REQUIRED',{d['code'] for d in res['unmet']})
        self.assertFalse((self.root/'output').exists())

    def test_empty_or_partial_selection_cannot_generate_unselected_categories(self):
        for selection in ([],self.cats[:1]):
            with patch.object(G,'generate_balanced',side_effect=AssertionError('must not generate')):
                result=self.build(category_selection=selection)
            self.assertEqual(result['status'],'REFUSED')
        self.assertFalse((self.root/'output').exists())

    def test_failed_gates_do_not_persist_or_report_built(self):
        with patch.object(G,'run_gates',return_value={'ok':False}),patch.object(G,'real_build_preconditions',return_value=[]):res=self.build()
        self.assertEqual(res['status'],'REFUSED')
        self.assertIn('BUILD_GATES_FAILED',{d['code'] for d in res['unmet']})
        self.assertFalse((self.root/'output').exists())

    def test_real_emitter_cannot_persist_verified_ai_attack_labels(self):
        self.world.gen_cfg.update(mode='real',attack_label_basis='post_filter_audit')
        self.world.basis=G.L.AttackBasis('post_filter_audit',frozenset(self.cats))
        self.auth['dataset_spec']='V5-DATA-SPEC-r4';self.ap.write_text(json.dumps(self.auth))
        res=self.build()
        self.assertEqual(res['status'],'REFUSED')
        codes={d['code'] for d in res['unmet']}
        self.assertNotIn('BUILD_AI_SPEC_NOT_ACTIVE',codes)
        self.assertIn('BUILD_AI_ROW_CONTRACT_NOT_ACTIVE',codes)
        self.assertFalse((self.root/'output').exists())

    def test_unpinned_or_false_exchange_and_uncommitted_authority_refused(self):
        self.auth.pop('audit_evidence');self.ap.write_text(json.dumps(self.auth))
        with patch.object(G,'generate_balanced',side_effect=AssertionError('generate')):
            self.assertEqual(self.build()['status'],'REFUSED')
        self.auth['audit_evidence']=self.binding;self.ap.write_text(json.dumps(self.auth))
        with patch.object(AE,'is_committed',return_value=False):
            self.assertEqual(self.build()['status'],'REFUSED')
        path=Path(self.binding['exchange']['path']);doc=json.loads(path.read_bytes())
        doc['source_report_sha256']='not-a-sha-or-report';path.write_text(json.dumps(doc))
        self.assertEqual(self.build()['status'],'REFUSED')


if __name__=='__main__':unittest.main()
