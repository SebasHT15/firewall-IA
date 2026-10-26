"""FINAL plumbing with synthetic examples/doubles only; no real data admission."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.model2 import training as T
from scripts.model2 import final_training as F
from scripts.model2.v5_fixture_integration import build_fixture, exchange


class FinalTrainingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as d:
            build_fixture(d)
            cls.examples = exchange.load_examples(d)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.dataset = self.root/'dataset'
        self.dataset.mkdir()
        self.manifest = {'status':'REAL','generator_config':{'mode':'real'},'fixture':False}
        (self.dataset/'manifest.json').write_bytes(T.encode(self.manifest))
        self.msha = T.digest((self.dataset/'manifest.json').read_bytes())
        self.recipe = {**T.candidate_recipe(),'status':'RATIFIED','owner_decision':'synthetic-test-only'}
        self.c1 = json.loads((T.ROOT/'reports/v5/hybrid/model2-readiness/c1-training-input-candidate-v1.json').read_bytes())
        self.c1.update(status='RATIFIED',owner_decision='synthetic-test-only')
        self.args = {}
        docs = {'recipe_path':self.recipe,'c1_contract':self.c1,'dataset_prereg':{},'freeze_record':{},
                'vocabulary_recipe':{},'ai_audit_authorization':{}}
        for name, doc in docs.items():
            p=self.root/(name+'.json'); p.write_bytes(T.encode(doc)); self.args[name]=p
        p=self.root/'selection.md'; p.write_text('Synthetic protocol double, never an owner approval.\n')
        self.args['selection_protocol']=p
        self.args['authorization']=self.root/'authorization.json'
        self.auth = {'schema':F.PROPOSED_AUTH_SCHEMA,'scope':'FINAL_OFFLINE_MODEL2','status':'AUTHORIZED',
            'owner_decision':'synthetic-test-only','authorized_by':'test-double','date':'synthetic',
            'recipe_sha256':T.digest(T.encode(self.recipe)), 'dataset_manifest_sha256':self.msha,
            'source_sha256':T.source_hashes(), 'reader_source_sha256':F.reader_hashes(),
            'library_versions':F.library_versions()}
        self.fields={'recipe_path':'recipe_file','c1_contract':'c1_contract','selection_protocol':'selection_protocol',
                     'dataset_prereg':'dataset_preregistration','freeze_record':'freeze_record',
                     'vocabulary_recipe':'vocabulary_recipe','ai_audit_authorization':'ai_audit_authorization'}
        self.refresh_auth()
        examples=copy.deepcopy(self.examples)
        for rows in examples.values():
            for row in rows: row['manifest_sha256']=self.msha
        self.bundle={'examples':examples,'dataset_final_evidence':{'mode':'FINAL','manifest_sha256':self.msha,
            'spec':'synthetic-test-double','audit_type':'ai_audited','vocabulary_bound_to_preregistration':True,
            'vocabulary_id':'synthetic-test-vocab','splits_opened':['TRAIN','VALIDATION'],
            'preregistration_sha256':self.auth['dataset_preregistration_sha256'],
            'freeze_record_sha256':self.auth['freeze_record_sha256'],
            'ai_audit_authorization_sha256':self.auth['ai_audit_authorization_sha256'],
            'rows':{s:len(rs) for s,rs in examples.items()}}}
        for name, value in [('FINAL_AUTH_SCHEMA',F.PROPOSED_AUTH_SCHEMA)]:
            p=patch.object(F,name,value); p.start(); self.addCleanup(p.stop)
        p=patch.object(exchange.D,'git_committed_unmodified',return_value=True)
        p.start(); self.addCleanup(p.stop)
        p=patch.object(exchange.D,'git_state',return_value={'clean':True})
        p.start(); self.addCleanup(p.stop)
        p=patch.object(exchange,'load_final_examples',return_value=self.bundle)
        self.loader=p.start(); self.addCleanup(p.stop)

    def refresh_auth(self):
        for arg,field in self.fields.items():
            self.auth[field+'_sha256']=T.digest(self.args[arg].read_bytes())
        self.args['authorization'].write_bytes(T.encode(self.auth))

    def test_schema_default_off_before_any_caller_file_access(self):
        with patch.object(F,'FINAL_AUTH_SCHEMA',None), patch.object(F,'capture',side_effect=AssertionError('read')):
            with self.assertRaisesRegex(F.FinalRefused,'not ratified'):
                F.train_final(self.dataset,**self.args)
        self.loader.assert_not_called()

    def test_positive_synthetic_adapter_fit_save_reload(self):
        artifact,report=F.train_final(self.dataset,**self.args)
        self.assertEqual(artifact['mode'],'FINAL')
        self.assertFalse(artifact['operational_policy_approved'])
        self.assertIsNone(artifact['operating_threshold'])
        self.assertLess(report['max_probability_delta'],1e-12)
        self.loader.assert_called_once_with(str(self.dataset),dataset_prereg=str(self.args['dataset_prereg']),
            freeze_record=str(self.args['freeze_record']),recipe_path=str(self.args['vocabulary_recipe']),
            ai_audit_authorization=str(self.args['ai_audit_authorization']))
        out=self.root/'model.json'
        sha=T.save_artifact(artifact,out)
        self.assertEqual(T.load_artifact(out,expected_sha256=sha),artifact)
        bad=copy.deepcopy(artifact); bad['final_training_evidence']['dataset_final_evidence']['manifest_sha256']='0'*64
        with self.assertRaisesRegex(F.FinalRefused,'evidence mismatch'):T.check_artifact(bad)

    def test_unratified_recipe_and_c1_refuse_before_shared_reader(self):
        for key in ('recipe_path','c1_contract'):
            original=self.args[key].read_bytes()
            doc=json.loads(original); doc['status']='PROPOSED'; self.args[key].write_bytes(T.encode(doc))
            self.refresh_auth()
            with self.subTest(key=key), self.assertRaisesRegex(ValueError,'ratified'):
                F.prepare_final(self.dataset,**self.args)
            self.args[key].write_bytes(original)
        self.loader.assert_not_called()

    def test_unapproved_learned_field_refused(self):
        doc={**self.c1,'baseline_fields':self.c1['baseline_fields']+['audit_type']}
        self.args['c1_contract'].write_bytes(T.encode(doc)); self.refresh_auth()
        with self.assertRaisesRegex(F.FinalRefused,'feature semantics'):F.prepare_final(self.dataset,**self.args)
        self.loader.assert_not_called()

    def test_bad_pins_sources_record_hash_or_dataset_refuse_before_rows(self):
        for key,value in [('library_versions',{}),('source_sha256',{}),('reader_source_sha256',{}),
                          ('dataset_manifest_sha256','0'*64),('recipe_file_sha256','0'*64),
                          ('scope','EXPERIMENTAL'),('owner_decision','')]:
            original=copy.deepcopy(self.auth)
            self.auth[key]=value; self.args['authorization'].write_bytes(T.encode(self.auth))
            with self.subTest(key=key),self.assertRaises(F.FinalRefused):F.prepare_final(self.dataset,**self.args)
            self.auth=original;self.refresh_auth()
        self.loader.assert_not_called()

    def test_uncommitted_record_or_dirty_tree_refused(self):
        with patch.object(exchange.D,'git_committed_unmodified',return_value=False):
            with self.assertRaisesRegex(F.FinalRefused,'committed'):F.prepare_final(self.dataset,**self.args)
        with patch.object(exchange.D,'git_state',return_value={'clean':False}):
            with self.assertRaisesRegex(F.FinalRefused,'clean'):F.prepare_final(self.dataset,**self.args)
        self.loader.assert_not_called()

    def test_fixture_manifest_and_row_symlink_escape_refused(self):
        (self.dataset/'manifest.json').write_bytes(T.encode({**self.manifest,'fixture':True}))
        with self.assertRaisesRegex(F.FinalRefused,'fixture'):F.prepare_final(self.dataset,**self.args)
        (self.dataset/'manifest.json').write_bytes(T.encode(self.manifest))
        (self.dataset/exchange.D.ROWS_FILE.format(split='TRAIN')).symlink_to(self.root/'outside.jsonl')
        with self.assertRaisesRegex(F.FinalRefused,'escapes'):F.prepare_final(self.dataset,**self.args)
        self.loader.assert_not_called()

    def test_protected_roles_are_refused_without_opening(self):
        for name in ('INTERNAL_TEST','E6_RESERVE','STAB-HELD','external_v2'):
            with self.subTest(name=name),patch.object(Path,'read_bytes',side_effect=AssertionError('read')):
                with self.assertRaisesRegex(F.FinalRefused,'protected'):F.capture(self.root/name/'rows.jsonl')

    def test_shared_refusal_or_mismatched_evidence_prevents_fit(self):
        with patch.object(T,'_fit',side_effect=AssertionError('fit')):
            self.loader.side_effect=exchange.ExampleExchangeError('dataset refused')
            with self.assertRaisesRegex(ValueError,'dataset refused'):F.train_final(self.dataset,**self.args)
            self.loader.side_effect=None
            self.bundle['dataset_final_evidence']['freeze_record_sha256']='0'*64
            with self.assertRaisesRegex(F.FinalRefused,'record evidence'):F.train_final(self.dataset,**self.args)

    def test_changed_record_during_consumption_prevents_fit(self):
        def changing(*a,**k):
            self.args['freeze_record'].write_text('changed')
            return self.bundle
        self.loader.side_effect=changing
        with patch.object(T,'_fit',side_effect=AssertionError('fit')):
            with self.assertRaisesRegex(F.FinalRefused,'record changed'):F.train_final(self.dataset,**self.args)

    def test_changed_record_during_fit_prevents_artifact_return(self):
        def changing(*a,**k):
            self.args['authorization'].write_text('changed')
            return {},{}
        with patch.object(T,'_fit',side_effect=changing):
            with self.assertRaisesRegex(F.FinalRefused,'record changed'):F.train_final(self.dataset,**self.args)

    def test_unbound_vocabulary_prevents_fit(self):
        for value in (False,None):
            self.bundle['dataset_final_evidence']['vocabulary_bound_to_preregistration']=value
            with patch.object(T,'_fit',side_effect=AssertionError('fit')):
                with self.assertRaisesRegex(F.FinalRefused,'vocabulary'):
                    F.train_final(self.dataset,**self.args)

    def test_fitting_final_without_evidence_refused(self):
        with self.assertRaisesRegex(F.FinalRefused,'evidence missing'):
            T._fit(self.bundle['examples'],self.recipe,'FINAL')


if __name__=='__main__':unittest.main()
