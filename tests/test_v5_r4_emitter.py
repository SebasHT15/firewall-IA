"""Actual generator -> shared readers -> trainer preparation on synthetic inputs.

Only ratification and committed-record checks are test doubles. No core generator,
gate, parser, integrity, eligibility or trainer preparation function is mocked.
"""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
for folder in ('scripts/dataset', 'scripts/training'):
    sys.path.insert(0, str(ROOT/folder))
import v5_audit_evidence as AE
import v5_fixture as F
import v5_generator as G
import v5_row_contract as RC
import v5_train_data as D
import v5_example_exchange as E
from tests.v5_audit_fixture import make_bundle


class R4EmitterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.world = F.build_world()
        self.cats = self.world.gen_cfg['trained_categories']['categories']
        self.world.gen_cfg.update(mode='real', attack_label_basis='post_filter_audit')
        for key in self.world.gen_cfg['_statuses']:
            self.world.gen_cfg['_statuses'][key] = 'RATIFIED'
        self.world.gen_cfg['i9']['cap'] = 'warn'
        self.world.pool_values['names_family'] = {}
        self.world.basis = G.L.AttackBasis('post_filter_audit', frozenset(self.cats))
        self.binding = make_bundle(self.root/'evidence', records=list(self.world.records.values()),
                                  outcomes={c:G.OUTCOME_PASS for c in self.cats})
        self.auth = {'schema':G.PROPOSED_REAL_BUILD_AUTH_SCHEMA, 'scope':'REAL_BUILD',
                     'preregistration_sha256':'synthetic-pre', 'authorized_by':'TEST DOUBLE',
                     'date':'synthetic', 'owner_decision':'synthetic test only',
                     'audit_evidence':self.binding, 'dataset_spec':'V5-DATA-SPEC-r4',
                     'row_contract':RC.SCHEMA}
        self.ap = self.root/'build-auth.json'
        for target, name, value in (
                (AE,'is_committed',lambda p:True), (D,'git_committed_unmodified',lambda p:True)):
            p = patch.object(target,name,value); p.start(); self.addCleanup(p.stop)

    def build(self):
        self.ap.write_text(json.dumps(self.auth))
        return G.authorized_build(self.world, authorization_path=str(self.ap),
            audit_exchange_path=self.binding['exchange']['path'], out_dir=str(self.root/'dataset'),
            preregistration_sha256='synthetic-pre', category_selection=self.cats,
            pool_values_list=F.fixture_pool_value_lists())

    def consume(self):
        result = self.build()
        self.assertEqual(result['status'],'BUILT',result)
        dataset = self.root/'dataset'
        manifest, sha = D.load_manifest(str(dataset))
        auth = {'schema':D.AUTH_SCHEMA, 'scope':'EXPERIMENTAL','provisional':True,
                'dataset_manifest_sha256':sha,'authorized_by':'TEST DOUBLE','date':'synthetic',
                'reference':'synthetic-only','purpose':'synthetic end-to-end test',
                'uses_pending_labels_as_verified':False,'audit_evidence':self.binding,
                'category_outcomes':{c:G.OUTCOME_PASS for c in self.cats}}
        ap = self.root/'experimental-auth.json'; ap.write_text(json.dumps(auth))
        return dataset, ap, manifest

    def test_generator_reader_and_v5_preparation_preserve_reference_provenance(self):
        dataset, auth, manifest = self.consume()
        self.assertEqual(manifest['row_contract'],RC.SCHEMA)
        self.assertIsNone(self.world.row_contract)  # no mutation of the caller's world
        examples = E.load_examples(str(dataset),authorization=str(auth))
        for row in sum(examples.values(),[]):
            if row['label'] == 'BLOCK' and row['label_status_basis'] == 'ai_audit':
                self.assertEqual(row['label_status'],RC.TRAINING_REFERENCE)
                self.assertEqual(row['row_contract'],RC.SCHEMA)
        self.assertTrue(any(r['label_status']==RC.TRAINING_REFERENCE for r in examples['TRAIN']))
        recipe, sha = D.load_recipe(E.DEFAULT_RECIPE)
        data = D.prepare(D.EXPERIMENTAL,str(dataset),str(Path(D.OUTPUT_ROOT)/'experimental'/'synthetic-r4-test'),recipe,sha,
                         authorization=str(auth))
        self.assertEqual(len(data.train_rows),len(examples['TRAIN']))
        self.assertEqual(len(data.validation_rows),len(examples['VALIDATION']))
        for row in data.train_rows+data.validation_rows:
            if row['meta']['label_status'] == RC.TRAINING_REFERENCE:
                self.assertIsNone(row['meta'].get('policy_id'))

    def test_proposed_status_is_not_accepted_without_the_manifest_contract(self):
        meta = {'label_status':RC.TRAINING_REFERENCE,'label':'BLOCK','label_status_basis':'ai_audit',
                'label_rule':'ATTACK_POOL_LEAF','policy_id':None}
        self.assertFalse(RC.is_reference(meta))
        self.assertTrue(RC.is_reference(meta,contract=RC.SCHEMA))
        for change in ({'policy_id':'invented-policy'},{'label_status_basis':'policy_defined'},
                       {'label':'ALLOW'},{'label_rule':'different'}):
            self.assertFalse(RC.is_reference({**meta,**change},contract=RC.SCHEMA))

    def test_unratified_contract_refuses_before_generation(self):
        with patch.object(D,'AI_AUDIT_ROW_STATUS_ALLOWED',()), \
             patch.object(G,'generate_balanced',side_effect=AssertionError('must not generate')):
            result = self.build()
        self.assertEqual(result['status'],'REFUSED')
        self.assertIn('BUILD_AI_ROW_CONTRACT_NOT_ACTIVE',{d['code'] for d in result['unmet']})
        self.assertFalse((self.root/'dataset').exists())


if __name__ == '__main__':
    unittest.main()
