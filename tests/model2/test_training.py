"""No real/protected data: test portable fidelity, split isolation and rejection."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import numpy as np
from scripts.model2 import training as t
from scripts.model2.v5_fixture_integration import build_fixture, exchange


class TrainingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with tempfile.TemporaryDirectory() as d:
            build_fixture(d)
            cls.examples = exchange.load_examples(d)
        cls.recipe = t.candidate_recipe()
        cls.artifact, cls.report = t._fit(cls.examples, cls.recipe, 'SMOKE')

    def test_portable_roundtrip_and_tamper(self):
        with tempfile.TemporaryDirectory() as d:
            path = Path(d)/'model.json'
            h = t.save_artifact(self.artifact, path)
            loaded = t.load_artifact(path, expected_sha256=h)
            for row in self.examples['VALIDATION']:
                self.assertEqual(t.score(loaded, row['text']), t.score(self.artifact, row['text']))
            with self.assertRaises(FileExistsError):
                t.save_artifact(self.artifact, path)
            path.write_bytes(path.read_bytes()+b' ')
            with self.assertRaisesRegex(ValueError, 'hash'):
                t.load_artifact(path, expected_sha256=h)
        self.assertLess(self.report['max_probability_delta'], 1e-12)

    def test_validation_labels_do_not_affect_fit(self):
        changed = copy.deepcopy(self.examples)
        for r in changed['VALIDATION']:
            r['label'] = 'BLOCK' if r['label'] == 'ALLOW' else 'ALLOW'
        a, _ = t._fit(changed, self.recipe, 'SMOKE')
        for key in ('feature_names','scale','coefficients','intercept'):
            self.assertEqual(a[key], self.artifact[key])

    def test_validation_features_do_not_affect_encoder_scaler_weights(self):
        changed = copy.deepcopy(self.examples)
        r = changed['VALIDATION'][0]
        r['text'] = r['text'].replace('GET ', 'UNSEENMETHOD ', 1)
        if r['text'] == self.examples['VALIDATION'][0]['text']:
            r['text'] = 'UNSEENMETHOD ' + r['text'].split(' ',1)[1]
        r['text_sha256'] = t.digest(r['text'].encode())
        r['identities']['text_sha256'] = r['text_sha256']
        a, _ = t._fit(changed, self.recipe, 'SMOKE')
        for key in ('feature_names','scale','coefficients','intercept'):
            self.assertEqual(a[key], self.artifact[key])
        self.assertNotIn('method=UNSEENMETHOD', a['feature_names'])

    def test_both_views_have_reload_fidelity(self):
        recipe = {**self.recipe, 'feature_view': t.PATH_VIEW}
        a, report = t._fit(self.examples, recipe, 'SMOKE')
        self.assertLess(report['max_probability_delta'], 1e-12)
        self.assertNotIn('path_length', a['feature_names'])
        self.assertNotIn('path_depth', a['feature_names'])

    def test_bad_artifact_contracts(self):
        mutations = ({'scale': [0]}, {'coefficients': [float('nan')]},
                     {'intercept': float('inf')}, {'classes':['BLOCK','ALLOW']},
                     {'source_sha256': {}}, {'feature_schema':'unapproved'},
                     {'operating_threshold':.5}, {'operational_policy_approved':True},
                     {'recipe_sha256':'0'*64})
        for changes in mutations:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                t.check_artifact({**self.artifact, **changes})

    def test_no_metadata_features_and_no_policy(self):
        for name in self.artifact['feature_names']:
            self.assertIn(name.split('=',1)[0], t.features.FEATURES)
        self.assertFalse(self.artifact['operational_policy_approved'])
        self.assertIsNone(self.artifact['operating_threshold'])
        for row in self.examples['TRAIN']:
            self.assertNotIn(row['text'], json.dumps(self.artifact))

    def test_corrupt_or_ineligible_rows(self):
        for field, value in [('text_sha256','0'*64), ('label_status','PENDING'),
                             ('eligibility',{'trainable':False}), ('label','DEFER'),
                             ('manifest_sha256','0'*64)]:
            bad = copy.deepcopy(self.examples)
            bad['TRAIN'][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                t._fit(bad, self.recipe, 'SMOKE')

    def test_cross_split_identity_rejected(self):
        bad = copy.deepcopy(self.examples)
        bad['VALIDATION'][0]['identities']['pair_id'] = bad['TRAIN'][0]['identities']['pair_id']
        with self.assertRaisesRegex(ValueError, 'crosses'):
            t._fit(bad, self.recipe, 'SMOKE')

    def test_unratified_experiment_refused_before_data_access(self):
        with patch.object(exchange, 'load_examples', side_effect=AssertionError('must not read data')):
            with self.assertRaisesRegex(ValueError,'ratified'):
                t.train_experimental('/not/read', self.recipe, authorization='/not/read', v5_recipe='/not/read')

    def test_experimental_refuses_fixture(self):
        with tempfile.TemporaryDirectory() as d:
            build_fixture(d)
            recipe = {**self.recipe, 'status':'RATIFIED', 'owner_decision':'synthetic-test-only'}
            with patch.object(exchange,'load_examples', side_effect=AssertionError('must not read rows')):
                with self.assertRaisesRegex(ValueError,'refuses fixtures'):
                    t.train_experimental(d, recipe, authorization='/not/read', v5_recipe='/not/read')

    def test_experimental_passes_authorization_to_shared_reader(self):
        recipe = {**self.recipe, 'status':'RATIFIED', 'owner_decision':'synthetic-test-only'}
        manifest_sha = self.examples['TRAIN'][0]['manifest_sha256']
        with patch.object(exchange.D, 'load_manifest', return_value=({'status':'PROVISIONAL'},manifest_sha)), \
                patch.object(exchange, 'load_examples', return_value=self.examples) as loader:
            artifact, _ = t.train_experimental('/synthetic-double', recipe,
                                               authorization='/synthetic-auth', v5_recipe='/synthetic-recipe')
            loader.assert_called_once_with('/synthetic-double', authorization='/synthetic-auth',
                                           recipe_path='/synthetic-recipe')
            self.assertEqual(artifact['mode'],'EXPERIMENTAL')
            self.assertIn('reader_source_sha256',artifact)

    def test_experimental_reader_refusal_and_manifest_race_propagate(self):
        recipe = {**self.recipe, 'status':'RATIFIED', 'owner_decision':'synthetic-test-only'}
        with patch.object(exchange.D, 'load_manifest', return_value=({'status':'PROVISIONAL'},'0'*64)):
            with patch.object(exchange,'load_examples',side_effect=exchange.ExampleExchangeError('refused')):
                with self.assertRaises(exchange.ExampleExchangeError):
                    t.train_experimental('/synthetic-double',recipe,authorization='/auth',v5_recipe='/recipe')
            with patch.object(exchange,'load_examples',return_value=self.examples):
                with self.assertRaisesRegex(ValueError,'manifest changed'):
                    t.train_experimental('/synthetic-double',recipe,authorization='/auth',v5_recipe='/recipe')

    def test_source_change_refuses_output(self):
        actual = t.source_hashes()
        with patch.object(t, 'source_hashes', side_effect=[actual, actual, {}]):
            with self.assertRaisesRegex(RuntimeError,'source changed'):
                t._fit(self.examples, self.recipe, 'SMOKE')

    def test_bad_recipe_and_final_refused(self):
        for changes in ({'C':True}, {'tol':float('nan')}, {'max_iter':0},
                        {'feature_view':'new'}, {'c1_extensions':'learned'},
                        {'operating_threshold':.5}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                t.validate_recipe({**self.recipe, **changes},'SMOKE')
        with self.assertRaisesRegex(ValueError,'FINAL'):
            t.validate_recipe(self.recipe,'FINAL')


if __name__ == '__main__':
    unittest.main()
