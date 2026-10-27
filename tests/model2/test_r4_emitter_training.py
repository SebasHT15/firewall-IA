"""Synthetic proposed r4 emitter -> shared reader -> portable Model 2 fit."""
from pathlib import Path
import unittest
from tests import test_v5_r4_emitter as fixture
from scripts.model2 import training as t


class R4TrainingTests(unittest.TestCase):
    def test_emitted_reference_rows_fit_and_reload_through_public_training_entry(self):
        case = fixture.R4EmitterTests()
        case.setUp(); self.addCleanup(case.doCleanups)
        dataset, authorization, manifest = case.consume()
        recipe = {**t.candidate_recipe(), 'status':'RATIFIED',
                  'owner_decision':'TEST DOUBLE; synthetic data only'}
        artifact, report = t.train_experimental(dataset, recipe, authorization=authorization,
                                                v5_recipe=fixture.E.DEFAULT_RECIPE)
        self.assertEqual(artifact['mode'],'EXPERIMENTAL')
        self.assertLess(report['max_probability_delta'],1e-12)
        examples = fixture.E.load_examples(str(dataset),authorization=str(authorization))
        self.assertTrue(any(r['label_status']==fixture.RC.TRAINING_REFERENCE for r in examples['TRAIN']))
        path = case.root/'model.json'
        sha = t.save_artifact(artifact,path)
        loaded = t.load_artifact(path,expected_sha256=sha)
        for row in examples['VALIDATION']:
            self.assertEqual(t.score(artifact,row['text']),t.score(loaded,row['text']))
        for name in artifact['feature_names']:
            self.assertIn(name.split('=',1)[0],t.features.FEATURES)
        self.assertFalse(artifact['operational_policy_approved'])
        self.assertIsNone(artifact['operating_threshold'])


if __name__=='__main__':unittest.main()
