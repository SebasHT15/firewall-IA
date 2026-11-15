"""Fixed benchmark selection has no dependency on predictions or input order."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts/v5_successor'))
from benchmark_successor_decoder import selected_ids


class SelectionTests(unittest.TestCase):
    def cases(self):
        return [dict(id=f'{cohort}-{label}-{i}', cohort=cohort, label=label,
                     component_id=f'g{i%15}' if cohort=='policy_validation_selection' else None,
                     category=f'category-{i%4}', carrier=('query','form','json')[i%3])
                for cohort in ('policy_validation_selection','authored_regression_known_DEV')
                for label in ('ALLOW','BLOCK') for i in range(80)]

    def test_order_invariant_and_balanced(self):
        cases = self.cases()
        ids = selected_ids(cases)
        self.assertEqual(ids, selected_ids(list(reversed(cases))))
        self.assertEqual(len(ids), len(set(ids)))
        selected = [c for c in cases if c['id'] in ids]
        self.assertEqual(sum(c['label']=='BLOCK' for c in selected), 50)
        self.assertEqual(sum(c['cohort']=='policy_validation_selection' for c in selected), 80)

    def test_prediction_fields_cannot_influence_selection(self):
        cases = self.cases()
        self.assertEqual(selected_ids(cases), selected_ids([dict(c, decision='BLOCK', p_block=1) for c in cases]))

    def test_insufficient_stratum_refused(self):
        with self.assertRaises(ValueError):
            selected_ids(self.cases()[:10])


if __name__=='__main__':
    unittest.main()
