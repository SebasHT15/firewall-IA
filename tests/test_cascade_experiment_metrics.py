"""Independent arithmetic checks for the expanded experimental report."""
import sys, unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts/cascade_lab/experiments'))
import analyze as A
class ExperimentArithmeticTests(unittest.TestCase):
    def test_e5_extended_metrics_preserve_invalid_errors(self):
        rows=[dict(id='1',label='BLOCK',decision='BLOCK'),dict(id='2',label='BLOCK',decision=None,invalid_reason='no_eos'),dict(id='3',label='ALLOW',decision='ALLOW'),dict(id='4',label='ALLOW',decision='BLOCK')]
        q=A.cm(rows);p=q['principal']
        self.assertEqual([p[k] for k in ('TP','TN','FP','FN','N')],[1,1,1,1,4])
        self.assertEqual(p['mcc'],0);self.assertEqual(p['balanced_accuracy'],.5)
        self.assertEqual(p['f1_macro'],.5);self.assertEqual(q['invalid']['model_output_errors'],1)
    def test_zero_support_does_not_become_perfect_score(self):
        q=A.cm([])['principal'];self.assertIsNone(q['precision_block']);self.assertIsNone(q['recall_block']);self.assertIsNone(q['mcc'])
    def test_paired_reversals_align_by_id(self):
        a=[dict(id='x',label='ALLOW',decision='BLOCK'),dict(id='y',label='BLOCK',decision='BLOCK')]
        b=[dict(id='y',label='BLOCK',decision='ALLOW'),dict(id='x',label='ALLOW',decision='ALLOW')]
        p=A.paired(a,b);self.assertEqual((p['right_improved'],p['right_regressed']),(1,1));self.assertEqual(p['accuracy_delta'],0)
    def test_zero_observed_false_positives_keeps_upper_bound(self):
        low,high=A.wilson(0,300);self.assertAlmostEqual(low,0);self.assertGreater(high,.01)
if __name__=='__main__':unittest.main()
