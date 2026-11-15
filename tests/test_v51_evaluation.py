"""Evaluation integrity: failure credit, tied scores, dependency and pairing."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'scripts/v5_successor'))
import evaluation_metrics as E
import collect_evaluation as C


def case(cid='a', label='BLOCK', component='g1', pair=None):
    return dict(id=cid, label=label, canonical_sha256=cid*64, component_id=component,
                cohort='test', category='SQL', pair_id=pair,
                expected_reason='SQL injection payload detected.' if label == 'BLOCK' else 'Normal',
                canonical_text='GET / HTTP/1.1\n')


def pred(c, decision=None, status='ok', **extra):
    return dict(id=c['id'], canonical_sha256=c['canonical_sha256'], status=status,
                decision=decision or c['label'], invalid_reason=None, **extra)


class QualityTests(unittest.TestCase):
    def test_invalid_block_is_fn_even_when_runtime_denies(self):
        c = case()
        result = E.quality([c], [pred(c, status='invalid')])
        self.assertEqual(result['principal_E5']['FN'], 1)
        self.assertEqual(result['parseable_only']['N'], 0)
        self.assertEqual(result['runtime_fail_closed_derived']['confusion']['TP'], 1)

    def test_invalid_benign_is_false_positive(self):
        c = case(label='ALLOW')
        self.assertEqual(E.quality([c], [pred(c, status='invalid')])['principal_E5']['FP'], 1)

    def test_non_ok_with_block_cannot_earn_credit(self):
        c = case()
        self.assertEqual(E.prediction_cell(c, pred(c, status='SCORING_FAILED'))[0], 'FN')

    def test_invalid_reason_makes_inconsistent_ok_invalid(self):
        c = case()
        p = pred(c)
        p['invalid_reason'] = 'no_eos'
        self.assertFalse(E.prediction_cell(c, p)[1])

    def test_unknown_decision_does_not_disappear_from_denominator(self):
        c = case()
        self.assertEqual(E.quality([c], [pred(c, 'UNKNOWN')])['principal_E5']['N'], 1)

    def test_explicit_missing_eos_cannot_earn_credit(self):
        c = case()
        self.assertFalse(E.prediction_cell(c, pred(c, ended_with_eos=False))[1])

    def test_unknown_label_is_rejected(self):
        with self.assertRaises(ValueError):
            E.prediction_cell(case(label='UNKNOWN'), {})

    def test_reason_is_distinct_from_binary_detection(self):
        c = case()
        result = E.quality([c], [pred(c, reason='Wrong category')])
        self.assertEqual(result['principal_E5']['TP'], 1)
        self.assertEqual(result['reason']['exact_rate_over_eligible'], 0)

    def test_empty_metrics_are_null_not_perfect(self):
        result = E.quality([], [])
        self.assertIsNone(result['principal_E5']['recall_block'])
        self.assertIsNone(result['invalid']['rate'])

    def test_standard_confusion_and_mcc(self):
        m = E.confusion(['TP']*3+['TN']*2+['FP']+['FN']*2)
        self.assertEqual(m['N'], 8)
        self.assertEqual(m['recall_block'], .6)
        self.assertAlmostEqual(m['mcc'], 4/(240**.5))


class IntegrityTests(unittest.TestCase):
    def test_missing_prediction_refused(self):
        with self.assertRaises(ValueError):
            E.checked_predictions([case()], [])

    def test_duplicate_prediction_refused(self):
        c = case()
        with self.assertRaises(ValueError):
            E.checked_predictions([c], [pred(c), pred(c)])

    def test_duplicate_case_refused(self):
        c = case()
        with self.assertRaises(ValueError):
            E.checked_predictions([c, c], [pred(c)])

    def test_changed_text_refused(self):
        c = case()
        p = pred(c)
        p['canonical_sha256'] = 'bad'
        with self.assertRaises(ValueError):
            E.checked_predictions([c], [p])

    def test_same_population_different_order_is_paired_by_id(self):
        a, b = case('a'), case('b')
        result = E.checked_predictions([a, b], [pred(b), pred(a)])
        self.assertEqual([p['id'] for p in result], ['a', 'b'])


class PairTests(unittest.TestCase):
    def test_joint_requires_both_members_correct(self):
        a, b = case('a', 'ALLOW', pair='x'), case('b', pair='x')
        r = E.pairs([a, b], [pred(a), pred(b, 'ALLOW')])
        self.assertEqual((r['complete_pairs'], r['both_correct'], r['attack_errors']), (1, 0, 1))

    def test_three_members_are_ambiguous(self):
        cases = [case(str(i), pair='x') for i in range(3)]
        self.assertEqual(E.pairs(cases, [pred(c) for c in cases])['incomplete_or_ambiguous_pairs'], 1)

    def test_bootstrap_does_not_replace_missing_groups_with_rows(self):
        c = case(component=None)
        self.assertEqual(E.cluster_bootstrap([c], [pred(c)])['status'], 'NOT_ESTIMABLE')

    def test_one_group_has_no_interval(self):
        c = case()
        self.assertEqual(E.cluster_bootstrap([c], [pred(c)])['status'], 'NOT_ESTIMABLE')

    def test_bootstrap_deterministic_and_preserves_perfect_result(self):
        cases = [case('a'), case('b', component='g2')]
        predictions = [pred(c) for c in cases]
        a = E.cluster_bootstrap(cases, predictions, replicates=40)
        self.assertEqual(a, E.cluster_bootstrap(cases, predictions, replicates=40))
        self.assertEqual(a['intervals_95']['recall_block']['low'], 1)

    def test_comparison_uses_same_ids_and_records_regression(self):
        a, b = case('a'), case('b', 'ALLOW', component='g2')
        old, new = [pred(a), pred(b)], [pred(a, 'ALLOW'), pred(b)]
        result = E.paired_comparison([a, b], old, new, replicates=30)
        self.assertEqual((result['improved'], result['regressed'], result['accuracy_delta']), (0, 1, -.5))


class ProbabilityTests(unittest.TestCase):
    def scores(self, values, labels):
        cases = [case(str(i), label) for i, label in enumerate(labels)]
        return cases, [dict(status='OK', p_block=x) for x in values]

    def test_perfect_ranking_and_selective_counts(self):
        cases, p = self.scores([.9, .1], ['BLOCK', 'ALLOW'])
        r = E.probability_metrics(cases, p, [.9])
        self.assertEqual((r['roc_auc'], r['average_precision']), (1, 1))
        self.assertEqual(r['descriptive_thresholds'][0]['early_block_fp'], 0)
        self.assertEqual(r['descriptive_thresholds'][0]['defer_rate'], .5)
        self.assertIsNone(r['selected_threshold'])

    def test_ties_receive_half_auc_and_ap_uses_tied_group(self):
        cases, p = self.scores([.5, .5], ['BLOCK', 'ALLOW'])
        r = E.probability_metrics(cases, p, [.9])
        self.assertEqual((r['roc_auc'], r['average_precision']), (.5, .5))
        self.assertEqual(r['brier'], .25)

    def test_single_class_auc_is_not_estimable(self):
        cases, p = self.scores([.5], ['BLOCK'])
        self.assertIsNone(E.probability_metrics(cases, p, [.9])['roc_auc'])

    def test_nonfinite_probability_refused(self):
        cases, p = self.scores([float('nan')], ['BLOCK'])
        with self.assertRaises(ValueError):
            E.probability_metrics(cases, p, [.9])

    def test_missing_score_cannot_shrink_population(self):
        with self.assertRaises(ValueError):
            E.probability_metrics([case()], [], [.9])

    def test_non_ok_score_refused_for_probability_summary(self):
        cases, p = self.scores([.9], ['BLOCK'])
        p[0]['status'] = 'SCORING_FAILED'
        with self.assertRaises(ValueError):
            E.probability_metrics(cases, p, [.9])


class RuntimeTests(unittest.TestCase):
    def test_false_fallback_does_not_imply_verified(self):
        r = E.decoder_summary([dict(decoder_verified=False, decoder_fallback=False, generated_tokens=0)])
        self.assertIn('no_generation', r)
        self.assertNotIn('verified', r)

    def test_conflicting_decoder_flags_are_not_verified(self):
        r = E.decoder_summary([dict(decoder_verified=True, decoder_fallback=True)])
        self.assertIn('inconsistent_flags', r)

    def test_counterfactual_non_ok_block_score_defers(self):
        c = case()
        model2 = pred(c, status='SCORING_FAILED', p_block=1)
        result = C.counterfactual([c], [pred(c, 'ALLOW')], [model2], .9)
        self.assertEqual(result[0]['decision'], 'ALLOW')
        self.assertEqual(result[0]['deciding_stage'], 'v5')

    def test_counterfactual_valid_early_block(self):
        c = case()
        result = C.counterfactual([c], [pred(c, 'ALLOW')], [pred(c, status='OK', p_block=.9)], .9)
        self.assertEqual(result[0]['deciding_stage'], 'model2')

    def test_latency_nearest_rank_not_average_of_percentiles(self):
        self.assertEqual(E.distribution([1, 2, 3, 100])['p95'], 100)

    def test_invalid_latency_refused(self):
        with self.assertRaises(ValueError):
            E.distribution([-1])

    def test_profile_mismatch_refused_before_classification(self):
        replies = [dict(model_loaded=True, adapter_sha256='adapter', runtime_profile={'sha256': 'experimental'}),
                   dict(recipe_sha256='recipe')]
        with patch.object(C, 'request_json', side_effect=replies):
            with self.assertRaises(ValueError):
                C.service_identity(None, 'http://127.0.0.1:1', 'adapter', 'recipe', None)

    def test_remote_http_not_allowed(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(ValueError):
                C.collect_http([], url='http://remote.invalid', adapter_sha='a', recipe_sha='r',
                               profile_sha=None, out=Path(temp))

    def test_http_contract_violation_is_invalid_not_correct(self):
        c = case()
        identity = dict(contract=dict(vocabulary=['BLOCK | SQL injection payload detected.']))
        replies = [dict(status='ok', decision='BLOCK', reason='wrong reason', ended_with_eos=True)]
        with tempfile.TemporaryDirectory() as temp, patch.object(C, 'service_identity', return_value=identity), patch.object(C, 'request_json', side_effect=replies):
            predictions, _ = C.collect_http([c], url='http://127.0.0.1:1', adapter_sha='a', recipe_sha='r',
                                            profile_sha=None, out=Path(temp), warmup=0)
            self.assertEqual(predictions[0]['status'], 'invalid')
            self.assertEqual(E.quality([c], predictions)['principal_E5']['FN'], 1)


if __name__ == '__main__':
    unittest.main()
