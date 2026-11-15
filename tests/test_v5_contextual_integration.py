"""Integration of prepared profile definitions with synthetic lab fixtures only.

No source package is qualified. Never add fixture_synthetic to a proposed source
record: executable tests construct independent fixture dictionaries explicitly.
"""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts/dataset'))
import v5_contextual_source_package as P
import v5_contextual_lab as L
from tests.test_v5_contextual_lab import unit,profile


class Integration(unittest.TestCase):
    def setUp(self):self.profiles={p['profile_id']:p for p in P.profiles()}

    def test_three_sql_contexts_match_read_only_lab_and_controls(self):
        payloads={'sql.quoted-or':"missing' OR '9'='9",'sql.numeric-or':'0 OR 9=9',
                  'sql.quoted-union':"missing' UNION SELECT 'fixture"}
        for pid,payload in payloads.items():
            with self.subTest(profile=pid):
                result=L.evaluate_unit(unit(payload,'sql_injection',pid),self.profiles[pid],allow_lab_execution=True)
                self.assertEqual((result['status'],result['validation_level']),('SUPPORTED','local_behavior'))
                self.assertTrue(next(c for c in result['checks'] if c['name']=='benign_input_matches_defended_reference')['ok'])

    def test_arithmetic_contexts_have_benign_and_data_only_reference(self):
        if L.capabilities()['jinja2'] is None:self.skipTest('Jinja2 unavailable')
        payloads={'jinja.multiply':'{{3*4}}','jinja.add':'{{3+4}}','jinja.subtract':'{{4-3}}'}
        for pid,payload in payloads.items():
            with self.subTest(profile=pid):
                result=L.evaluate_unit(unit(payload,'ssti',pid),self.profiles[pid],allow_lab_execution=True)
                self.assertEqual(result['status'],'SUPPORTED')
                checks={c['name']:c['ok'] for c in result['checks']}
                self.assertTrue(checks['data_only_reference_preserves_literal'])
                self.assertTrue(checks['benign_input_matches_data_only_reference'])

    def test_prepared_records_never_gain_fixture_execution(self):
        candidate=P.authored_units(1)[0]
        with patch.object(L.sqlite3,'connect',side_effect=AssertionError('execution must not start')):
            result=L.evaluate_unit(candidate,self.profiles[candidate['profile_id']],allow_lab_execution=True)
        self.assertEqual(result['status'],'REJECTED')
        self.assertTrue(any(c['name']=='origin_guard' and not c['ok'] for c in result['checks']))

    def test_default_mode_does_not_execute_any_profile(self):
        with patch.object(L.sqlite3,'connect',side_effect=AssertionError('no SQL in default mode')):
            for candidate in P.authored_units(1):
                result=L.evaluate_unit(candidate,self.profiles[candidate['profile_id']])
                self.assertNotEqual(result['validation_level'],'local_behavior')
                self.assertFalse(result['allow_lab_execution'])

    def test_paths_use_the_declared_base(self):
        for pid,payload,expected in [('path.posix-parent','../private/fixture.txt','/lab/public'),
                                     ('path.windows-parent',r'..\private\fixture.txt',r'C:\lab\public')]:
            result=L.evaluate_unit(unit(payload,'path_traversal',pid),self.profiles[pid])
            detail=next(c['detail'] for c in result['checks'] if c['name']=='escapes_base_dir')
            self.assertIn(repr(expected),detail)

    def test_malformed_types_and_duplicate_marker_rejected(self):
        p=profile('html_fragment','<div>{INPUT}</div>','plain')
        for candidate in (None,[],42):
            result=L.evaluate_unit(candidate,p)
            self.assertEqual(result['status'],'REJECTED')
        result=L.evaluate_unit(unit('x','xss','P-1'),profile('html_fragment','{INPUT}{INPUT}','plain'))
        self.assertEqual(result['status'],'REJECTED')

    def test_unbounded_and_invalid_arithmetic_are_unsupported(self):
        p=self.profiles['jinja.multiply']
        for payload in ('{{9**99999999}}','{{1/0}}','{{'+'1+'*100+'1}}','{{999999999999999}}'):
            with self.subTest(payload=payload[:30]):
                result=L.evaluate_unit(unit(payload,'ssti','jinja.multiply'),p,allow_lab_execution=True)
                self.assertEqual(result['status'],'UNSUPPORTED')


if __name__=='__main__':unittest.main()
