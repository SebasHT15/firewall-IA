"""Pilot permission pins effective parameters; it cannot grant final or training use."""
import copy
import sys
from pathlib import Path
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts/dataset'))
import v5_pilot_authorization as P


class CalibrationPermissionTests(unittest.TestCase):
    def setUp(self):
        self.auth={'schema':P.SCHEMA,'scope':'PILOT_BUILD','purpose':'CALIBRATION_ONLY',
                   'generator_config_sha256':'g','split_config_sha256':'s','preregistration_sha256':'p',
                   'allows_training':False,'final_dataset':False,'authorized_by':'TEST DOUBLE',
                   'date':'synthetic','owner_decision':'test only',
                   'pilot_fraction':{'numerator':1,'denominator':10},'full_pairs_per_cluster_category':20}
        self.kw={'generator_sha':'g','split_sha':'s','preregistration_sha':'p',
                 'generator_config':{'quota':{'pairs_per_cluster_category':2}}}

    def test_unratified_schema_refuses_even_a_complete_record(self):
        with patch.object(P,'ACTIVE_SCHEMA',None):
            self.assertTrue(P.check(self.auth,**self.kw))

    def test_effective_input_pins_and_scope_are_mandatory(self):
        with patch.object(P,'ACTIVE_SCHEMA',P.SCHEMA):
            self.assertEqual(P.check(self.auth,**self.kw),[])
            for change in ({'generator_config_sha256':'changed'},{'split_config_sha256':'changed'},
                           {'preregistration_sha256':'changed'},{'scope':'REAL_BUILD'},
                           {'purpose':'TRAINING'},{'allows_training':True},{'final_dataset':True}):
                with self.subTest(change=change):self.assertTrue(P.check({**self.auth,**change},**self.kw))

    def test_quota_fraction_not_a_declarative_label(self):
        with patch.object(P,'ACTIVE_SCHEMA',P.SCHEMA):
            for full in (True,0,-1,None):
                self.assertTrue(P.check({**self.auth,'full_pairs_per_cluster_category':full},**self.kw))
            self.assertTrue(P.check({**self.auth,'pilot_fraction':{'numerator':1,'denominator':2}},**self.kw))
            self.assertTrue(P.check(self.auth,**{**self.kw,'generator_config':{'quota':{'pairs_per_cluster_category':20}}}))
            self.assertEqual(P.check({**self.auth,'full_pairs_per_cluster_category':11},**self.kw),[])


if __name__=='__main__':unittest.main()
