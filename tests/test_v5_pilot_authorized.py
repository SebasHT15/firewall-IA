"""Synthetic controls for pilot preparation -> effective #80 authorized build."""
import builtins
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from tests import test_v5_r4_emitter as shared
from tests import test_v5_pilot_inputs as original

P, C = original.P, original.C


class PilotIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name); self.pools=self.root/'pools'
        with contextlib.redirect_stdout(io.StringIO()):original.build_pools(str(self.pools),300)

    def test_measure_reads_verified_train_validation_only(self):
        out=self.root/'prepared'
        P.prepare(str(self.pools),str(out),per_category=40)
        actual=builtins.open; seen=[]
        def spy(path,*args,**kwargs):
            if isinstance(path,(str,Path)):seen.append(str(path))
            return actual(path,*args,**kwargs)
        with patch('builtins.open',spy):report=P.measure(str(out))
        self.assertEqual(report['per_source_contribution_scope'],['TRAIN','VALIDATION'])
        self.assertTrue(report['per_source_contribution'])
        self.assertFalse(any('INTERNAL_TEST' in path or 'E6_RESERVE' in path for path in seen))
        path=out/'rows.VALIDATION.meta.jsonl';path.write_bytes(path.read_bytes()+b' ')
        with self.assertRaisesRegex(P.PilotInputError,'hash mismatch'):P.measure(str(out))

    def test_guard_protected_inputs_before_open(self):
        with patch('builtins.open',side_effect=AssertionError('must reject before open')):
            for method,args in ((P.load_attack_records,(str(self.root/'INTERNAL_TEST/source.jsonl'),)),
                                (P._verify_pool_manifest,(str(self.root/'E6_RESERVE'),P.PILOT_POOL_IDS)),
                                (P.measure,(str(self.root/'STAB-HELD'),))):
                with self.assertRaises(SystemExit):method(*args)

    def test_builder_exclusions_have_excluded_status(self):
        records,_=original.B.build_pool('addr_data',300)
        excluded=[r for r in records if r['exclusion_reason']]
        self.assertTrue(excluded)
        self.assertTrue(all(r['status']==C.EXCLUDED for r in excluded))

    def test_complete_synthetic_production_route_uses_shared_build_and_reader(self):
        self._exercise_production_route()

    def test_calibration_accepts_pinned_proposed_values_but_cannot_train(self):
        self._exercise_production_route(purpose='PILOT_BUILD')

    def _exercise_production_route(self,purpose='REAL_BUILD'):
        values=P._synthetic_benign_stand_ins()
        benign=self.root/'benign';benign.mkdir()
        artifacts=[]
        for pool,items in values.items():
            records=[{'pool_id':pool,'value':v,'value_entry_id':C.value_entry_id(pool,v),
                      'status':C.ACCEPTED,'exclusion_reason':None,'synthetic':True} for v in items]
            artifacts.append(C.write_jsonl(str(benign/(pool+'.jsonl')),records,key=lambda r:r['value']))
        (benign/'manifest.json').write_text(json.dumps({'artifacts':artifacts}))
        records=P.synthetic_attack_records(40)
        binding=shared.make_bundle(self.root/'evidence',records=records,
                                  outcomes={c:shared.G.OUTCOME_PASS for c in P.PILOT_CATEGORIES})
        prereg=self.root/'prereg.json';prereg.write_text('{"test_double":true}')
        pre_sha=hashlib.sha256(prereg.read_bytes()).hexdigest()
        auth={'schema':shared.G.PROPOSED_REAL_BUILD_AUTH_SCHEMA,'scope':'REAL_BUILD',
              'preregistration_sha256':pre_sha,'authorized_by':'TEST DOUBLE','date':'synthetic',
              'owner_decision':'synthetic-only','audit_evidence':binding,'dataset_spec':'V5-DATA-SPEC-r4',
              'row_contract':shared.RC.SCHEMA}
        ap=self.root/'auth.json';ap.write_text(json.dumps(auth))
        cfg=P.pilot_gen_config(P.PILOT_CATEGORIES,mode='real',attack_label_basis='post_filter_audit')
        for block in cfg.values():
            if isinstance(block,dict) and 'status' in block:
                block['status']='PROPOSED' if purpose=='PILOT_BUILD' else 'RATIFIED'
        if purpose=='PILOT_BUILD':cfg['oracle']['status']='PENDING'
        gp=self.root/'gen.json';gp.write_text(json.dumps(cfg))
        split=P.pilot_split_config(list(P.BENIGN_POOL_IDS)+list(P.PILOT_POOL_IDS),P.PILOT_CATEGORIES)
        sp=self.root/'split.json';sp.write_text(json.dumps(split))
        if purpose=='PILOT_BUILD':
            auth.update(schema=shared.G.PA.SCHEMA,scope='PILOT_BUILD',purpose='CALIBRATION_ONLY',
                        generator_config_sha256=shared.G.config_sha256(cfg),
                        split_config_sha256=shared.G.S.config_sha256(split),allows_training=False,
                        final_dataset=False,pilot_fraction={'numerator':1,'denominator':10},
                        full_pairs_per_cluster_category=20)
            ap.write_text(json.dumps(auth))
        kw=dict(build_purpose=purpose,attack_pool=binding['pool']['path'],benign_dir=str(benign),authorization_path=str(ap),
                audit_exchange_path=binding['exchange']['path'],dataset_prereg=str(prereg),
                split_config=str(sp),generator_config=str(gp))
        out=self.root/'dataset'
        with contextlib.ExitStack() as stack:
            for target,name,value in ((shared.AE,'is_committed',lambda p:True),
                                      (shared.D,'git_committed_unmodified',lambda p:True)):
                stack.enter_context(patch.object(target,name,value))
            if purpose=='PILOT_BUILD':
                # The same proposed parameters remain forbidden to the full-build route.
                full_auth={**auth,'schema':shared.G.REAL_BUILD_AUTH_SCHEMA,'scope':'REAL_BUILD'}
                ap.write_text(json.dumps(full_auth))
                forbidden=P.prepare(str(self.pools),str(self.root/'not-final'),**{**kw,'build_purpose':'REAL_BUILD'})
                self.assertEqual(forbidden['status'],'REFUSED')
                self.assertIn('VALUE_NOT_RATIFIED',{d['code'] for d in forbidden['unmet']})
                self.assertFalse((self.root/'not-final').exists())
                ap.write_text(json.dumps(auth))
            result=P.prepare(str(self.pools),str(out),**kw)
            self.assertEqual(result['status'],'BUILT',result)
            manifest,sha=shared.D.load_manifest(str(out))
            self.assertEqual(manifest['generator_config']['mode'],'real')
            self.assertFalse(manifest['fixture'])
            self.assertEqual(manifest['row_contract'],shared.RC.SCHEMA)
            exp={**auth,'schema':shared.D.AUTH_SCHEMA,'scope':'EXPERIMENTAL','provisional':True,
                 'dataset_manifest_sha256':sha,'reference':'TEST DOUBLE','purpose':'synthetic integration',
                 'uses_pending_labels_as_verified':False,
                 'category_outcomes':{c:shared.G.OUTCOME_PASS for c in P.PILOT_CATEGORIES}}
            ep=self.root/'experimental.json';ep.write_text(json.dumps(exp))
            if purpose=='PILOT_BUILD':
                self.assertEqual(manifest['status'],'PROVISIONAL_PILOT')
                self.assertFalse(manifest['training_authorized'])
                self.assertTrue(all(v in ('PROPOSED','PENDING') for v in manifest['value_statuses'].values()))
                with patch.object(shared.E,'_verify_and_parse',side_effect=AssertionError('no training rows')):
                    with self.assertRaisesRegex(shared.E.ExampleExchangeError,'CALIBRATION_DATA_NOT_FOR_TRAINING'):
                        shared.E.load_examples(str(out),authorization=str(ep))
                final=shared.D.gate_dataset_final(manifest,sha,dataset_prereg=None,freeze_record=None)
                self.assertIn('CALIBRATION_DATA_NOT_FOR_TRAINING',{d.code for d in final})
            else:
                examples=shared.E.load_examples(str(out),authorization=str(ep))
                self.assertTrue(any(r['label_status']==shared.RC.TRAINING_REFERENCE for r in examples['TRAIN']))
            measured=P.measure(str(out))
            self.assertEqual(measured['protected_role_files_opened'],[])
        # Restored defaults must refuse the identical records before writing.
        refused=P.prepare(str(self.pools),str(self.root/'refused'),**kw)
        self.assertEqual(refused['status'],'REFUSED')
        self.assertFalse((self.root/'refused').exists())


if __name__=='__main__':unittest.main()
