"""Composition access, identity and resource gates, without weights or commits."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts/v5_successor'))
import successor_contract as C
from train_successor import gpu_available


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.path=Path(self.tmp.name)/'owner.json'
        self.manifest=dict(recipe=dict(path='recipe.json',sha256='r'),protocol=dict(path='protocol.json',sha256='p'),
                           evidence=dict(policy_admission=dict(path='policy.json',sha256='s')),
                           manifest_path='manifest.json',source_sha256={'scripts/source.py':'x'})
        self.auth=dict(schema=C.AUTH_SCHEMA,status='APPROVED_EXPERIMENTAL',scope='EXPERIMENTAL_V5_ONLY',
                       training_allowed=True,accept_scoped_policy_sources=True,
                       owner_decision='unit-fixture-only',authorized_by='unit-fixture',date='fixture',
                       dataset_manifest_sha256='m',recipe_sha256='r',protocol_sha256='p',policy_source_admission_sha256='s')
    def admit(self,committed=lambda _:True):
        self.path.write_text(json.dumps(self.auth))
        return C.require_admission(self.manifest,'m',self.path,committed=committed)
    def test_no_record_never_authorizes_training(self):
        with self.assertRaisesRegex(C.Refused,'missing'):C.require_admission(self.manifest,'m',None)
    def test_uncommitted_admission_is_rejected(self):
        with self.assertRaisesRegex(C.Refused,'committed'):self.admit(lambda _:False)
    def test_draft_is_rejected_even_with_hashes(self):
        self.auth['status']='DRAFT_PENDING_OWNER'
        with self.assertRaisesRegex(C.Refused,'APPROVED_EXPERIMENTAL'):self.admit()
    def test_other_training_scope_is_rejected(self):
        self.auth['scope']='FINAL'
        with self.assertRaisesRegex(C.Refused,'scope'):self.admit()
    def test_training_flag_must_be_literal_true(self):
        self.auth['training_allowed']='true'
        with self.assertRaisesRegex(C.Refused,'scope'):self.admit()
    def test_blank_owner_is_rejected(self):
        self.auth['owner_decision']=' '
        with self.assertRaisesRegex(C.Refused,'incomplete'):self.admit()
    def test_other_manifest_is_rejected(self):
        self.auth['dataset_manifest_sha256']='other'
        with self.assertRaisesRegex(C.Refused,'hash mismatch'):self.admit()
    def test_other_recipe_is_rejected(self):
        self.auth['recipe_sha256']='other'
        with self.assertRaisesRegex(C.Refused,'hash mismatch'):self.admit()
    def test_other_source_proposal_is_rejected(self):
        self.auth['policy_source_admission_sha256']='other'
        with self.assertRaisesRegex(C.Refused,'hash mismatch'):self.admit()
    def test_scoped_source_admission_must_be_explicit(self):
        self.auth['accept_scoped_policy_sources']=False
        with self.assertRaisesRegex(C.Refused,'not accepted'):self.admit()
    def test_bound_code_must_also_be_committed(self):
        with self.assertRaisesRegex(C.Refused,'sources/records'):self.admit(lambda p:not p.endswith('source.py'))
    def test_exact_committed_fixture_is_admitted_only_as_experimental(self):
        self.assertEqual(self.admit()['scope'],'EXPERIMENTAL_V5_ONLY')


class InputBoundaryTests(unittest.TestCase):
    def test_changed_bytes_do_not_parse(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'TRAIN.source.jsonl';path.write_bytes(b'changed')
            with self.assertRaisesRegex(C.Refused,'changed'):C.capture(dict(path=str(path),sha256='0'*64))
    def test_reserve_descriptor_rejected_before_opening_rows(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'manifest.json'
            m=dict(schema=C.SCHEMA,status='EXPERIMENTAL_CANDIDATE',manifest_path=str(path.resolve()),
                   row_contract=C.RC.SCHEMA,dataset_dir=d,artifacts=[dict(name='rows.INTERNAL_TEST.jsonl',path='never-open')])
            path.write_text(json.dumps(m))
            with self.assertRaisesRegex(C.Refused,'TRAIN/VALIDATION'):C.load_package(path)
    def test_mapped_metadata_preserves_label_evidence_and_source(self):
        before=dict(schema='v51-stage4-preview-row/v1',split='TRAIN_CANDIDATE',label='BLOCK',
                    label_status='POLICY_DEFINED',label_status_basis='policy_defined',payload_record_id='source')
        frozen=copy.deepcopy(before);after=C.mapped_meta(before,'TRAIN')
        self.assertEqual(before,frozen);self.assertEqual(after['payload_record_id'],'source')
        self.assertEqual(after['label_status'],'POLICY_DEFINED');self.assertEqual(after['source_split'],'TRAIN_CANDIDATE')
    def test_review_never_calls_training_admission(self):
        with patch.object(C,'load_package',return_value=({},'hash')),patch.object(C,'verify_metadata',return_value=({},{})),patch.object(C,'read_rows',return_value=({},{})),patch.object(C,'require_admission') as admission:
            C.prepare('fixture',training=False);admission.assert_not_called()
    def test_training_checks_access_before_reading_rows(self):
        with patch.object(C,'load_package',return_value=({},'hash')),patch.object(C,'read_rows',side_effect=AssertionError('rows opened')) as rows:
            with self.assertRaisesRegex(C.Refused,'missing'):C.prepare('fixture',training=True)
            rows.assert_not_called()


class ResourceTests(unittest.TestCase):
    def test_claude_reservation_is_respected(self):
        with self.assertRaisesRegex(C.Refused,'Claude'):gpu_available({'owner':'Claude'},[])
    def test_foreign_gpu_worker_is_respected(self):
        with self.assertRaisesRegex(C.Refused,'another GPU'):gpu_available({'owner':None},['123, python'])
    def test_desktop_only_does_not_occupy_training_slot(self):
        gpu_available({'owner':None},['123, /usr/bin/ptyxis'])


class EvidenceLineageTests(unittest.TestCase):
    def setUp(self):
        preview=[dict(split=s+'_CANDIDATE',path='/fixture/'+s+'.preview',sha256=s+'-preview') for s in C.SPLITS]
        sources=[dict(split=s+'_CANDIDATE',path='/fixture/'+s+'.source',sha256=s+'-source') for s in C.SPLITS]
        self.evidence=dict(preview=dict(source_partition_sha256='plan',catalog_sha256='catalog',artifacts=preview),
            partition=dict(catalog_sha256='catalog',source_registry_sha256='registry',artifacts=sources),
            preview_audit=dict(preview_sha256='rendering'),shortcuts=dict(preview_sha256='rendering'),
            probes=dict(preview_sha256='rendering'),catalog_audit=dict(catalog_sha256='catalog'),
            provenance=dict(candidate_sha256='registry'),
            policy_admission=dict(source_registry_sha256='registry',policy_sha256='policy',validator_sha256='validator'))
        self.manifest=dict(evidence=dict(preview=dict(sha256='rendering'),partition=dict(sha256='plan')),
            parent=dict(manifest=dict(sha256='parent')),
            source_sha256={'scripts/dataset/v5_policy/policy_table_v1.json':'policy',
                           'scripts/v5_successor/policy_admission_proposal.py':'validator'},
            augmentation=dict(preview_artifacts={s:dict(path=r['path'],sha256=r['sha256']) for s,r in zip(C.SPLITS,preview)},
                              source_artifacts={s:dict(path=r['path'],sha256=r['sha256']) for s,r in zip(C.SPLITS,sources)}))
        self.protocol=dict(parent_manifest_sha256='parent')
    def check(self):C.verify_lineage(self.manifest,self.evidence,self.protocol)
    def test_same_lineage_passes(self):self.check()
    def test_pass_from_other_rendering_is_rejected(self):
        self.evidence['probes']['preview_sha256']='another'
        with self.assertRaisesRegex(C.Refused,'another rendering'):self.check()
    def test_swapped_train_validation_sources_are_rejected(self):
        self.manifest['augmentation']['source_artifacts']['TRAIN']=self.manifest['augmentation']['source_artifacts']['VALIDATION']
        with self.assertRaisesRegex(C.Refused,'not the reviewed'):self.check()
    def test_other_preview_input_is_rejected(self):
        self.manifest['augmentation']['preview_artifacts']['TRAIN']['sha256']='unreviewed'
        with self.assertRaisesRegex(C.Refused,'not the reviewed'):self.check()
    def test_other_parent_is_rejected(self):
        self.protocol['parent_manifest_sha256']='another'
        with self.assertRaisesRegex(C.Refused,'parent mismatch'):self.check()
    def test_other_registry_is_rejected(self):
        self.evidence['policy_admission']['source_registry_sha256']='another'
        with self.assertRaisesRegex(C.Refused,'registry lineage'):self.check()
    def test_other_catalog_is_rejected(self):
        self.evidence['catalog_audit']['catalog_sha256']='another'
        with self.assertRaisesRegex(C.Refused,'catalog evidence'):self.check()


class PolicyComponentTests(unittest.TestCase):
    def setUp(self):
        category=C.L.K.SSRF;reason=C.L.CATEGORY_REASON[category]
        self.meta=dict(attack_category=category,label_status='POLICY_DEFINED',label_status_basis='policy_defined',
                       policy_id='POL-URL-META',label_rule='POL-URL-META',reason_string=reason,output='BLOCK | '+reason)
        self.source=dict(policy_id='POL-URL-META')
    def test_policy_metadata_remains_policy_defined(self):C.require_policy_label(self.meta,self.source)
    def test_parent_ai_audit_cannot_be_transferred_to_new_urls(self):
        self.meta.update(label_status='TRAINING_REFERENCE',label_status_basis='ai_audit')
        with self.assertRaisesRegex(C.Refused,'cannot inherit'):C.require_policy_label(self.meta,self.source)
    def test_policy_proof_cannot_be_upgraded_to_verified(self):
        self.meta.update(label_status='VERIFIED',label_status_basis='independent_evidence')
        with self.assertRaisesRegex(C.Refused,'cannot inherit'):C.require_policy_label(self.meta,self.source)
    def test_wrong_reason_is_rejected(self):
        self.meta['output']='BLOCK | SQL injection payload detected.'
        with self.assertRaisesRegex(C.Refused,'reason/rule'):C.require_policy_label(self.meta,self.source)
    def test_other_slot_category_requires_a_new_protocol(self):
        self.meta['attack_category']=C.L.K.XSS
        with self.assertRaisesRegex(C.Refused,'outside typed-URL'):C.require_policy_label(self.meta,self.source)


if __name__=='__main__':unittest.main()
