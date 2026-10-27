"""Preparation integrity only: no candidate qualification or payload execution."""
import copy
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'scripts/dataset'))
import v5_contextual_source_package as P
import build_v5_attack_pool as B


class Construction(unittest.TestCase):
    def test_six_families_contexts_and_pending_labels(self):
        units=P.authored_units(16);profiles={p['profile_id']:p for p in P.profiles()}
        self.assertEqual({r['category_key'] for r in units},set(P.FAMILIES))
        self.assertEqual(len(units),256);self.assertEqual(len(profiles),16)
        self.assertEqual(len({r['record_id'] for r in units}),256)
        for row in units:
            profile=profiles[row['profile_id']]
            self.assertEqual(profile['category_key'],row['category_key'])
            self.assertEqual(profile['sink_template'].count('{INPUT}'),1)
            self.assertTrue(profile['benign_control_template'])
            self.assertTrue(profile['assumptions'])
            self.assertIsNone(row['audit_label']);self.assertFalse(row['training_eligible'])
            self.assertEqual(row['label_status'],'PENDING_ADJUDICATION')
            self.assertNotIn('status',row)  # Cannot look like an ACCEPTED stage-2 row.
            self.assertTrue(row['context_is_metadata_only'])

    def test_constants_do_not_create_new_construction_lineages(self):
        one=P.diversity(P.authored_units(1))['categories']
        many=P.diversity(P.authored_units(16))['categories']
        for category in P.FAMILIES:
            self.assertEqual(one[category]['construction_lineages'],many[category]['construction_lineages'])
        self.assertEqual(sum(v['construction_lineages'] for v in many.values()),16)
        self.assertLess(sum(v['frozen_family_keys'] for v in many.values()),256)

    def test_closed_construction_parameters_and_context_ids(self):
        for n in (0,65,True,'1',None):
            with self.subTest(n=n),self.assertRaises(ValueError):P.payload_for('sql.quoted-or',n)
        with self.assertRaises(ValueError):P.payload_for('unknown',1)
        for variants in (0,65,True,'2'):
            with self.assertRaises(ValueError):P.authored_units(variants)


class Packages(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name)

    def reseal(self,path,name,raw):
        (path/name).write_bytes(raw)
        manifest=json.loads((path/'manifest.json').read_bytes())
        for descriptor in manifest['artifacts']:
            if descriptor['path']==name:descriptor.update(sha256=P.digest(raw),bytes=len(raw))
        (path/'manifest.json').write_bytes(P.encoded(manifest))

    def test_determinism_no_audit_and_no_overwrite(self):
        a=self.root/'a';b=self.root/'b'
        P.prepare(a,variants=3);P.prepare(b,variants=3)
        for path in a.iterdir():self.assertEqual(path.read_bytes(),(b/path.name).read_bytes())
        result=P.verify(a)
        self.assertEqual(result['units'],48);self.assertFalse(result['audit_executed'])
        self.assertFalse(result['training_eligible'])
        with self.assertRaises(ValueError):P.prepare(a)

    def test_tampered_payload_rejected_even_if_artifact_resealed(self):
        out=self.root/'out';P.prepare(out,variants=1)
        raw=(out/'source_units.jsonl').read_bytes();items=[json.loads(x) for x in raw.split(b'\n') if x]
        items[0]['payload_wire']='unrelated documentation'
        self.reseal(out,'source_units.jsonl',b''.join(P.encoded(r) for r in items))
        with self.assertRaisesRegex(ValueError,'units differ'):P.verify(out)

    def test_context_and_authority_changes_refused(self):
        out=self.root/'out';P.prepare(out,variants=1)
        profiles=json.loads((out/'context_profiles.json').read_bytes())
        profiles[0]['assumptions']=[]
        self.reseal(out,'context_profiles.json',P.encoded(profiles))
        with self.assertRaisesRegex(ValueError,'context profiles changed'):P.verify(out)
        m=json.loads((out/'manifest.json').read_bytes());m['training_eligible']=True
        (out/'manifest.json').write_bytes(P.encoded(m))
        with self.assertRaisesRegex(ValueError,'unadmitted'):P.verify(out)

    def test_proposed_units_refused_by_existing_attack_pool_reader(self):
        import v5_pilot_inputs as PI
        out=self.root/'out';P.prepare(out,variants=1)
        with self.assertRaisesRegex(PI.PilotInputError,'no accepted stage-2 records'):
            PI.load_attack_records(str(out/'source_units.jsonl'))

    def test_symlink_artifact_cannot_escape_package(self):
        out=self.root/'out';P.prepare(out,variants=1)
        target=self.root/'elsewhere';target.write_bytes((out/'source_units.jsonl').read_bytes())
        (out/'source_units.jsonl').unlink();(out/'source_units.jsonl').symlink_to(target)
        with self.assertRaisesRegex(ValueError,'escapes package'):P.verify(out)


class WholeDocuments(unittest.TestCase):
    def test_source_body_unicode_heading_and_wordlist_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);patt=root/'patt';patt.mkdir()
            source='intro\n# Section\n```python\n{{1+2}}\n# code is not a heading\n{{3+4}}\u2028tail\n```\nprose\n'
            files={'Server Side Template Injection/fixture.md':source,
                   'SQL Injection/fixture.txt':"one\r\ntwo\r\n"}
            per_file={}
            for rel,text in files.items():
                path=patt/rel;path.parent.mkdir(exist_ok=True,parents=True);path.write_bytes(text.encode())
                category=rel.split('/')[0]
                per_file[rel]={'category':category,'kind':'md' if rel.endswith('.md') else 'txt','sha256':P.digest(path.read_bytes())}
            deny=P.digest((P.ROOT/'scripts/dataset/v5_lexicon/patt_third_party_denylist_v2.json').read_bytes())
            manifest={'patt':{'commit':'fixture'},'denylist':{'sha256':deny},'per_file':per_file}
            path=root/'baseline.json';path.write_bytes(P.encoded(manifest))
            with patch.object(B,'check_patt',return_value={'commit':'fixture','clean':True}):
                units,meta=P.inventory_patt(patt,path,P.digest(path.read_bytes()))
            self.assertEqual(len(units),2)
            fenced=next(r for r in units if r['source_unit_kind']=='CLOSED_FENCED_DOCUMENT')
            self.assertEqual(fenced['source_body'],"{{1+2}}\n# code is not a heading\n{{3+4}}\u2028tail\n")
            self.assertEqual([r['text'] for r in fenced['headings']],['Section'])
            self.assertEqual(fenced['source_body'].encode(),source.encode()[fenced['utf8_byte_start']:fenced['utf8_byte_end']])
            wordlist=next(r for r in units if r['source_unit_kind']=='WHOLE_WORDLIST_DOCUMENT')
            self.assertEqual(wordlist['source_body'],'one\r\ntwo\r\n')
            self.assertTrue(all(not r['training_eligible'] and r['audit_label'] is None for r in units))

    def test_denied_files_are_not_opened(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);deny_path=P.ROOT/'scripts/dataset/v5_lexicon/patt_third_party_denylist_v2.json'
            denied=json.loads(deny_path.read_bytes())['denied'][0]['path']
            category=denied.split('/')[0]
            manifest={'patt':{'commit':'fixture'},'denylist':{'sha256':P.digest(deny_path.read_bytes())},
                      'per_file':{denied:{'category':category,'kind':'txt','sha256':'0'*64}}}
            path=root/'baseline.json';path.write_bytes(P.encoded(manifest))
            # The denied source deliberately does not exist.
            with patch.object(B,'check_patt',return_value={'commit':'fixture','clean':True}):
                units,meta=P.inventory_patt(root,path,P.digest(path.read_bytes()))
            self.assertEqual(units,[]);self.assertEqual(meta['denied_files_not_read'],[denied])


if __name__=='__main__':unittest.main()
