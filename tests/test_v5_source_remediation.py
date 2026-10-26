"""Synthetic parser/residue checks; no public pool, protected data or network."""
import importlib.util
from pathlib import Path
import re
import sys
import unittest
import json
import tempfile
from unittest.mock import patch

PATH=Path(__file__).resolve().parents[1]/'scripts/dataset/v5_source_remediation.py'
spec=importlib.util.spec_from_file_location('source_remediation',PATH)
M=importlib.util.module_from_spec(spec)
sys.modules[spec.name]=M
spec.loader.exec_module(M)


class FenceTests(unittest.TestCase):
    def test_inline_triples_do_not_shift_into_prose(self):
        text='```js\nvalue=`hello```;\n```\nPROSE MUST STAY OUT\n```js\nnext()\n```\n'
        blocks=M.fenced_blocks(text)
        self.assertEqual([b.body for b in blocks],['value=`hello```;\n','next()\n'])
        self.assertTrue(all(b.close_line for b in blocks))

    def test_fence_markers_lengths_and_info(self):
        text='````lang extra\na\n```\nb\n````\n~~~text\nc\n```\nd\n~~~\n'
        blocks=M.fenced_blocks(text)
        self.assertEqual([b.body for b in blocks],['a\n```\nb\n','c\n```\nd\n'])
        self.assertEqual(blocks[0].info,'lang extra')

    def test_indented_documentation_fences(self):
        text='    ``` js\n    first()\n    ```\nparagraph\n  ```html\nsecond\n```\n'
        blocks=M.fenced_blocks(text)
        self.assertEqual([b.body for b in blocks],['    first()\n','second\n'])

    def test_unclosed_block_is_identified(self):
        blocks=M.fenced_blocks('```js\nfirst\n```not-a-close\nsecond\n')
        self.assertEqual(len(blocks),1)
        self.assertIsNone(blocks[0].close_line)

    def test_crlf_and_unicode_separators_preserved(self):
        text='```js\r\nfirst\u2028second\u2029third\r\n```\r\n'
        b=M.fenced_blocks(text)[0]
        self.assertEqual(b.body,'first\u2028second\u2029third\r\n')
        self.assertEqual(b.close_line,3)
        self.assertEqual(text[b.start:b.end],b.body)

    def test_backticks_in_info_are_not_an_opener(self):
        self.assertEqual(M.fenced_blocks('```lang`inline\nprose\n'),())

    def test_units_keep_provenance_and_never_emit_unclosed_or_prose(self):
        text='intro\n```js\na\u2028b\nc\n```\nPROSE\n```js\nunterminated\n'
        units=M.document_units(text)
        self.assertEqual([u['raw'] for u in units],['a\u2028b','c'])
        self.assertEqual([u['physical_line'] for u in units],[3,4])
        self.assertTrue(all(u['multiline_source_block'] for u in units))

    def test_legacy_unicode_split_maps_to_physical_source(self):
        text='heading\n```js\nfirst\u2028second\n```\n'
        start,end,raw=M.legacy_span(text,0,1,False,re.compile(r'```(?:[\w+.-]*)\n(.*?)```',re.S))
        self.assertEqual(raw,'second')
        self.assertEqual(text[start:end],raw)
        self.assertEqual(text.count('\n',0,start)+1,3)


class ResidueTests(unittest.TestCase):
    def check(self,s,cat='SQL Injection',kind='md'):
        return M.residue_proposal(s,cat,kind)

    def test_explicit_metavariables_but_not_arbitrary_identifiers(self):
        for s in ('x [RANDNUM12]','x [RANDSTR]','x [SLEEPTIME]','x <DBNAME>', '[ATTACKER.DOMAIN.TLD]'):
            self.assertIn('explicit_documentation_metavariable',self.check(s)['exclude_reasons'])
        for s in ('SELECT [USER] FROM [dbo].[actual_table]', '{{7*7}}', 'value=[abc]', "[0,1,2]"):
            self.assertEqual(self.check(s)['exclude_reasons'],[])

    def test_versioned_documentation_suffix_only(self):
        for suffix in ('Error-Based RCE <= 1.19','Boolean-Based RCE >=1.41, >=2.10, >=3.0',
                       'Boolean-Based RCE with sandbox bypass using CVE-2022-23614'):
            r=self.check('{{7*7}} // '+suffix,'Server Side Template Injection')
            self.assertEqual(r['transformed'],'{{7*7}}')
            self.assertEqual(r['transform'],'strip_versioned_documentation_suffix')
        for s in ('{{"}} // Error-Based RCE <= 1.19"}}','{{ "http://example.test/a" }}',
                  '{{7*7}} // arbitrary application text','{{7*7}} # meaningful_operator'):
            r=self.check(s,'Server Side Template Injection')
            self.assertIsNone(r['transform'])
            self.assertEqual(r['transformed'],s)

    def test_tool_output_and_versioned_invocation(self):
        self.assertTrue(self.check('sqlite> .dbconfig')['exclude_reasons'])
        self.assertTrue(self.check('python2.7 ./tool.py','Server Side Template Injection')['exclude_reasons'])
        self.assertTrue(self.check('root:x:0:0:root:/root:/bin/sh','Command Injection')['exclude_reasons'])
        self.assertEqual(self.check(';python3 -c "print(1)"','Command Injection')['exclude_reasons'],[])
        self.assertEqual(self.check('cat /etc/passwd','Command Injection')['exclude_reasons'],[])

    def test_context_signals_do_not_auto_exclude(self):
        r=self.check('SELECT data_column FROM data_table')
        self.assertEqual(r['exclude_reasons'],[])
        self.assertTrue(r['review_reasons'])
        r=self.check('$template->render();','Server Side Template Injection')
        self.assertTrue(r['review_reasons'])
        self.assertEqual(r['exclude_reasons'],[])

    def test_sql_pagination_placeholder_is_quarantined_without_substitution(self):
        for payload in ('SELECT 1 LIMIT data_offset,1', 'SELECT 1 LIMIT 1 OFFSET data_offset',
                        "' and 1=cast((SELECT name FROM t WHERE name='data_table' LIMIT 1 OFFSET data_offset) as int) and '1'='1"):
            result=self.check(payload)
            self.assertIn('sql_pagination_metavariable_requires_context',result['exclude_reasons'])
            self.assertEqual(result['transformed'],payload)
        for payload in ("SELECT 'LIMIT data_offset'", 'SELECT "OFFSET data_offset"',
                        'SELECT 1 LIMIT 0,1', 'SELECT 1 OFFSET real_offset'):
            self.assertNotIn('sql_pagination_metavariable_requires_context',self.check(payload)['exclude_reasons'])
        self.assertEqual(self.check('LIMIT data_offset','Command Injection')['exclude_reasons'],[])

    def test_other_categories_untouched(self):
        r=self.check('[RANDNUM]','Server Side Request Forgery')
        self.assertEqual(r['exclude_reasons'],[])
        self.assertEqual(r['transformed'],'[RANDNUM]')



class ProposalIntegrationTests(unittest.TestCase):
    @staticmethod
    def candidate(raw, i, category='SQL Injection'):
        return dict(category=category, source_file=category+'/README.md', source_kind='md',
                    block_index=0, line_index=i, block_level=False, raw=raw)

    def test_exclusions_precede_dedup_without_changing_default(self):
        from tests.test_v5_attack_pool import B
        cands=[self.candidate("' UNION SELECT [RANDNUM] --",i) for i in range(2)]
        baseline=B.process(cands,{})
        self.assertTrue(any(r['status']==B.C.ACCEPTED for r in baseline))
        proposed=B.process(cands,{},candidate_remediation=M.residue_proposal)
        self.assertTrue(all(r['status']==B.C.EXCLUDED for r in proposed))
        self.assertTrue(all(r['exclusion_reason'].startswith('candidate_remediation:') for r in proposed))
        self.assertEqual(B.process(cands,{}),baseline)

    def test_transform_recomputes_identity_before_dedup(self):
        from tests.test_v5_attack_pool import B
        cands=[self.candidate(s,i,'Server Side Template Injection') for i,s in enumerate(
            ['{{7*7}} // Boolean-Based RCE >=1.41, >=2.10, >=3.0','{{7*7}}'])]
        result=B.process(cands,{},candidate_remediation=M.residue_proposal)
        accepted=[r for r in result if r['status']==B.C.ACCEPTED]
        self.assertEqual(len(accepted),1)
        self.assertEqual(accepted[0]['payload_wire'],'{{7*7}}')
        self.assertEqual(accepted[0]['label_status'],B.C.LABEL_PENDING)
        self.assertEqual(B.I.family_key(result[0]['payload_wire']),B.I.family_key(result[1]['payload_wire']))
        self.assertEqual(result[0]['canonical_key'],result[1]['canonical_key'])

    def test_builder_isolated_reproducible_and_denied_sources_remain_excluded(self):
        from tests.test_v5_attack_pool import B, write_tree, write_denylist, STUB_GUARD
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp); patt=root/'patt'; deny=root/'deny.json'
            denied='SQL Injection/Intruder/denied.txt'
            fence=chr(96)*3
            write_tree(str(patt),{
                'XSS Injection/README.md':fence+'js\n<script>alert('+chr(96)+'x'+fence+')</script>\n'+fence+'\nUNWANTED PROSE\n'+fence+'html\n<img src=x onerror=alert(1)>\n'+fence+'\n',
                'Directory Traversal/README.md':fence+'\n../../etc/passwd\n'+fence+'\n',
                denied:"' OR 7=7 --\n"})
            write_denylist(str(deny),[denied])
            with patch.object(B,'check_patt',STUB_GUARD), patch.object(B,'DEFAULT_DENYLIST',str(deny)):
                first=M.build_candidate(root/'first',patt=patt)
                second=M.build_candidate(root/'second',patt=patt)
            self.assertEqual(first,second)
            self.assertFalse(first['training_eligible'])
            self.assertFalse(first['audit_outcomes_inherited'])
            self.assertFalse((root/'first/manifest.json').exists())
            rows=[json.loads(x) for x in (root/'first/candidate_pool.jsonl').read_bytes().splitlines()]
            excluded=[json.loads(x) for x in (root/'first/candidate_excluded.jsonl').read_bytes().splitlines()]
            self.assertTrue(all(r['source_file']!=denied and r['label_status']==B.C.LABEL_PENDING for r in rows))
            self.assertTrue(any(r['source_file']==denied and r['exclusion_reason']=='third_party_file' for r in excluded))
            self.assertTrue(all('UNWANTED PROSE' not in r['payload_raw'] for r in rows+excluded))
            original,_=B.extract_patt(str(patt))
            default=B.process(original+B.hardcoded_candidates(),{denied:{'reason':'fixture'}})
            nonfocus=lambda rs: [r for r in rs if r['category_v4'] not in M.FOCUS and r['status']==B.C.ACCEPTED]
            self.assertEqual(nonfocus(rows),nonfocus(default))
            for a in first['artifacts']:
                self.assertEqual((root/'first'/a['path']).read_bytes(),(root/'second'/a['path']).read_bytes())

class SourceUnitTests(unittest.TestCase):
    def block(self, body, info=''):
        fence=chr(96)*3
        return M.fenced_blocks(fence+info+'\n'+body+'\n'+fence+'\n')[0]

    def test_composite_template_quarantined_but_complete_line_list_retained(self):
        self.assertEqual(M.source_unit_proposal(self.block('{{\n x=1;\n y=x;\n}}')),
                         'multiline_enclosed_template')
        self.assertIsNone(M.source_unit_proposal(self.block('{{7*7}}\n{{8*8}}')))
        self.assertIsNone(M.source_unit_proposal(self.block('{{ single }}')))

    def test_explicit_program_and_document_enclosures(self):
        self.assertEqual(M.source_unit_proposal(self.block('<?php\n echo $x;\n?>')),'host_language_program')
        self.assertEqual(M.source_unit_proposal(self.block('<html>\n<body>test</body>\n</html>')),'multiline_markup_document')
        self.assertEqual(M.source_unit_proposal(self.block('<?xml version="1.0"?>\n<svg>\n</svg>')),'multiline_markup_document')
        self.assertIsNone(M.source_unit_proposal(self.block('<?php echo 1;?>\n<?php echo 2;?>')))

    def test_template_loop_and_unenclosed_cases(self):
        self.assertEqual(M.source_unit_proposal(self.block('{% for x in xs %}\n{{x}}\n{% endfor %}')),
                         'multiline_template_loop')
        self.assertIsNone(M.source_unit_proposal(self.block('one()\ntwo()')))
        self.assertIsNone(M.source_unit_proposal(self.block('{% for x in xs %}\nunclosed')))

    def test_quarantine_only_applies_in_proposal_mode(self):
        from tests.test_v5_attack_pool import B
        c=ProposalIntegrationTests.candidate("' OR 1=1 --",0)
        c['candidate_source_unit_quarantine']='synthetic-composite'
        self.assertEqual(B.process([c],{})[0]['status'],B.C.ACCEPTED)
        row=B.process([c],{},candidate_remediation=M.residue_proposal)[0]
        self.assertEqual(row['status'],B.C.EXCLUDED)
        self.assertEqual(row['exclusion_reason'],'candidate_source_unit:synthetic-composite')

    def test_builder_preserves_whole_quarantined_source_without_admitting_fragments(self):
        from tests.test_v5_attack_pool import B,write_tree,write_denylist,STUB_GUARD
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp);patt=root/'patt';deny=root/'deny.json'
            fence=chr(96)*3
            body='{{\n alert(1);\n}}\n'
            write_tree(str(patt),{'XSS Injection/README.md':fence+'javascript\n'+body+fence+'\n'})
            write_denylist(str(deny),[])
            with patch.object(B,'check_patt',STUB_GUARD),patch.object(B,'DEFAULT_DENYLIST',str(deny)):
                manifest=M.build_candidate(root/'out',patt=patt,quarantine_composite=True)
            blocks=[json.loads(x) for x in (root/'out/quarantined_source_blocks.jsonl').read_bytes().splitlines()]
            self.assertEqual(len(blocks),1)
            self.assertEqual(blocks[0]['body'],body)
            self.assertEqual(blocks[0]['block_sha256'],M.digest(body.encode()))
            self.assertFalse(blocks[0]['training_eligible'])
            self.assertIsNone(blocks[0]['audit_label'])
            self.assertEqual(manifest['quarantined_source_lines'],3)
            rows=[json.loads(x) for x in (root/'out/candidate_pool.jsonl').read_bytes().splitlines()]
            self.assertFalse(any(r['source_file']=='XSS Injection/README.md' for r in rows))


if __name__=='__main__': unittest.main()
