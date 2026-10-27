#!/usr/bin/env python3
"""Prepare contextual source v2; no admission, audit sampling or training.

Project-authored units have explicit construction lineage and sink assumptions.
PATT documents are inventoried intact for later curation, never split into attack
rows. Neither lane is an approved attack pool. Context remains metadata only.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re

import v5_identities as I
import v5_pools_common as C
import v5_source_remediation as M

ROOT = Path(C.REPO_ROOT)
SCHEMA = 'v5-contextual-source-package/proposal-v2'
UNIT_SCHEMA = 'v5-contextual-source-unit/proposal-v2'
PACKAGE_STATUS = 'PROPOSED_NOT_ADMITTED'
FAMILIES = ('sql_injection', 'xss', 'command_injection', 'ssti', 'path_traversal', 'file_inclusion')
SOURCE_FAMILIES = {'SQL Injection':'sql_injection', 'XSS Injection':'xss',
                   'Command Injection':'command_injection', 'Server Side Template Injection':'ssti',
                   'Directory Traversal':'path_traversal', 'File Inclusion':'file_inclusion'}
ARTIFACTS = {'source_units.jsonl', 'context_profiles.json', 'patt_document_inventory.jsonl', 'diversity.json'}


def encoded(obj):
    return (json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(',', ':'))+'\n').encode('utf-8')


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def capture(path, expected=None):
    path = Path(path)
    C.assert_not_protected(str(path))
    raw = path.read_bytes()
    if expected is not None and digest(raw) != expected:
        raise ValueError(f'source integrity mismatch: {path.name}')
    return raw


def profile(pid, category, kind, sink, control, mechanism, observation, assumptions):
    return {'profile_id':pid, 'category_key':category, 'context_kind':kind,
            'sink_template':sink, 'benign_control_template':control, 'mechanism':mechanism,
            'expected_observation':observation, 'assumptions':assumptions,
            'validation_scope':'Proposed local context only; no execution or qualification performed',
            'allowed_request_slot_types':['path_file'] if category in ('path_traversal','file_inclusion') else ['free_string','json_leaf'],
            'metadata_only':True, 'training_eligible':False}


def profiles():
    """Contexts describe vulnerable application sinks, not HTTP request templates."""
    result = []
    for name,kind in [('quoted-or','sqlite_quoted_value'),('numeric-or','sqlite_numeric_expression'),('quoted-union','sqlite_quoted_value')]:
        sql_profile=profile('sql.'+name,'sql_injection',kind,
            "SELECT secret FROM t WHERE name = '{INPUT}'" if kind=='sqlite_quoted_value' else 'SELECT secret FROM t WHERE id = {INPUT}',
            'SELECT secret FROM t WHERE name = ?' if kind=='sqlite_quoted_value' else 'SELECT secret FROM t WHERE id = ?',
            'SQL string termination and injected predicate/set operator' if kind=='sqlite_quoted_value' else 'Injected SQL boolean operator',
            'Changed result set in an in-memory fixture; parameterized reference treats the input as data',
            ['SQLite grammar; single-quoted strings; t(id,name,secret) is synthetic',
             'Input is concatenated unsafely; parameterized input does not share that assumption'])
        sql_profile['benign_input']='alpha' if kind=='sqlite_quoted_value' else '1'
        result.append(sql_profile)
    for name in ('script','img-event','svg-event'):
        result.append(profile('xss.'+name,'xss','html_fragment','<section>{INPUT}</section>','plain text',
            'HTML markup introduces an active script or event handler',
            'Parser structure can be inspected; JavaScript execution would require a separate browser check',
            ['HTML text sink without escaping; inline JavaScript permitted by the hypothetical CSP',
             'An HTML parser alone cannot prove event firing, browser behavior or exploitation']))
    for name in ('separator','dollar-substitution','backtick-substitution'):
        result.append(profile('shell.'+name,'command_injection','posix_shell_unquoted_argument',
            "printf '%s' {INPUT}",'fixture','Shell metacharacters introduce a second printf evaluation',
            'A local shell model would distinguish an extra command/substitution from a literal argument',
            ['POSIX shell, unquoted concatenation, printf available',
             'No shell is executed during preparation; PHP/template expressions are not shell payloads']))
    for name in ('multiply','add','subtract'):
        result.append(profile('jinja.'+name,'ssti','jinja2_template_source','{INPUT}','plain text',
            'User input becomes template source and introduces a literal arithmetic expression',
            'A synthetic arithmetic/string probe would render a computed value; a data-only reference preserves the literal',
            ['Jinja2 source evaluation; values are literal arithmetic/strings, no objects or attributes',
             'Probe covers expression evaluation, not RCE or a particular production application']))
    result.append(profile('path.posix-parent','path_traversal','posix_file_path','/lab/public/{INPUT}','readme.txt',
        'Parent traversal escapes the designated POSIX public directory', 'Normalized synthetic path lies outside /lab/public',
        ['POSIX path semantics; input is joined unsafely; no filesystem access or existence claim']))
    result.append(profile('path.windows-parent','path_traversal','windows_file_path',r'C:\lab\public\{INPUT}','readme.txt',
        'Parent traversal escapes the designated Windows public directory', r'Normalized synthetic path lies outside C:\lab\public',
        ['Windows path semantics; input is joined unsafely; no filesystem access or existence claim']))
    result.append(profile('include.relative-local','file_inclusion','php_local_include',
        "include('/lab/public/' . '{INPUT}');",'index.php','A local include operand traverses outside the allowed tree',
        'An isolated PHP fixture would include a controlled marker file outside the public tree',
        ['Unescaped user input reaches PHP include; relative path is joined to /lab/public',
         'Marker files are hypothetical; no PHP interpreter or file read is run']))
    result.append(profile('include.absolute-local','file_inclusion','php_local_include',
        "include('{INPUT}');",'index.php','An unrestricted include operand selects an absolute local file',
        'An isolated PHP fixture would include a controlled marker file outside the public tree',
        ['PHP include accepts the local absolute path; no application allowlist or containment check',
         'Marker files are hypothetical; no PHP interpreter or file read is run']))
    return sorted(result,key=lambda p:p['profile_id'])


def payload_for(profile_id, n):
    if type(n) is not int or not 1 <= n <= 64:
        raise ValueError('construction parameter n must be an integer in [1,64]')
    token=f'probe{n}'
    values={
        'sql.quoted-or':f"missing' OR '{n}'='{n}",
        'sql.numeric-or':f'0 OR {n}={n}',
        'sql.quoted-union':f"missing' UNION SELECT '{token}",
        'xss.script':f'<script>alert({n})</script>',
        'xss.img-event':f'<img src=x onerror=alert({n})>',
        'xss.svg-event':f'<svg onload=confirm({n})></svg>',
        'shell.separator':f"fixture; printf '%s' {token}",
        'shell.dollar-substitution':f"$(printf '%s' {token})",
        'shell.backtick-substitution':f"`printf '%s' {token}`",
        'jinja.multiply':f'{{{{{n}*{n+1}}}}}',
        'jinja.add':f'{{{{{n}+{n+1}}}}}',
        'jinja.subtract':f'{{{{{n+1}-{n}}}}}',
        'path.posix-parent':f'../private/marker{n}.txt',
        'path.windows-parent':f'..\\private\\marker{n}.txt',
        'include.relative-local':f'../private/marker{n}.php',
        'include.absolute-local':f'/lab/private/marker{n}.php',
    }
    if profile_id not in values:raise ValueError('unknown construction profile')
    return values[profile_id]


def authored_units(variants):
    if type(variants) is not int or not 1 <= variants <= 64:
        raise ValueError('variants must be an integer in [1,64]')
    units=[]
    for p in profiles():
        pid=p['profile_id']
        for n in range(1,variants+1):
            wire=payload_for(pid,n)
            construction=digest(encoded({'profile_id':pid,'version':SCHEMA}))
            units.append({'schema':UNIT_SCHEMA,'record_id':digest(encoded([SCHEMA,pid,n,wire])),
                'payload_wire':wire,'category_key':p['category_key'],'profile_id':pid,
                'parameters':{'n':n},'construction_family_id':construction,
                'source_origin':'project_authored_context_grammar','license':'MIT (project LICENSE)',
                'label_status':'PENDING_ADJUDICATION','audit_label':None,'training_eligible':False,
                'context_is_metadata_only':True,'prior_audit_outcomes_inherited':False})
    return sorted(units,key=lambda r:r['record_id'])


def source_heading_index(text, blocks):
    stack=[];result={}
    openers={b.open_line for b in blocks}
    covered=set()
    physical_lines=text.split('\n')
    for block in blocks:
        covered.update(range(block.open_line,(block.close_line or len(physical_lines))+1))
    for number,value in enumerate(physical_lines,1):
        if number in openers:result[number]=[dict(h) for h in stack]
        if number in covered:continue
        match=re.match(r'^(#{1,6})\s+(.+?)\s*$',value.removesuffix('\r'))
        if match:
            level=len(match[1]);stack=[h for h in stack if h['level']<level]
            stack.append({'level':level,'line':number,'text':match[2]})
    return result


def inventory_patt(patt, baseline_path, baseline_sha):
    """Complete source units only. No wordlist line becomes an attack record."""
    import build_v5_attack_pool as B
    patt=Path(patt).resolve()
    C.assert_not_protected(str(patt))
    info=B.check_patt(str(patt))
    manifest_raw=capture(baseline_path,baseline_sha);manifest=json.loads(manifest_raw)
    if manifest['patt']['commit']!=info['commit']:raise ValueError('baseline PATT pin differs')
    deny_path=ROOT/'scripts/dataset/v5_lexicon/patt_third_party_denylist_v2.json'
    deny_raw=capture(deny_path,manifest['denylist']['sha256']);deny=json.loads(deny_raw)
    if deny['status']!='APPROVED':raise ValueError('approved denylist required')
    denied={r['path'] for r in deny['denied']};units=[];source_hashes={};denied_files=[]
    for rel,f in sorted(manifest['per_file'].items()):
        if f['category'] not in SOURCE_FAMILIES:continue
        if rel in denied:
            denied_files.append(rel);continue
        path=(patt/rel).resolve()
        if not path.is_relative_to(patt):raise ValueError('source path escapes pinned PATT')
        raw=capture(path,f['sha256']);text=raw.decode('utf-8');source_hashes[rel]=digest(raw)
        blocks=M.fenced_blocks(text) if f['kind']=='md' else ()
        heading_index=source_heading_index(text,blocks)
        spans=[(b.start,b.end,b.open_line+1,b.close_line-1 if b.close_line else None,
                'CLOSED_FENCED_DOCUMENT' if b.close_line else 'UNTERMINATED_FENCED_DOCUMENT',b.info,b) for b in blocks]
        if f['kind']=='txt':spans=[(0,len(text),1,len(text.split('\n')),'WHOLE_WORDLIST_DOCUMENT','',None)]
        for start,end,first,last,kind,language,block in spans:
            body=text[start:end]
            units.append({'source_unit_id':digest(encoded([rel,digest(raw),start,end])),
                'source_file':rel,'source_sha256':digest(raw),'source_category_hint':f['category'],
                'source_unit_kind':kind,'start_line':first,'end_line':last,
                'utf8_byte_start':len(text[:start].encode()),'utf8_byte_end':len(text[:end].encode()),
                'fence_info':language,'headings':heading_index[block.open_line] if block else [],
                'source_body':body,'source_body_sha256':digest(body.encode()),
                'context_status':'PENDING_EXPLICIT_UNIT_CURATION','category_hint_is_not_label':True,
                'audit_label':None,'training_eligible':False})
    return units,{'patt':info,'baseline_manifest_sha256':digest(manifest_raw),'denylist_sha256':digest(deny_raw),
                  'denied_files_not_read':denied_files,'source_file_sha256':source_hashes,
                  'inventory_role':'Whole documents for curation; no payload pool or category admission'}


def diversity(units):
    result={}
    for category in FAMILIES:
        items=[r for r in units if r['category_key']==category]
        result[category]={'literal_units':len(items),'literal_payloads':len({r['payload_wire'] for r in items}),
                         'frozen_family_keys':len({I.family_key(r['payload_wire']) for r in items}),
                         'construction_lineages':len({r['construction_family_id'] for r in items})}
    return {'categories':result,'source_providers':1,'split_assigned':False,
            'd60_evaluability_established':False,
            'limitations':['Variants of one grammar are not independent families.',
                           'Frozen family keys are a diagnostic; ancestry grouping must also prevent cross-split grammar leakage.',
                           'No claim about unseen providers, production traffic or operational error rates.',
                           'No protected evaluation or prior audit sample was consumed.']}


def prepare(out, *, variants=16, patt=None, baseline_path=None, baseline_sha=None):
    out=Path(out);C.assert_not_protected(str(out))
    if out.exists():raise ValueError('output exists; source versions are never overwritten')
    units=authored_units(variants);context=profiles();inventory=[];source={'inventory_prepared':False}
    if patt is not None:
        if not baseline_path or not baseline_sha:raise ValueError('pinned baseline required for PATT inventory')
        inventory,source=inventory_patt(patt,baseline_path,baseline_sha)
        source['inventory_prepared']=True
    payloads={'source_units.jsonl':b''.join(encoded(r) for r in units),
              'context_profiles.json':encoded(context),
              'patt_document_inventory.jsonl':b''.join(encoded(r) for r in inventory),
              'diversity.json':encoded(diversity(units))}
    manifest={'schema':SCHEMA,'status':PACKAGE_STATUS,'training_eligible':False,
              'audit_executed':False,'sample_drawn':False,'audit_outcomes_inherited':False,
              'category_outcomes':{},'variants_per_construction':variants,
              'owner_scope':'Prepare sources and validation proposal only; no audit or training authorization',
              'source':source,'authored_unit_counts':dict(sorted(Counter(r['category_key'] for r in units).items())),
              'context_profiles':len(context),'document_inventory_units':len(inventory),
              'implementation_sha256':{name:digest(capture(ROOT/name)) for name in
                  ('scripts/dataset/v5_contextual_source_package.py','scripts/dataset/v5_source_remediation.py',
                   'scripts/dataset/v5_identities.py','scripts/dataset/parse_dataset_v4.py')},
              'artifacts':[{'path':name,'sha256':digest(raw),'bytes':len(raw)} for name,raw in sorted(payloads.items())]}
    out.mkdir(parents=True)
    for name,raw in payloads.items():(out/name).write_bytes(raw)
    (out/'manifest.json').write_bytes(encoded(manifest))
    return manifest


def verify(out):
    out=Path(out).resolve();manifest=json.loads(capture(out/'manifest.json'))
    if (manifest.get('schema')!=SCHEMA or manifest.get('status')!=PACKAGE_STATUS
            or any(manifest.get(k) is not False for k in ('training_eligible','audit_executed','sample_drawn','audit_outcomes_inherited'))
            or manifest.get('category_outcomes')!={}):raise ValueError('package must remain unadmitted and unaudited')
    descriptors=manifest['artifacts']
    if len(descriptors)!=len(ARTIFACTS) or {a['path'] for a in descriptors}!=ARTIFACTS:raise ValueError('invalid artifact set')
    contents={}
    for a in descriptors:
        path=(out/a['path']).resolve()
        if not path.is_relative_to(out):raise ValueError('artifact escapes package')
        raw=capture(path,a['sha256'])
        if len(raw)!=a['bytes']:raise ValueError('artifact byte count mismatch')
        contents[a['path']]=raw
    for name,sha in manifest['implementation_sha256'].items():
        path=(ROOT/name).resolve()
        if not path.is_relative_to(ROOT):raise ValueError('implementation path escapes repository')
        capture(path,sha)
    if contents['source_units.jsonl']!=b''.join(encoded(r) for r in authored_units(manifest['variants_per_construction'])):
        raise ValueError('units differ from construction or contain changed labels/context')
    if contents['context_profiles.json']!=encoded(profiles()):raise ValueError('context profiles changed')
    items=authored_units(manifest['variants_per_construction'])
    if contents['diversity.json']!=encoded(diversity(items)):raise ValueError('diversity report mismatch')
    inventory=[json.loads(line) for line in contents['patt_document_inventory.jsonl'].split(b'\n') if line.strip()]
    if len(inventory)!=manifest['document_inventory_units']:raise ValueError('inventory count mismatch')
    for item in inventory:
        if (item.get('training_eligible') is not False or item.get('audit_label') is not None
                or digest(item['source_body'].encode())!=item['source_body_sha256']):raise ValueError('inventory state/body mismatch')
    if len({r['record_id'] for r in items})!=len(items):raise ValueError('duplicate unit identity')
    return {'status':'PREPARATION_INTEGRITY_OK','units':len(items),'context_profiles':len(profiles()),
            'inventory_units':len(inventory),'training_eligible':False,'audit_executed':False}


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    sub=ap.add_subparsers(dest='command',required=True)
    build=sub.add_parser('prepare');build.add_argument('--out',required=True,type=Path)
    build.add_argument('--variants',type=int,default=16)
    build.add_argument('--patt',type=Path);build.add_argument('--baseline-manifest',type=Path)
    build.add_argument('--baseline-sha256')
    check=sub.add_parser('verify');check.add_argument('--out',required=True,type=Path)
    args=ap.parse_args()
    if args.command=='prepare':
        prepare(args.out,variants=args.variants,patt=args.patt,baseline_path=args.baseline_manifest,baseline_sha=args.baseline_sha256)
    print(json.dumps(verify(args.out),indent=2))


if __name__=='__main__':main()
