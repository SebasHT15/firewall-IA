"""PROPOSED source-remediation diagnostics and isolated unadjudicated pool.

Standalone fenced-block boundaries avoid treating inline backticks as Markdown
closers. Narrow negative document-residue rules are proposals, not attack labels.
The CLI compares the entire pinned existing pool, keeping every audit denominator.
--candidate additionally writes a distinctly PROPOSED pool, never a training build.
"""
from collections import Counter, defaultdict
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import sys

FOCUS = frozenset(('SQL Injection', 'XSS Injection', 'Command Injection',
                   'Server Side Template Injection'))
SCHEMA = 'v5-source-remediation/proposal-v1'
ROOT = Path(__file__).resolve().parents[2]
OPEN = re.compile(r'^( *)(`{3,}|~{3,})([^\r\n]*)\r?$')
PLACEHOLDER = re.compile(r'\[(?:RANDNUM\d*|RANDSTR\d*|SLEEPTIME|ATTACKER\.DOMAIN\.TLD)\]|<DBNAME>')
VERSION = r'(?:[<>]=?\s*\d+(?:\.\d+)*(?:,\s*[<>]=?\s*\d+(?:\.\d+)*)*)'
DOC_SUFFIX = re.compile(r'^(.*(?:\}\}|%\}|%>))\s+(?://|#)\s+'
                        r'(?:Error-Based|Boolean-Based) RCE(?:\s+' + VERSION +
                        r'|\s+with sandbox bypass using CVE-\d{4}-\d+)\s*$')


@dataclass(frozen=True)
class Fence:
    start: int       # body character offsets into exact decoded source
    end: int
    open_line: int
    close_line: int | None
    info: str
    body: str


def fenced_blocks(content):
    """Line-anchored backtick/tilde fences, including indented documentation lists.

    Not a full CommonMark/container parser. Indents >=4 must close at the same
    indentation; <=3 allow a <=3-space close. Unclosed bodies are recorded and
    quarantined, never silently emitted as payloads. Unicode LS/PS are not lines.
    """
    result, active, offset = [], None, 0
    lines = content.split('\n')
    for number, line in enumerate(lines, 1):
        clean = line.removesuffix('\r')
        m = OPEN.fullmatch(clean)
        if active:
            indent, marker, body_start, open_line, info = active
            closing = re.fullmatch(r'( *)([' + re.escape(marker[0]) + r']{' + str(len(marker)) + r',})[ \t]*', clean)
            if closing and (len(closing[1]) <= 3 if indent <= 3 else len(closing[1]) == indent):
                result.append(Fence(body_start, offset, open_line, number, info, content[body_start:offset]))
                active = None
        elif m:
            marker, info = m[2], m[3].strip()
            if marker[0] != '`' or '`' not in info:
                active = (len(m[1]), marker, offset + len(line) + (number < len(lines)), number, info)
        offset += len(line) + (number < len(lines))
    if active:
        _, _, body_start, open_line, info = active
        result.append(Fence(body_start, len(content), open_line, None, info, content[body_start:]))
    return tuple(result)


def legacy_span(content, block_index, line_index, block_level, fence_re):
    matches = list(fence_re.finditer(content))
    if type(block_index) is not int or not 0 <= block_index < len(matches):
        raise ValueError('legacy block index not reproducible')
    match = matches[block_index]
    if block_level:
        return match.start(1), match.end(1), match.group(1).strip()
    lines = match.group(1).splitlines(keepends=True)
    if type(line_index) is not int or not 0 <= line_index < len(lines):
        raise ValueError('legacy line index not reproducible')
    start = match.start(1) + sum(len(s) for s in lines[:line_index])
    raw = lines[line_index].splitlines()[0] if lines[line_index].splitlines() else ''
    return start, start + len(raw), raw


def source_unit_proposal(block):
    """Recognize explicit enclosing syntax, not attack validity or audit labels.

    A composite example is preserved for context review instead of admitting its
    component lines as independent payloads. Lists of complete one-line templates
    are retained. This conservative proposal does not parse every source language.
    """
    lines = [line.strip() for line in block.body.split('\n') if line.strip()]
    if len(lines) < 2:
        return None
    first, last = lines[0], lines[-1]
    if first == '<?php' and last == '?>':
        return 'host_language_program'
    if ((first.startswith('<?xml ') and last in ('</svg>', '</html>'))
            or (re.fullmatch(r'<html(?:\s[^>]*)?>', first, re.I) and last.lower() == '</html>')):
        return 'multiline_markup_document'
    if first.startswith('{{') and '}}' not in first and last.endswith('}}'):
        return 'multiline_enclosed_template'
    if re.fullmatch(r'{%[-+]?\s*for\b.*?[-+]?%}', first) and re.fullmatch(r'{%[-+]?\s*endfor\s*[-+]?%}', last):
        return 'multiline_template_loop'
    return None


def document_units(content, *, quarantine_composite=False):
    """Proposed line units with physical provenance; no eligibility or labels.

    Multi-line examples still need an explicit unit policy. This routine does not
    pretend that each line of a program is an independently usable payload.
    """
    result = []
    for index, block in enumerate(fenced_blocks(content)):
        if block.close_line is None:
            continue
        body_lines = block.body.split('\n')
        if body_lines and body_lines[-1] == '':
            body_lines.pop()
        for line_index, raw in enumerate(body_lines):
            result.append({'block_index': index, 'line_index': line_index,
                           'physical_line': block.open_line + line_index + 1,
                           'fence_info': block.info, 'multiline_source_block': len(body_lines) > 1,
                           'raw': raw.removesuffix('\r'),
                           'candidate_source_unit_quarantine': source_unit_proposal(block) if quarantine_composite else None})
    return result


def residue_proposal(payload, category, source_kind):
    """Pure candidate actions. No sample IDs, source filenames or labels consulted."""
    if category not in FOCUS:
        return {'exclude_reasons': [], 'review_reasons': [], 'transformed': payload, 'transform': None}
    reject, review, result, transform = [], [], payload, None
    if PLACEHOLDER.search(payload):
        reject.append('explicit_documentation_metavariable')
    if re.match(r'^(?:sqlite|mysql|psql)>\s', payload):
        reject.append('interactive_tool_prompt')
    if category == 'Command Injection' and re.fullmatch(r'[A-Za-z_][\w-]*:[^:\n]*:\d+:\d+:[^:\n]*:[^:\n]*:[^:\n]*', payload):
        reject.append('passwd_output_record')
    if source_kind == 'md':
        if re.fullmatch(r'\*\*[^*\n]+\*\*:', payload):
            reject.append('markdown_heading')
        if category in ('SQL Injection','Server Side Template Injection') and re.match(r'^(?:python\d*(?:\.\d+)*|sqlmap)(?:\s|$)', payload):
            reject.append('versioned_tool_invocation')
        if category == 'Server Side Template Injection':
            m = DOC_SUFFIX.fullmatch(payload)
            if m:
                result, transform = m[1], 'strip_versioned_documentation_suffix'
            # Context evidence only: a template language may legitimately use $.
            if re.match(r'^(?:foreach\s*\(|\$\w+\s*(?:=&|=|->))', payload):
                review.append('possible_host_language_source')
        if category == 'SQL Injection':
            # Narrow documentation-unit quarantine, not a SQL-validity judgement.
            # A literal LIMIT/OFFSET data_offset still needs substitution/context;
            # do not fabricate a concrete offset or admit it as a finished unit.
            # Remove complete SQL string literals before matching the token pair.
            sql_strings = r"'(?:''|[^'])*'|\"(?:\"\"|[^\"])*\""
            sql_tokens = re.sub(sql_strings, ' ', payload)
            # A leading quote may terminate the host expression. Retain both
            # lexical interpretations for quarantine; neither establishes attack truth.
            if payload.startswith("'"):
                sql_tokens += ' ' + re.sub(sql_strings, ' ', payload[1:])
            if re.search(r'\b(?:LIMIT|OFFSET)\s+data_offset\b', sql_tokens, re.I):
                reject.append('sql_pagination_metavariable_requires_context')
            elif re.search(r'\bdata_(?:offset|column|table|info)\b', payload):
                review.append('possible_implicit_documentation_metavariable')
    return {'exclude_reasons': reject, 'review_reasons': review, 'transformed': result, 'transform': transform}


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def diagnose(repo=ROOT, patt=Path('/home/sebas/PayloadsAllTheThings')):
    # Access only pinned public-source pool and its audit, never role datasets.
    sys.path.insert(0, str(repo/'scripts/dataset'))
    import build_v5_attack_pool as builder
    builder.check_patt(str(patt))
    audit = repo/'reports/v5/postfilter-audit'
    state = json.loads((audit/'round-1/audit_state.json').read_bytes())
    source_hashes = {}
    def captured(path, expected):
        raw = path.read_bytes()
        if digest(raw) != expected:
            raise ValueError(f'pinned source changed: {path.name}')
        source_hashes[str(path.relative_to(repo))] = digest(raw)
        return raw
    manifest = json.loads(captured(repo/'datasets/v5_sources/attack/manifest.json',state['pool_manifest_sha256']))
    pool = [json.loads(s) for s in captured(repo/state['pool']['path'],state['pool']['sha256']).split(b'\n') if s.strip()]
    sample = [json.loads(s) for s in captured(audit/'round-1/sample.jsonl',state['sample']['sha256']).split(b'\n') if s.strip()]
    report_root = audit/'r3-execution-2026-10-23'
    sealed = {l.split()[1]:l.split()[0] for l in (report_root/'SHA256SUMS').read_text().splitlines()}
    trace = [json.loads(s) for s in captured(report_root/'adjudication.jsonl',sealed['adjudication.jsonl']).split(b'\n') if s.strip()]
    by_sample = {r['sample_id']:r for r in sample}
    by_record = {by_sample[r['sample_id']]['record_id']:r for r in trace}
    cache, ledger = {}, []
    for row in pool:
        cat = row['category_v4']
        if cat not in FOCUS:
            continue
        proposal = residue_proposal(row['payload_wire'],cat,row['source_kind'])
        detail = {'record_id':row['record_id'],'category':cat,'source_file':row['source_file'],
                  'source_kind':row['source_kind'], 'payload_wire_sha256':digest(row['payload_wire'].encode()),
                  'exclude_reasons':list(proposal['exclude_reasons']), 'review_reasons':proposal['review_reasons'],
                  'transform':proposal['transform'], 'proposed_wire_sha256':digest(proposal['transformed'].encode())}
        if row['source_kind']=='md':
            rel = row['source_file']
            if rel not in cache:
                p = (patt/rel).resolve()
                if not p.is_relative_to(patt.resolve()):
                    raise ValueError('source path outside pinned PATT')
                raw = p.read_bytes()
                if digest(raw) != manifest['per_file'][rel]['sha256']:
                    raise ValueError('PATT source differs from pool manifest')
                content = raw.decode('utf-8') # Never ignore malformed encoding in new evidence.
                cache[rel] = (content,fenced_blocks(content),digest(raw))
            content,blocks,_ = cache[rel]
            start,end,raw = legacy_span(content,row['block_index'],row['line_index'],row['block_level'],builder.p4.FENCE_RE)
            if raw != row['payload_raw']:
                raise ValueError('legacy provenance mismatch')
            inside = [b for b in blocks if b.close_line is not None and b.start <= start and end <= b.end]
            detail['physical_line'] = content.count('\n',0,start)+1
            if not inside:
                detail['exclude_reasons'].insert(0,'outside_closed_standalone_fence')
            elif len(inside[0].body.strip().split('\n')) > 1:
                # Disclosure only. A multi-line fence may be a list of independent examples.
                detail['multiline_source_block'] = True
        detail['action'] = ('PROPOSED_EXCLUDE' if detail['exclude_reasons'] else 'PROPOSED_TRANSFORM'
                            if detail['transform'] else 'REVIEW_CONTEXT' if detail['review_reasons'] else 'UNCHANGED')
        label = by_record.get(row['record_id'])
        if label:
            detail['seen_audit_sample_id'] = label['sample_id']
            detail['seen_audit_label'] = label['adjudicated_label'] or 'UNRESOLVED'
        ledger.append(detail)
    # Also inventory new extraction units, including files with no accepted rows.
    # A candidate absent from the current pool is NOT automatically recovered truth.
    extraction = defaultdict(Counter)
    current_texts = {(r['source_file'],r['payload_wire']) for r in pool}
    for rel, info in sorted(manifest['per_file'].items()):
        cat = info['category']
        if cat not in FOCUS or info['kind'] != 'md' or info['third_party_denied']:
            continue
        p = (patt/rel).resolve()
        if not p.is_relative_to(patt.resolve()):
            raise ValueError('source path outside pinned PATT')
        if rel not in cache:
            raw = p.read_bytes()
            if digest(raw) != info['sha256']:
                raise ValueError('PATT source differs from pool manifest')
            content = raw.decode('utf-8')
            cache[rel] = (content,fenced_blocks(content),digest(raw))
        content = cache[rel][0]
        for unit in document_units(content):
            extraction[cat]['proposed_line_units'] += 1
            value, reason = builder.p4.quality_filter(unit['raw'],cat)
            if value is None:
                extraction[cat]['existing_quality_filter_rejections'] += 1
                continue
            extraction[cat]['quality_passing_units_not_yet_eligible'] += 1
            if (rel,value) not in current_texts:
                extraction[cat]['quality_passing_units_absent_from_current_pool_not_yet_eligible'] += 1
    cats = {}
    for cat in sorted(FOCUS):
        items = [r for r in ledger if r['category']==cat]
        cats[cat] = {'pool_rows':len(items), 'actions':dict(Counter(r['action'] for r in items)),
            'exclusion_reasons':dict(Counter(x for r in items for x in r['exclude_reasons'])),
            'review_reasons':dict(Counter(x for r in items for x in r['review_reasons'])),
            'seen_audit_cross_tab':dict(Counter(r.get('seen_audit_label','')+' / '+r['action'] for r in items if 'seen_audit_label' in r)),
            'source_files_before':len({r['source_file'] for r in items}),
            'source_files_after_proposed_exclusion':len({r['source_file'] for r in items if r['action']!='PROPOSED_EXCLUDE'})}
    result = {'schema':SCHEMA,'status':'PROPOSED_DIAGNOSTIC_ONLY','pool_rows':len(pool),'focused_rows':len(ledger),
        'categories':cats,'source_sha256':source_hashes,
        'proposed_extraction_inventory':{k:dict(v) for k,v in sorted(extraction.items())},
        'patt_source_sha256':{k:v[2] for k,v in sorted(cache.items())},
        'implementation_sha256':digest(Path(__file__).read_bytes()),
        'unclosed_fences':{k:[b.open_line for b in v[1] if b.close_line is None] for k,v in cache.items() if any(b.close_line is None for b in v[1])},
        'limitations':['Rules were designed after seeing round-1 labels; cross-tab is development evidence, not validation.',
            'No new pool, new labels, new audit or category acceptance produced.',
            'Only existing accepted rows compared; a future corrected extractor may discover additional candidates.',
            'Context review is not automatic exclusion or an admission label.',
            'No change to V4 extraction, active builder, approved filters, frozen audit or protected evaluations.']}
    return result, ledger


def build_candidate(out, repo=ROOT, patt=Path('/home/sebas/PayloadsAllTheThings'), *, quarantine_composite=False):
    """Isolated, unadjudicated proposal. No legacy manifest or label reuse."""
    sys.path.insert(0,str(repo/'scripts/dataset'))
    import build_v5_attack_pool as builder
    patt_info=builder.check_patt(str(patt))
    denied_doc,denied,deny_sha=builder.load_denylist(builder.DEFAULT_DENYLIST)
    candidates,files=builder.extract_patt(str(patt))
    replacement={}
    unclosed={}
    provenance=[]
    quarantined_blocks=[]
    for rel,info in sorted(files.items()):
        if info['category'] not in FOCUS or info['kind']!='md' or rel in denied:
            continue
        raw=(patt/rel).read_bytes()
        if digest(raw)!=info['sha256']:
            raise ValueError('source changed during candidate extraction')
        content=raw.decode('utf-8')
        blocks=fenced_blocks(content)
        if any(b.close_line is None for b in blocks):
            unclosed[rel]=[b.open_line for b in blocks if b.close_line is None]
        replacement[rel]=[]
        if quarantine_composite:
            for index, block in enumerate(blocks):
                reason = source_unit_proposal(block)
                if block.close_line is not None and reason:
                    quarantined_blocks.append({'source_file':rel,'source_sha256':info['sha256'],
                        'block_index':index,'open_line':block.open_line,'close_line':block.close_line,
                        'block_sha256':digest(block.body.encode()),'body':block.body,'reason':reason,
                        'status':'PENDING_UNIT_CONTEXT_REVIEW','training_eligible':False,'audit_label':None})
        for u in document_units(content,quarantine_composite=quarantine_composite):
            c={'category':info['category'],'source_file':rel,'source_kind':'md',
               'block_index':u['block_index'],'line_index':u['line_index'],'block_level':False,'raw':u['raw'],
               'candidate_source_unit_quarantine':u['candidate_source_unit_quarantine']}
            replacement[rel].append(c)
            provenance.append({'record_id':builder.make_record_id(c),'source_file':rel,
                'source_sha256':info['sha256'],'physical_line':u['physical_line'],
                'fence_info':u['fence_info'],'multiline_source_block':u['multiline_source_block']})
    replaced=[]
    emitted=set()
    for c in candidates:
        rel=c['source_file']
        if rel not in replacement:
            replaced.append(c)
        elif rel not in emitted:
            replaced.extend(replacement[rel]); emitted.add(rel)
    for rel in sorted(set(replacement)-emitted):
        replaced.extend(replacement[rel])
    replaced+=builder.hardcoded_candidates()
    recs=builder.process(replaced,denied,candidate_remediation=residue_proposal)
    if len({r['record_id'] for r in recs})!=len(recs):
        raise ValueError('candidate record ID collision')
    accepted=[r for r in recs if r['status']==builder.C.ACCEPTED]
    excluded=[r for r in recs if r['status']==builder.C.EXCLUDED]
    if len(accepted)+len(excluded)!=len(recs) or any(r['label_status']!=builder.C.LABEL_PENDING for r in accepted):
        raise ValueError('candidate label/partition invariant violated')
    artifacts=[]
    out.mkdir(exist_ok=False)
    for name,items in [('candidate_pool.jsonl',accepted),('candidate_excluded.jsonl',excluded),
                       ('source_locations.jsonl',provenance),('quarantined_source_blocks.jsonl',quarantined_blocks)]:
        raw=(''.join(json.dumps(r,ensure_ascii=False,sort_keys=True)+'\n' for r in items)).encode()
        (out/name).write_bytes(raw)
        artifacts.append({'path':name,'sha256':digest(raw),'rows':len(items),'bytes':len(raw)})
    result={'schema':'v5-remediation-candidate-pool/proposal-v1','status':'PROPOSED_UNADJUDICATED',
        'training_eligible':False,'audit_outcomes_inherited':False,'patt':patt_info,
        'composite_unit_quarantine':quarantine_composite,
        'quarantined_source_blocks':len(quarantined_blocks),
        'quarantined_source_lines':sum(r['exclusion_reason'].startswith('candidate_source_unit:') for r in excluded),
        'denylist_sha256':deny_sha,'denylist_status':denied_doc['status'],
        'artifacts':artifacts,'focus_categories':sorted(FOCUS),'unclosed_fences':unclosed,
        'accepted_counts':dict(Counter(r['category_v4'] for r in accepted)),
        'accepted_native_forms':dict(Counter(x for r in accepted for x in r['native_forms'])),
        'accepted_pending_context_review':sum(bool(r.get('candidate_review_reasons')) for r in accepted),
        'candidate_rule_exclusions':dict(Counter(r['exclusion_reason'] for r in excluded
                                               if r['exclusion_reason'].startswith('candidate_remediation:'))),
        'candidate_transform_count':sum(r['transform']=='strip_versioned_documentation_suffix' for r in recs),
        'source_sha256':{rel:info['sha256'] for rel,info in sorted(files.items())},
        'implementation_sha256':{name:digest((repo/name).read_bytes()) for name in
            ('scripts/dataset/v5_source_remediation.py','scripts/dataset/build_v5_attack_pool.py',
             'scripts/dataset/parse_dataset_v4.py','scripts/dataset/audit_v5_attack_pool.py')},
        'limitations':['Line units from multi-line code blocks may still be incomplete; context policy pending.',
            'No corrected-pool audit run; no category admission or training authorization.',
            'This proposal schema intentionally cannot be consumed as an approved V5 pool manifest.']}
    (out/'proposal_manifest.json').write_text(json.dumps(result,indent=2)+'\n')
    return result


if __name__ == '__main__':
    import argparse
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--out',type=Path,required=True,help='New directory for diagnostic artifacts only')
    ap.add_argument('--candidate',action='store_true',help='Also write an isolated PROPOSED unadjudicated pool')
    ap.add_argument('--source-units',action='store_true',help='With --candidate, quarantine explicit composite examples and preserve whole blocks')
    args=ap.parse_args()
    if args.source_units and not args.candidate: ap.error('--source-units requires --candidate')
    if args.out.exists(): ap.error('output exists; use a new directory')
    result,ledger=diagnose()
    args.out.mkdir(parents=True)
    (args.out/'diagnostic.json').write_text(json.dumps(result,ensure_ascii=False,indent=2)+'\n')
    (args.out/'ledger.jsonl').write_text(''.join(json.dumps(r,ensure_ascii=False)+'\n' for r in ledger))
    if args.candidate:
        build_candidate(args.out/'candidate',quarantine_composite=args.source_units)
    print(json.dumps(result['categories'],indent=2))
