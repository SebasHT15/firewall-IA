#!/usr/bin/env python3
"""H1 research-data hygiene checker. Never edits inputs or authorizes a freeze.

Unknown provenance and unparsed authorities fail closed. Controlled pool values are
resolved per occurrence through the row's value ids, leaf spans and hash-pinned
source records. Membership proves source attribution, not human validation.
"""
import sys
import argparse
import hashlib
import ipaddress
import json
from collections import Counter
from pathlib import Path
import re
import unicodedata
import urllib.parse

REPO = Path(__file__).resolve().parents[3]
MARKER_HOST = 'attacker.domain.tld'
MARKER_PAYLOAD_RECORD_ID = '2f894b44ea21f0b11b2cd155eda48beece5dac82f629cee6ea4920b4f478ae1d'
MARKER_PAYLOAD = '<base href=http://[ATTACKER.DOMAIN.TLD]>'
MARKER_RE = re.compile(r'<base[ +]+href=http://\[ATTACKER\.DOMAIN\.TLD\]>', re.I)
RESERVED = {'localhost', 'example', 'example.com', 'example.net', 'example.org'}
SUFFIXES = ('.test', '.example', '.invalid', '.localhost', '.example.com', '.example.net', '.example.org')
URL = re.compile(r'https?://([^\s/?#"\'<>\\`]+)', re.I)
RELATIVE_URL = re.compile(r'''(?:src|href)[ \t]*=[ \t]*["']?//([^\s/?#"'<>\\`]+)''',re.I)
HEADER = re.compile(r'(?im)^Host:[ \t]*([^\r\n]+)')
LABEL = re.compile(r'^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$')
EMAIL = re.compile(r'[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}')
JSON_VALUE = re.compile(r'"(?P<key>[^"\\]+)"\s*:\s*"(?P<val>(?:[^"\\]|\\.)*)"')
FORM_VALUE = re.compile(r'(?:[?&]|\n\n)(?P<key>[A-Za-z0-9_%-]+)=(?P<val>[^&\s]*)')
CRED_KEY = re.compile(r'^(?:passphrase|password|passwd|pwd|secret|token|api[_-]?key|apikey|auth|authorization|credential)(?:[_-].*)?$', re.I)
SECRET = re.compile(r'\b(?:AKIA[A-Z0-9]{16}|(?:sk_live_|sk_test_|ghp_|github_pat_)[A-Za-z0-9_]{16,}|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----')
VENDORS = {'google','youtube','amazon','aws','microsoft','azure','apple','facebook','meta','cloudflare','akamai','github','gitlab','oracle','ibm','cisco','paypal','stripe','openai','anthropic','slack','dropbox','netflix','twitter','alibaba','tencent'}
VENDOR = re.compile(r'\b(?:' + '|'.join(sorted(VENDORS)) + r')\b', re.I)
ATTACK_PATH = 'datasets/v5_sources/final_candidate/attack_pool.jsonl'
ATTACK_PIN = '4d43e0bf190e6b08b9fb0828ae20aa4c17f9eef849b149389a00abc035ae0c39'
DEFAULT_POOL_PINS = {
 'passwords': ('/home/sebas/Documents/Codex/2026-10-22/firewall-c1-model2-continuidad/work/pilot-integration-007/pools', '375f3d2b415ab5e78606d88b4b15371f02580d1d469aa0dc60bebaa643b56f09'),
 'symbols': ('datasets/v5_sources/benign','48474e3bf7adf868eea95f20337e406601624b1442bbc7c533f50f4fccf9bd0d'),
 'prose_en': ('datasets/v5_sources/benign','48474e3bf7adf868eea95f20337e406601624b1442bbc7c533f50f4fccf9bd0d'),
}

for _pool in ('addr_data','rel_paths','urls_public','urls_relative'):
    DEFAULT_POOL_PINS[_pool]=DEFAULT_POOL_PINS['passwords']
for _pool in ('names_given','names_family','streets'):
    DEFAULT_POOL_PINS[_pool]=DEFAULT_POOL_PINS['symbols']

def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def value_id(pool, value):
    return digest((pool + '\0' + unicodedata.normalize('NFC', value)).encode())


def load_provenance(pins):
    """Capture pinned manifests and every referenced pool actually used for exceptions."""
    records, evidence = {}, []
    for pool, (directory, expected) in sorted(pins.items()):
        root = Path(directory)
        if not root.is_absolute():
            root = REPO / root
        raw = (root/'manifest.json').read_bytes()
        if digest(raw) != expected:
            raise ValueError(f'pool manifest hash mismatch: {pool}')
        manifest = json.loads(raw)
        arts = [a for a in manifest['artifacts'] if Path(a['path']).name == pool+'.jsonl']
        if len(arts) != 1:
            raise ValueError(f'missing/ambiguous artifact: {pool}')
        art = arts[0]
        raw = (root/(pool+'.jsonl')).read_bytes()
        if digest(raw) != art['sha256'] or len(raw) != art['bytes']:
            raise ValueError(f'pool artifact hash/size mismatch: {pool}')
        for line in raw.splitlines():
            row = json.loads(line)
            if row.get('status') != 'ACCEPTED' or row.get('exclusion_reason') is not None:
                continue
            if row.get('pool_id') != pool or row.get('value_entry_id') != value_id(pool,row['value']):
                raise ValueError(f'pool value identity mismatch: {pool}')
            records[(pool,row['value_entry_id'])] = {
                'value':row['value'], 'pool':pool, 'value_entry_id':row['value_entry_id'],
                'source_ref':row.get('source_ref'), 'constructed':row.get('constructed',False),
                'manifest_sha256':expected, 'artifact_sha256':art['sha256'],
            }
        evidence.append({'pool':pool,'directory':str(root),'manifest_sha256':expected,
                         'artifact_sha256':art['sha256'],'bytes':len(raw)})
    return records, evidence


def reserved(host):
    return host in RESERVED or host.endswith(SUFFIXES)


def clean_authority(authority):
    """Return the complete DNS/IP host. Invalid input raises; it is never dropped."""
    a = authority.strip()
    if not a or re.search(r'[\s%<>"\'\\]',a):
        raise ValueError('invalid authority characters')
    if '@' in a:
        a = a.rsplit('@',1)[1]
    if a.startswith('['):
        match = re.fullmatch(r'\[([^\]]+)\](?::([0-9]+))?',a)
        if not match:
            raise ValueError('invalid bracketed authority')
        host, port = match.groups()
        if host.lower() != MARKER_HOST:
            ipaddress.IPv6Address(host)
    else:
        if a.count(':') > 1:
            raise ValueError('IPv6 requires brackets')
        host, sep, port = a.partition(':')
        if sep and not port.isdigit():
            raise ValueError('invalid port')
    if port and int(port) > 65535:
        raise ValueError('invalid port range')
    host = host.lower().rstrip('.')
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    try:
        host = host.encode('idna').decode('ascii')
    except UnicodeError as e:
        raise ValueError('invalid IDN') from e
    if len(host)>253 or not all(LABEL.fullmatch(p) for p in host.split('.')):
        raise ValueError('invalid DNS host')
    return host


def variants(text):
    out = [text]
    for _ in range(2):
        out.append(urllib.parse.unquote(out[-1]))
    return out


def proofs(text, meta, records, transform, attack_records=None):
    """Locate controlled values in the *actual* leaf spans, not just metadata names."""
    entries = {tuple(e) for e in meta.get('value_entries',[]) if isinstance(e,list) and len(e)==2}
    vals = set(meta.get('values',[]))
    out=[]
    for start,end in meta.get('leaf_spans',{}).values():
        if not (isinstance(start,int) and isinstance(end,int) and 0<=start<=end<=len(text)):
            continue
        raw_leaf = text[start:end]
        leaf = transform(raw_leaf)
        decoded = {leaf,urllib.parse.unquote_plus(leaf)}
        try:
            val=json.loads(leaf)
            if isinstance(val,str):decoded.add(val)
        except (ValueError,TypeError):
            pass
        try:
            decoded.add(json.loads('"'+leaf+'"'))
        except (ValueError,TypeError):
            pass
        for key in entries:
            rec=records.get(key)
            if rec and rec['value'] in vals and rec['value'] in decoded:
                out.append((len(transform(text[:start])),len(transform(text[:end])),rec))
    if attack_records and meta.get('label')=='BLOCK':
        rec=attack_records.get(meta.get('payload_record_id'))
        span=meta.get('leaf_spans',{}).get(meta.get('attacked_slot'))
        if rec and span and meta.get('attack_category')==rec.get('dedup_scope'):
            start,end=span
            if 0<=start<=end<=len(text):
                leaf=transform(text[start:end]); leaves={leaf,urllib.parse.unquote_plus(leaf)}
                try:
                    x=json.loads(leaf)
                    if isinstance(x,str):leaves.add(x)
                except ValueError:pass
                benign={records[k]['value'] for k in entries if k in records and records[k]['value'] in vals}
                for payload in {rec.get('payload_logical',''),rec.get('payload_wire','')}:
                    payload=transform(payload)
                    if not payload:continue
                    if any(v==payload or (payload in v and v.replace(payload,'',1) in benign) for v in leaves):
                        proof={'pool':'attack_payload','value_entry_id':rec['record_id'],
                               'source_ref':rec.get('source_file'), 'artifact_sha256':rec.get('_h1_source_sha256',ATTACK_PIN),
                               'classification':'audited attack syntax in the attacked leaf; not a benign secret'}
                        out.append((len(transform(text[:start])),len(transform(text[:end])),proof));break
    return out


def justification(start,end,span_proofs,kind):
    for a,b,rec in span_proofs:
        if a<=start and end<=b:
            # Only generated/synthetic value pools can excuse email/credential-like strings.
            # Public CC0 prose can explain an ordinary word such as "apple", not an identity.
            if kind=='email' and (rec['pool'] not in ('passwords','symbols') or EMAIL.fullmatch(rec['value'])):
                continue
            if kind=='vendor' and rec['pool']!='prose_en':
                continue
            return {k:v for k,v in rec.items() if k!='value'}
    return None


def scalar_provenance(dataset):
    """Replay only pre-render scalar RNG draws; never build/render/rewrite a dataset."""
    sys.path.insert(0,str(REPO/'scripts/dataset'))
    import v5_generator as G
    manifest=json.loads((dataset/'manifest.json').read_text())
    art=next(a for a in manifest['artifacts'] if a['path']=='assignment/assignment.jsonl')
    raw=(dataset/art['path']).read_bytes()
    if digest(raw)!=art['sha256']:raise ValueError('scalar assignment hash mismatch')
    catalog=G.K.load_catalog()
    if catalog.sha256!=manifest['catalog']['sha256'] or catalog.lexicon_sha256!=manifest['catalog']['lexicon_sha256']:
        raise ValueError('scalar catalog hash mismatch')
    assignment=[json.loads(l) for l in raw.splitlines()]
    counts=Counter((r['split'],r['pool']) for r in assignment if r['kind']=='value_entry')
    templates={}
    for r in assignment:
        if r['kind']=='template':templates.setdefault((r['split'],r['cluster']),[]).append(catalog.by_id[r['id']])
    traced={};cache={}
    for split in ('TRAIN','VALIDATION','INTERNAL_TEST'):
        for n,l in enumerate((dataset/f'rows.{split}.meta.jsonl').read_text().splitlines(),1):
            m=json.loads(l); key=(split,m['struct_cluster_id'],m['quota'],m['attempt'])
            if key not in cache:
                category=m.get('attack_category') or m.get('twin_category')
                tpls=sorted((t for t in templates[(split,m['struct_cluster_id'])] if any(category in slot.compatible_categories for slot in t.attack_slots)),key=lambda t:t.template_id)
                rng=G.I.row_rng(*key);t=G._choice(rng,tpls);G._choice(rng,G.R.PROFILES);G.draw_names(t,catalog.lexicon,rng)
                scalars={}
                for slot in t.slots:
                    if slot.attackable:
                        pools=[p for p in slot.pools if counts[(split,p)]]
                        pool=G._choice(rng,pools);rng.randrange(counts[(split,pool)])
                    else:
                        leaf=G.draw_scalar(slot,rng)
                        if slot.value_type=='token':scalars[slot.slot_id]=leaf.logical
                cache[key]=(t.template_id,scalars)
            tid,scalars=cache[key]
            if tid!=m['template_id']:raise ValueError('scalar template/RNG mismatch')
            traced[(split,n)]=scalars
    return traced,{'generator_sha256':digest((REPO/'scripts/dataset/v5_generator.py').read_bytes()),
                  'catalog_sha256':catalog.sha256,'lexicon_sha256':catalog.lexicon_sha256,
                  'assignment_sha256':art['sha256'],'method':'exact scalar RNG replay only; no dataset regeneration'}


def scan(dataset, *, pool_pins=None):
    dataset=Path(dataset)
    attack_records={}
    attack_pin=None
    if pool_pins is None:
        manifest_inputs=json.loads((dataset/'manifest.json').read_text())
        source=manifest_inputs['pilot_inputs']['attack_source']
        attack_path=Path(source['path'])
        if not attack_path.is_absolute():attack_path=REPO/attack_path
        attack_pin=source['sha256']
        if attack_pin!=manifest_inputs['attack_pool_sha256']:raise ValueError('attack source/manifest binding mismatch')
        attack_raw=attack_path.read_bytes()
        if digest(attack_raw)!=attack_pin:raise ValueError('attack pool hash mismatch')
        attack_records={r['record_id']:{**r,'_h1_source_sha256':attack_pin} for r in map(json.loads,attack_raw.splitlines())}
        input_pins={k:(v['dir'],v['manifest_sha256']) for k,v in manifest_inputs['pilot_inputs']['pool_provenance'].items()}
    else:input_pins=pool_pins
    records,evidence=load_provenance(input_pins)
    scalar_values,scalar_evidence=scalar_provenance(dataset) if pool_pins is None else ({},None)
    controls={k:{'candidates':[],'confirmed':[],'unresolved':[]} for k in ('host_identity','email','credential','vendor')}
    errors=[];marker_hits=[];seen=set();rows=0;distinct=set()
    manifest=dataset/'manifest.json'
    captured=[]
    for split in ('TRAIN','VALIDATION','INTERNAL_TEST'):
        rp=dataset/f'rows.{split}.jsonl';mp=dataset/f'rows.{split}.meta.jsonl'
        rb,mb=rp.read_bytes(),mp.read_bytes()
        captured.extend([{'path':str(rp),'sha256':digest(rb)}, {'path':str(mp),'sha256':digest(mb)}])
        rs,ms=rb.splitlines(),mb.splitlines()
        if len(rs)!=len(ms):
            errors.append({'split':split,'error':'row/meta count mismatch'});continue
        for i,(rl,ml) in enumerate(zip(rs,ms),1):
            row,meta=json.loads(rl),json.loads(ml);text=row.get('text')
            if not isinstance(text,str) or not text:
                errors.append({'split':split,'line':i,'error':'missing text'});continue
            rows+=1;where=f'{split}:line {i}'
            if meta.get('text_sha256') and meta['text_sha256']!=digest(text.encode()):
                errors.append({'where':where,'error':'row/meta text hash mismatch'});continue
            for level,s in enumerate(variants(text)):
                transform=lambda x,n=level: variants(x)[n]
                ps=proofs(text,meta,records,transform,attack_records)
                for slot,val in scalar_values.get((split,i),{}).items():
                    a,b=meta['leaf_spans'][slot]
                    try:actual=json.loads(text[a:b])
                    except ValueError:actual=text[a:b]
                    if actual!=val:raise ValueError('scalar value differs from deterministic source')
                    ps.append((len(transform(text[:a])),len(transform(text[:b])),
                       {'pool':'generated_scalar','source_ref':'draw_scalar(token): exact RNG replay',
                        'value_entry_id':digest(val.encode()),**scalar_evidence}))
                markers=list(MARKER_RE.finditer(s)) if (meta.get('label')=='BLOCK' and meta.get('attack_category')=='XSS Injection' and meta.get('payload_record_id')==MARKER_PAYLOAD_RECORD_ID) else []
                def add(kind,match,value,extra=None,force=False,span=None):
                    start,end = span or match.span()
                    key=(where,kind,value,start,end)
                    # Same decoded occurrence may move; keep exact diagnostics, don't aggregate raw variants into claims.
                    if key in seen:return
                    seen.add(key)
                    item={'where':where,'value_sha256':digest(value.encode()),'kind':kind,**(extra or {})}
                    proof=None if force else justification(start,end,ps,kind)
                    item['provenance']=proof
                    controls[kind]['candidates'].append(item)
                    if proof:return
                    controls[kind]['confirmed' if force or kind in ('host_identity','email','vendor') else 'unresolved'].append(item)
                for rx in (URL,HEADER,RELATIVE_URL):
                    for m in rx.finditer(s):
                        # Encoded syntax is checked in decoded variants. Raw percent bytes are not a host.
                        if '%' in m.group(1):
                            if level==2:controls['host_identity']['unresolved'].append({'where':where,'reason':'authority still encoded after two decoding passes'})
                            continue
                        try:h=clean_authority(m.group(1))
                        except ValueError:
                            controls['host_identity']['unresolved'].append({'where':where,'authority_sha256':digest(m.group(1).encode()),'reason':'unparsed authority'});continue
                        distinct.add(h)
                        if h==MARKER_HOST and any(a.start()<=m.start() and m.end()<=a.end() for a in markers):
                            marker_hits.append(where);continue
                        if not reserved(h):add('host_identity',m,h,{'host':h},force=True)
                        if any(p in VENDORS for p in h.split('.')):add('vendor',m,h,{'host':h},force=True)
                for m in EMAIL.finditer(s):
                    add('email',m,m.group(),{'prefix_candidate':bool(s[m.end():m.end()+1] and s[m.end():m.end()+1] not in ' \"\'<>&,)}]\n\r\t')})
                for rx in (JSON_VALUE,FORM_VALUE):
                    for m in rx.finditer(s):
                        if not CRED_KEY.fullmatch(urllib.parse.unquote(m.group('key'))):continue
                        add('credential',m,m.group('val'),{'field':m.group('key')},span=m.span('val'))
                for m in SECRET.finditer(s):add('credential',m,m.group(),{'detector':'secret-format'},force=True)
                for m in VENDOR.finditer(s):
                    if re.match(r'"\s*:',s[m.end():]):
                        continue  # A JSON key named meta is syntax, not a company identity.
                    # Host/domain brands were already counted above; text occurrences still require attribution.
                    add('vendor',m,m.group().lower(),{'word':m.group()})
    for c in controls.values():
        for key in ('candidates','confirmed','unresolved'):
            # Identical captured diagnostics across decode variants count once.
            c[key]=list({json.dumps(x,sort_keys=True):x for x in c[key]}.values())
        c['pass']=not c['confirmed'] and not c['unresolved']
    result={'schema':'v5-H1-identity-secrets/v4-codex','control':'H1 (C §4.6)',
      'dataset_manifest_sha256':digest(manifest.read_bytes()) if manifest.exists() else None,
      'checker_sha256':digest(Path(__file__).read_bytes()),'rows_scanned':rows,'input_captures':captured,
      'provenance_sources':evidence,'attack_pool_sha256':attack_pin,'scalar_provenance':scalar_evidence,'errors':errors,'distinct_hosts':sorted(distinct),
      'documented_marker':{'literal':MARKER_PAYLOAD,'record_id':MARKER_PAYLOAD_RECORD_ID,'scope':'per exact occurrence + XSS/BLOCK metadata','hits':sorted(set(marker_hits))},
      'subcontrols':controls,'H1_pass_on_v3':not errors and all(c['pass'] for c in controls.values()),
      'accredited_committed_checker':False,'owner_authorization':False,
      'limitations':['Pattern scan, not a proof that every possible secret format is detectable.',
                      'Controlled source membership is not independent human validation.',
                      'The documented marker disposition does not authorize freeze or training.']}
    return result


def main():
    p=argparse.ArgumentParser();p.add_argument('dataset');p.add_argument('output');a=p.parse_args()
    try:
        result=scan(a.dataset)
    except (OSError,ValueError,KeyError,TypeError) as e:
        result={'schema':'v5-H1-identity-secrets/v4-codex','H1_pass_on_v3':False,'errors':[str(e)]}
    Path(a.output).write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print(json.dumps({k:result.get(k) for k in ('H1_pass_on_v3','rows_scanned','errors')}))
    return 0 if result['H1_pass_on_v3'] else 1


if __name__=='__main__':
    raise SystemExit(main())
