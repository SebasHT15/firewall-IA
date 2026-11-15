"""Verify AI audit outcomes against pinned report, sampling state and source pool.

No labels/authority are inferred. The owner authorization supplies the pins; this
module checks their bytes and agreement. Pool content is public-source material,
never a generated dataset or protected evaluation.
"""
import hashlib
import json
import subprocess
from pathlib import Path

import v5_pools_common as C

SCHEMA = 'v5-ai-audit-evidence/v1-PROPOSED'
EXCHANGE_SCHEMA = 'v5-r3-category-outcomes-exchange/v1'
REPORT_SCHEMA = 'v5-postfilter-r3-adjudication/v1'
FILES = ('exchange', 'report', 'state', 'pool_manifest', 'pool')
OUTCOMES = {'PASS_AI_AUDITED', 'FAIL', 'INSUFFICIENT_EVIDENCE'}


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def valid_hash(value):
    return type(value) is str and len(value) == 64 and all(c in '0123456789abcdef' for c in value)


def is_committed(path):
    p = Path(path).resolve()
    root = Path(C.REPO_ROOT).resolve()
    if not p.is_relative_to(root):
        return False
    rel = str(p.relative_to(root))
    tracked = subprocess.run(['git','-C',str(root),'ls-files','--error-unmatch','--',rel],capture_output=True)
    diff = subprocess.run(['git','-C',str(root),'diff','--quiet','HEAD','--',rel],capture_output=True)
    return tracked.returncode == 0 and diff.returncode == 0


def verify(binding, *, expected_pool_sha256=None, expected_outcomes=None, records=None,
           captured_exchange=None, record_ids=None, committed_checker=None):
    if type(binding) is dict and binding.get('schema') == 'v5-native-source-audit-evidence/v1':
        import v5_native_source_audit as native
        return native.verify(binding, expected_pool_sha256=expected_pool_sha256,
                             expected_outcomes=expected_outcomes, records=records,
                             record_ids=record_ids, committed_checker=committed_checker)
    if type(binding) is not dict or binding.get('schema') != SCHEMA:
        raise ValueError('audit evidence binding missing or unsupported')
    raw, docs, hashes = {}, {}, {}
    for name in FILES:
        desc = binding.get(name)
        if (type(desc) is not dict or type(desc.get('path')) is not str or not desc['path'].strip()
                or not valid_hash(desc.get('sha256'))):
            raise ValueError(f'audit evidence descriptor invalid: {name}')
        path = Path(desc['path'])
        if not path.is_absolute():
            path = Path(C.REPO_ROOT)/path
        if committed_checker is not None and name in ('exchange','report','state') and not committed_checker(str(path)):
            raise ValueError(f'audit metadata must be committed and unchanged: {name}')
        try:
            C.assert_not_protected(str(path))
        except SystemExit as e:
            raise ValueError('protected audit evidence path') from e
        if name == 'exchange' and captured_exchange is not None:
            # The generator already captured this object once. Check those exact bytes' hash.
            got, obj = captured_exchange
            if got != desc['sha256'] or type(obj) is not dict:
                raise ValueError('audit exchange hash mismatch')
            hashes[name], docs[name] = got, obj
            continue
        data = path.read_bytes()
        got = sha256(data)
        if got != desc['sha256']:
            raise ValueError(f'audit evidence hash mismatch: {name}')
        raw[name], hashes[name] = data, got
        if name != 'pool':
            docs[name] = json.loads(data)
            if type(docs[name]) is not dict:
                raise ValueError(f'audit evidence is not an object: {name}')
    exchange, report, state = (docs[k] for k in ('exchange','report','state'))
    if exchange.get('schema') != EXCHANGE_SCHEMA or exchange.get('audit_type') != 'ai_audited':
        raise ValueError('audit exchange schema/provenance mismatch')
    if report.get('schema') != REPORT_SCHEMA or report.get('audit_type') != 'ai_audited':
        raise ValueError('audit report schema/provenance mismatch')
    if exchange.get('source_report_sha256') != hashes['report']:
        raise ValueError('audit exchange does not name the verified report')
    reported = report.get('category_outcomes')
    if type(reported) is not dict or not reported:
        raise ValueError('audit report has no category outcomes')
    outcomes = {}
    for cat, item in reported.items():
        if type(cat) is not str or type(item) is not dict:
            raise ValueError('audit report category invalid')
        status = item.get('status')
        status = 'FAIL' if status == 'NOT_SUPPORTED' else status
        if status not in OUTCOMES:
            raise ValueError('audit report outcome unknown')
        outcomes[cat] = status
    if exchange.get('category_outcomes') != outcomes:
        raise ValueError('audit exchange outcomes differ from the report')
    if expected_outcomes is not None and expected_outcomes != outcomes:
        raise ValueError('declared category outcomes differ from verified audit')
    sample_sha = (state.get('sample') or {}).get('sha256')
    source_pins = report.get('source_sha256')
    if not valid_hash(sample_sha) or type(source_pins) is not dict or not any(k.endswith('/sample.jsonl') and v == sample_sha for k,v in source_pins.items()):
        raise ValueError('audit report and sampling state do not name the same sample')
    if ((state.get('pool') or {}).get('sha256') != hashes['pool']
            or state.get('pool_manifest_sha256') != hashes['pool_manifest']):
        raise ValueError('audit sampling state does not name the verified pool')
    if expected_pool_sha256 is not None and expected_pool_sha256 != hashes['pool']:
        raise ValueError('dataset and audit pool differ')
    if records is not None or record_ids is not None:
        pool = {}
        for line in raw['pool'].split(b'\n'):
            if not line.strip():
                continue
            item = json.loads(line)
            if type(item) is not dict or type(item.get('record_id')) is not str or item['record_id'] in pool:
                raise ValueError('invalid/duplicate pool record')
            pool[item['record_id']] = item
        for rid in record_ids or ():
            if type(rid) is not str or rid not in pool:
                raise ValueError('dataset record absent from audited pool')
        for row in records or ():
            source = pool.get(row.get('record_id'))
            if source is None:
                raise ValueError('world record absent from audited pool')
            for field in ('payload_wire', 'dedup_scope', 'category_v4', 'source_file', 'payload_raw'):
                if field in source and row.get(field) != source[field]:
                    raise ValueError(f'world record differs from audited pool: {field}')
    return {'category_outcomes':outcomes, 'audit_type':'ai_audited',
            'sha256':hashes, 'pool_sha256':hashes['pool']}
