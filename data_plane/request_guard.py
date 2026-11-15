"""Versioned deterministic guard for an audited application header-to-Jinja sink.

This is NOT a V5 model decision or a new canonical-request/v1 representation.
A policy is pinned to the application contract and can inspect only POST headers.
Raw HTTP header values are used as Flask does (no speculative percent decoding).
Only Jinja's lexical template openings are denied; raw values never enter records.
"""
from dataclasses import dataclass
import hashlib
import json
import re

SCHEMA_V1='request-header-sink-guard/v1'
SCHEMA='request-header-sink-guard/v2'
@dataclass(frozen=True)
class Policy:
    policy_id: str
    application_contract_ref: str
    sha256: str
    schema: str = SCHEMA


def load(path, expected_sha256=None, expected_contract=None):
    with open(path,'rb') as fh:
        raw=fh.read()
    digest=hashlib.sha256(raw).hexdigest()
    if expected_sha256 is not None and digest!=expected_sha256:
        raise ValueError('request guard policy hash mismatch')
    d=json.loads(raw)
    if (not isinstance(d,dict) or set(d)!={'schema','policy_id','application_contract_ref','methods','sink'}
        or d['schema'] not in (SCHEMA_V1, SCHEMA) or d['methods']!=['POST'] or d['sink']!='jinja_template_headers'
        or not isinstance(d['policy_id'],str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,128}',d['policy_id'])
        or not isinstance(d['application_contract_ref'],str) or not d['application_contract_ref']):
        raise ValueError('request guard policy contract invalid')
    if expected_contract is not None and d['application_contract_ref']!=expected_contract:
        raise ValueError('request guard application binding mismatch')
    return Policy(d['policy_id'],d['application_contract_ref'],digest,d['schema'])


def evaluate(snapshot, policy):
    matched=False
    # Flask/Werkzeug normalizes the method; raw lowercase/mixed-case aliases
    # must not reach the same POST sink without inspection. v1 is preserved
    # only for explicitly loaded historical DEV policies.
    method=snapshot.method if policy.schema==SCHEMA_V1 else snapshot.method.upper()
    if method==b'POST':
        # The audited app stores all incoming POST headers then concatenates them
        # into a Jinja template; guard every POST to cover backend route aliases.
        matched=any(any(x in value for x in (b'{{',b'{%',b'{#'))
                    for _,value in snapshot.headers)
    return {'status':'MATCH' if matched else 'CLEAR','policy_id':policy.policy_id,
            'policy_sha256':policy.sha256,'contract':policy.schema,
            'reason':'jinja_header_syntax' if matched else None}
