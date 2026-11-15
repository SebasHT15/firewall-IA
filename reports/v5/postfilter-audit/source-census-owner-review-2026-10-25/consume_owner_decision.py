#!/usr/bin/env python3
"""Apply the recorded owner disposition to exactly four unresolved census traces."""
import copy
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path('/home/sebas/Desktop/firewall-IA')
HERE = Path(__file__).resolve().parent
BASE = HERE/'base-result.json'
PREREG = HERE/'preregistration.json'
sys.path.insert(0, str(ROOT/'scripts/dataset'))
import adjudicate_v5_r4_continuation as rules

def sha(raw): return hashlib.sha256(raw).hexdigest()
def dump(value): return (json.dumps(value, sort_keys=True, ensure_ascii=False, indent=2)+'\n').encode()

decision_raw = (HERE/'owner-decision.json').read_bytes()
decision = json.loads(decision_raw)
raw = BASE.read_bytes()
assert sha(raw) == decision['base_result_sha256']
base = json.loads(raw)
assert decision['owner_chat_quote'] == 'Sí, aprobar las cuatro como UNCERTAIN'
assert decision['disposition_type'] == 'RESOLVE_WITH_EVIDENCE'
assert decision['resolved_label'] == 'UNCERTAIN'
assert decision['votes_modified'] is False and decision['population_modified'] is False
assert decision['training_authorized'] is False
ids = set(decision['sample_ids'])
assert len(ids) == 4
unresolved = {r['sample_id'] for r in base['traces'] if r['adjudicated_label'] is None}
assert ids == unresolved
population = {json.loads(line)['sample_id']:json.loads(line) for line in (HERE/'population.jsonl').read_text().splitlines() if line}
assert set(population) >= ids
for rid in ids:
    item = population[rid]
    src = item['source']
    original = (Path('/home/sebas/PayloadsAllTheThings')/src['source_file']).read_bytes()
    assert sha(original) == src['source_sha256']
    assert original[src['utf8_byte_start']:src['utf8_byte_end']].decode() == item['payload_wire']
traces = copy.deepcopy(base['traces'])
for trace in traces:
    if trace['sample_id'] in ids:
        assert trace['rule'] == 'UNRESOLVED_THREE_WAY'
        assert trace['adjudicated_label'] is None
        trace['adjudicated_label'] = 'UNCERTAIN'
        trace['owner_disposition'] = {'type':'RESOLVE_WITH_EVIDENCE', 'decision_sha256':sha(decision_raw)}
prereg = json.loads(PREREG.read_bytes())
assert sha(PREREG.read_bytes()) == base['preregistration_sha256']
outcomes = rules.summarize(traces,prereg)
for cat in ('Command Injection','SQL Injection'):
    assert outcomes[cat] == base['category_outcomes'][cat]
assert outcomes['Server Side Template Injection']['status'] == 'PASS_AI_AUDITED'
assert outcomes['XSS Injection']['status'] == 'PASS_AI_AUDITED'
result = {
    'schema':'v5-contextual-source-census-owner-resolved/v1',
    'base_result_sha256':sha(raw), 'owner_decision_sha256':sha(decision_raw),
    'preregistration_sha256':base['preregistration_sha256'],
    'population_sha256':base['population_sha256'],
    'category_outcomes':outcomes, 'traces':traces,
    'provenance':base['provenance'], 'training_authorized':False,
    'pool_evidence_transferred':False, 'human_validation':False,
}
(HERE/'result.json').write_bytes(dump(result))
(HERE/'SHA256SUMS').write_text(''.join(f'{sha((HERE/name).read_bytes())}  {name}\n' for name in ('PROPOSAL.md','owner-decision.json','result.json','base-result.json','preregistration.json','population.jsonl')))
print(json.dumps({k:{'status':v['status'],'C1':v['wilson_incorrect_upper'],'C2':v['wilson_uncertain_incorrect_upper']} for k,v in outcomes.items()},indent=2))
