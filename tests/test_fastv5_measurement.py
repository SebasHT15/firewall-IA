"""Prevent known denominator and attribution errors without running services."""
import sys, unittest, tempfile, json
from pathlib import Path
from unittest.mock import patch
from types import SimpleNamespace as NS
R=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(R/'scripts/local_stack/challenges'),str(R/'scripts/local_stack')]
import score_trial as S
from trial_client import TrialClient
import trial


def row(label='BLOCK', blocked=False, stage='v5', effect=False):
    return {'arm':'fastv5','label':label,'complete':True,'app_received':not blocked,
            'layer':'firewall' if blocked else 'application','applied':'DENY' if blocked else 'FORWARD',
            'deciding_stage':stage,'canonical_outcome':'ACCEPT','v5':{'status':'ok','decision':'BLOCK' if blocked else 'ALLOW'},
            'group_id':'g','session_id':'s','family':'unit','effect_observed':effect,'effect_eligible':False}

class MeasurementTests(unittest.TestCase):
    def test_status_only_error_does_not_enter_exploit_denominator(self):
        direct={'c':row(effect=True)}; rows={'c':row(blocked=True)}
        out=S.score_arm(rows,direct)
        self.assertEqual(out['counts'].get('eligible_effect_positive_direct',0),0)
        self.assertEqual(out['counts']['non_exploit_oracle_excluded'],1)
    def test_observation_is_not_an_independent_benign_or_attack(self):
        obs=row(label='ALLOW',effect=True);obs['sequence_role']='observe'
        self.assertIsNone(S.primary_cell(obs))
    def test_two_step_prevention_requires_direct_positive_and_no_persistent_effect(self):
        attack=row();attack.update(attack_sequence_id='seq',sequence_role='attack')
        observe=row(label='ALLOW',effect=True);observe.update(attack_sequence_id='seq',sequence_role='observe')
        direct={'a':dict(attack),'o':dict(observe)}
        stopped=dict(attack,app_received=False,applied='DENY',layer='firewall',v5={'status':'ok','decision':'BLOCK'})
        absent=dict(observe,effect_observed=False)
        out=S.sequence_effects({'a':stopped,'o':absent},direct)
        self.assertEqual(out['outcomes']['seq'],'PREVENTED_AT_ATTACK')
        self.assertEqual(S.sequence_effects({'a':stopped,'o':observe},direct)['outcomes']['seq'],'PERSISTED')
        self.assertEqual(S.sequence_effects({'a':stopped,'o':dict(absent,complete=False)},direct)['outcomes']['seq'],'UNKNOWN')
        direct['o']['effect_observed']=False
        self.assertEqual(S.sequence_effects({'a':stopped,'o':absent},direct)['outcomes']['seq'],'DIRECT_NOT_POSITIVE')
    def test_guard_failure_is_not_a_detector_true_positive(self):
        r=row(blocked=True,stage='request_guard');r['v5']=None
        r['request_guard']={'status':'ERROR'}
        self.assertEqual(S.classify(r),'INFRA_ERROR')
        r['request_guard']['status']='MATCH'
        self.assertEqual(S.classify(r),'BLOCK')
    def test_fast_path_savings_excludes_guard_blocks(self):
        ref={k:row(label='ALLOW',effect=True)for k in ('f','g')}
        fast=dict(ref['f'],deciding_stage='fast_path',v5=None,response_sha256='hash')
        guard=dict(ref['g'],deciding_stage='request_guard',v5=None,applied='DENY',app_received=False,request_guard={'status':'MATCH'})
        out=S.compare_fast_path(ref,{'f':fast,'g':guard},ref)
        self.assertEqual(out['counts']['v5_calls_avoided_fast_path'],1)
        self.assertEqual(out['counts']['v5_calls_avoided_request_guard'],1)
        self.assertEqual(out['fast_path_calls_avoided_fraction'],.5)
    def test_failed_transport_is_not_retried_and_reports_unknown_effect(self):
        client=object.__new__(TrialClient)
        with patch.object(client,'_request',side_effect=ConnectionResetError('private detail'))as req,patch.object(client,'close')as close:
            result=client.request('POST','/',body=b'side effect')
            self.assertEqual(req.call_count,1);close.assert_called_once()
            self.assertEqual(result['error'],'ConnectionResetError')
            self.assertNotIn('private detail',str(result))
            self.assertIsNone(trial.effect({'type':'status','value':200},result))

    def test_partial_jsonl_is_retained_without_lost_or_duplicate_records(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'log.jsonl'
            first=b'{"n":1}\n';path.write_bytes(first+b'{"n":')
            rows,offset=trial.smoke.new_json_lines(path,0)
            self.assertEqual(rows,[{'n':1}]);self.assertEqual(offset,len(first))
            with path.open('ab')as fh:fh.write(b'2}\n')
            rows,end=trial.smoke.new_json_lines(path,offset)
            self.assertEqual(rows,[{'n':2}])
            self.assertEqual(trial.smoke.new_json_lines(path,end),([],end))
            path.write_bytes(b'bad\n')
            with self.assertRaises(json.JSONDecodeError):trial.smoke.new_json_lines(path,0)

if __name__=='__main__':unittest.main()
