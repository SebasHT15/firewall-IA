"""Unconstrained prefixes and complete suffix verification, including EOS."""
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch,Mock,MagicMock
ROOT=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(ROOT/'scripts/v5_successor'),str(ROOT/'control_plane')]
from verified_suffix import matching_candidates,suffix_verified,compatible_generation,classify_verified,generate_verified

class VerificationTests(unittest.TestCase):
    def test_prefix_is_not_forced_into_the_vocabulary(self):
        self.assertEqual(matching_candidates([[1,2,0],[1,3,0]],[9]),[])
    def test_ambiguous_prefix_needs_more_native_tokens(self):
        self.assertEqual(len(matching_candidates([[1,2,0],[1,3,0]],[1])),2)
    def test_one_mismatched_token_rejects_proposal(self):
        self.assertFalse(suffix_verified([2,3,0],[2,7,0]))
    def test_eos_mismatch_rejects_proposal(self):
        self.assertFalse(suffix_verified([2,3,0],[2,3,4]))
    def test_missing_eos_rejects_proposal(self):
        self.assertFalse(suffix_verified([2,3,0],[2,3]))
    def test_empty_verification_is_not_success(self):
        self.assertFalse(suffix_verified([],[]))
    def test_complete_exact_proposal_is_verified(self):
        self.assertTrue(suffix_verified([2,3,0],[2,3,0]))
    def test_nontrivial_logits_processors_cannot_be_ignored(self):
        self.assertFalse(compatible_generation(SimpleNamespace(repetition_penalty=1.2)))
        self.assertFalse(compatible_generation(SimpleNamespace(forced_eos_token_id=0)))
        self.assertTrue(compatible_generation(SimpleNamespace()))
        self.assertTrue(compatible_generation(SimpleNamespace(renormalize_logits=None,token_healing=None)))
    def test_content_rejection_cannot_recurse_into_serving_decoder(self):
        import v5_inference_core as core
        fake=SimpleNamespace(contract=None,tokenizer=None)
        with patch.dict(sys.modules,{'torch':SimpleNamespace()}),patch.object(core,'encode_canonical',side_effect=core.V5ContentRejected('over budget')):
            parsed,measure=classify_verified(fake,'unencodable',[])
        self.assertEqual(parsed.invalid_reason,'content_rejected')
        self.assertEqual(measure['generated_tokens'],0)
        self.assertEqual(measure['generate_ms'],0)
        self.assertFalse(measure['ended_with_eos'])

    def fallback_fixture(self,first):
        logits=MagicMock();logits.__getitem__.return_value.argmax.return_value.item.return_value=first
        verify=MagicMock();verify.__getitem__.return_value.argmax.return_value.tolist.return_value=[9,2]
        mdl=Mock(side_effect=[SimpleNamespace(logits=logits,past_key_values='kv'),SimpleNamespace(logits=verify)])
        mdl._prepare_generation_config.return_value=(SimpleNamespace(),{})
        output=MagicMock();output.__getitem__.return_value.tolist.return_value=[99,98]
        mdl.generate.return_value=output
        model=SimpleNamespace(model=mdl,tokenizer=SimpleNamespace(eos_token_id=2),contract=SimpleNamespace(max_new_tokens=17))
        fake_torch=SimpleNamespace(tensor=Mock(),ones=Mock())
        return model,fake_torch

    def test_unknown_native_prefix_returns_native_invalid_tokens(self):
        model,torch=self.fallback_fixture(9)
        with patch.dict(sys.modules,{'torch':torch}):
            tokens,info=generate_verified(model,SimpleNamespace(shape=(1,2),device='cpu'),SimpleNamespace(dtype='long'),[[1,3,2]])
        self.assertEqual(tokens,[99,98]);self.assertTrue(info['fallback'])
        self.assertFalse(info['suffix_verified']);model.model.generate.assert_called_once()

    def test_failed_suffix_verification_never_forces_candidate_or_eos(self):
        model,torch=self.fallback_fixture(1)
        with patch.dict(sys.modules,{'torch':torch}):
            tokens,info=generate_verified(model,SimpleNamespace(shape=(1,2),device='cpu'),SimpleNamespace(dtype='long'),[[1,3,2]])
        self.assertEqual(tokens,[99,98]);self.assertTrue(info['fallback'])
        self.assertFalse(info['suffix_verified']);self.assertNotIn(2,tokens)
        self.assertEqual(model.model.generate.call_args.kwargs['max_new_tokens'],17)

if __name__=='__main__':unittest.main()
