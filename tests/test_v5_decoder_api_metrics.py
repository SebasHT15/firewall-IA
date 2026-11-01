"""Optional decoder telemetry preserves decisions, including invalid outputs."""
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'control_plane'))
import v5_classifier_api as API


class DecoderMetricsTests(unittest.TestCase):
    def classify(self,*,invalid=False,extra=None):
        parsed=SimpleNamespace(status='invalid' if invalid else 'ok',decision=None if invalid else 'ALLOW',
                               reason=None if invalid else 'Normal HTTP request with no attack patterns detected.',
                               invalid_reason='no_eos' if invalid else None)
        measure=dict(encode_ms=1.,transfer_ms=1.,generate_ms=10.,decode_ms=1.,parse_ms=1.,
                     ended_with_eos=not invalid,generated_tokens=7,prompt_tokens=100)
        measure.update(extra or {})
        with patch.object(API.app.state,'v5',object()),patch.object(API.core,'classify_canonical',return_value=(parsed,measure)):
            return API.classify(API.ClassifyRequest(canonical_request='GET / HTTP/1.1\n'))
    def test_native_telemetry_is_unset(self):
        reply=self.classify();self.assertIsNone(reply.decoder_verified);self.assertIsNone(reply.decoder_fallback)
        self.assertEqual(reply.decision,'ALLOW')
    def test_verified_metrics_are_exposed_without_changing_decision(self):
        reply=self.classify(extra=dict(suffix_verified=True,fallback=False,prefix_tokens=4,verification_tokens=8))
        self.assertTrue(reply.decoder_verified);self.assertFalse(reply.decoder_fallback)
        self.assertEqual(reply.decoder_verification_tokens,8);self.assertEqual(reply.decision,'ALLOW')
    def test_fallback_does_not_turn_invalid_into_allow(self):
        reply=self.classify(invalid=True,extra=dict(suffix_verified=False,fallback=True))
        self.assertEqual(reply.status,'invalid');self.assertIsNone(reply.decision)
        self.assertEqual(reply.invalid_reason,'no_eos');self.assertTrue(reply.decoder_fallback)


if __name__=='__main__':unittest.main()
