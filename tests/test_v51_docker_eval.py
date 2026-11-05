"""Meaningful guardrails for the new effect-vs-classification experiment."""
import importlib.util
from pathlib import Path
import sys
import unittest

REPO = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(REPO / 'scripts/v5_successor/docker_eval'), str(REPO / 'data_plane')]
import population as P
import experiment as E
import canonical_request as C

spec = importlib.util.spec_from_file_location('docker_experiment_report', REPO / 'scripts/v5_successor/docker_eval/report.py')
REPORT = importlib.util.module_from_spec(spec)
spec.loader.exec_module(REPORT)


class DockerExperiment(unittest.TestCase):
    def test_every_wire_has_the_declared_real_canonical_form(self):
        for case in P.population('172.30.81.3'):
            headers = [(b'Host', b'shop.fwlab.test'), (b'X-Experiment-Id', b'not-model-input')]
            if case['content_type']:
                headers.append((b'Content-Type', case['content_type'].encode()))
            body = case['body'].encode()
            if body or case['method'] == 'POST':
                headers.append((b'Content-Length', str(len(body)).encode()))
            parts = C.RequestParts(case['method'].encode(), case['target'].encode(), 'HTTP/1.1', tuple(headers), body)
            result = C.canonicalize(parts, C.Limits(max_decoded_body=19920, token_budget=415, max_bytes_per_token=48))
            self.assertEqual(result.outcome, 'ACCEPT', case['id'])
            self.assertEqual(result.text, P.canonical(case), case['id'])

    def test_order_preserves_login_cart_and_checkout(self):
        cases = P.population('172.30.81.3')
        order = P.order(cases)
        self.assertEqual(set(order), {c['id'] for c in cases})
        for session in {c['session'] for c in cases if c['session']}:
            indices = [order.index(c['id']) for c in cases if c['session'] == session]
            self.assertEqual(indices, sorted(indices))

    def test_known_routes_separate_and_all_families_have_benign_controls(self):
        cases = P.population('172.30.81.3')
        self.assertEqual([c['target'] for c in cases if c['cohort'] == 'known_regression'], ['/healthz','/static/app.css'])
        for f in {c['family'] for c in cases if c['label'] == 'BLOCK'}:
            self.assertEqual({c['label'] for c in cases if c['family'] == f}, {'ALLOW','BLOCK'})

    def test_http_success_and_reflected_payload_do_not_prove_exploitation(self):
        c = dict(label='BLOCK', oracle='secret', expected=P.CANARY)
        self.assertFalse(E.effect(c, dict(body='normal 200 page', status=200)))
        c = dict(label='BLOCK', oracle='browser_script', expected='XSS_0')
        self.assertIsNone(E.effect(c, dict(body="<script>window.__fwlab_marker='XSS_0'</script>", status=200)))

    def test_redirect_requires_external_location(self):
        c = dict(label='BLOCK', oracle='external_location', expected='collector.fwlab.test')
        self.assertFalse(E.effect(c, dict(body='',status=302,headers=[('Location','/products')])))
        self.assertTrue(E.effect(c, dict(body='',status=302,headers=[('Location','//collector.fwlab.test/cb')])))

    def test_invalid_cannot_earn_ml_detection_credit_because_gateway_denies(self):
        row = dict(id='a', canonical_sha256='a'*64, label='BLOCK', received=False, record={'deciding_stage':'v5'},
                   model2=None, v5=dict(status='invalid', decision=None, invalid_reason='no_eos'))
        pred = REPORT.prediction(row)
        self.assertEqual(REPORT.M.prediction_cell(row,pred), ('FN',False,None))

    def test_model2_defer_does_not_become_a_binary_allow(self):
        row = dict(id='a',canonical_sha256='a'*64,record={'deciding_stage':'v5'},
                   model2={'status':'OK','decision':'DEFER'},v5={})
        self.assertIsNone(REPORT.prediction(row)['decision'])


if __name__ == '__main__':
    unittest.main()
