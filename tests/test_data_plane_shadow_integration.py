"""The two independently developed shadow hooks must coexist without changing V4."""

import asyncio
import unittest

from tests.test_data_plane_fast_path import (
    EligibleEvidence, INVALID, OK_ALLOW, OK_BLOCK, POLICY_REL, URL,
    classifier, data_plane, make_request, tflow,
)
import hybrid_shadow as shadow


class Runner:
    def __init__(self, status):
        self.status = status
        self.calls = 0

    async def run(self, raw_request):
        self.calls += 1
        if self.status == "raise":
            raise RuntimeError("simulated analyzer failure")
        return shadow.ShadowResult(self.status, None, "integration-test", elapsed_ms=0.1)


class CombinedShadowHooks(unittest.IsolatedAsyncioTestCase):
    async def test_both_hooks_preserve_v4_response_and_input(self):
        for code, body in ((200, OK_ALLOW), (200, OK_BLOCK), (200, INVALID), (500, {})):
            for status in (shadow.UNAVAILABLE, shadow.INVALID_OUTPUT, shadow.TIMEOUT, "raise"):
                with self.subTest(classifier_code=code, body=body, analyzer=status):
                    baseline_seen, combined_seen = [], []
                    baseline = tflow.tflow(req=make_request())
                    combined = tflow.tflow(req=make_request())
                    runner = Runner(status)
                    plain = data_plane.FirewallGateway(
                        URL, 1.0, transport=classifier(code, body, baseline_seen))
                    gateway = data_plane.FirewallGateway(
                        URL, 1.0, transport=classifier(code, body, combined_seen),
                        shadow_analyzer=runner, shadow_fast_path=True,
                        fast_path_policy_file=POLICY_REL, fast_path_evidence=EligibleEvidence())
                    with self.assertLogs("firewall.data_plane", level="INFO") as logs:
                        await plain.request(baseline)
                        await gateway.request(combined)
                        await asyncio.gather(*list(gateway._shadow_tasks))
                    expected = None if baseline.response is None else (
                        baseline.response.status_code, baseline.response.content)
                    actual = None if combined.response is None else (
                        combined.response.status_code, combined.response.content)
                    self.assertEqual(actual, expected)
                    self.assertEqual([r.content for r in combined_seen],
                                     [r.content for r in baseline_seen])
                    self.assertEqual(len(combined_seen), 1)
                    self.assertEqual(runner.calls, 1)
                    self.assertIn("FAST_ALLOW (hypothetical", "\n".join(logs.output))
                    self.assertIn("HYBRID SHADOW", "\n".join(logs.output))

    async def test_pending_analyzer_does_not_hold_fast_path_or_response(self):
        release = asyncio.Event()

        class PendingRunner:
            async def run(self, raw_request):
                await release.wait()
                return shadow.ShadowResult(shadow.UNAVAILABLE, "test", "integration-test")

        seen = []
        flow = tflow.tflow(req=make_request())
        gateway = data_plane.FirewallGateway(
            URL, 1.0, transport=classifier(200, OK_BLOCK, seen),
            shadow_analyzer=PendingRunner(), shadow_fast_path=True,
            fast_path_policy_file=POLICY_REL, fast_path_evidence=EligibleEvidence())
        try:
            with self.assertLogs("firewall.data_plane", level="INFO") as logs:
                await asyncio.wait_for(gateway.request(flow), 1.0)
                self.assertFalse(release.is_set())
                self.assertEqual(flow.response.status_code, 403)
                self.assertEqual(len(seen), 1)
                self.assertIn("FAST_ALLOW (hypothetical", "\n".join(logs.output))
        finally:
            release.set()
            await asyncio.gather(*list(gateway._shadow_tasks))
