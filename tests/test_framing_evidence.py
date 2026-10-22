"""Unit tests for data_plane/framing_evidence.py — the HTTP/1.1 framing OBSERVATION evidence
(issue #68, Track A; D70 PROPOSED).

These are focused, mostly PURE tests: `framing_evidence` imports only the sibling
`canonical_observer`/`canonical_adapter` (stdlib at import time), so the bulk of the suite needs no
data-plane environment and no worker. ONE end-to-end test (`TestResidualFramingEndToEnd`) spawns the
real worker to prove that a request rejected EARLY (canonical `R4`) while ALSO carrying bad framing
(duplicate Content-Length, i.e. an `R1` vector) surfaces as UNATTESTABLE — never as success — so the
ABSENCE of an `R1` code can never be read as a pass. It is skipped (disclosed, not passed) if the
data-plane env (mitmproxy) is unavailable.

Nothing here enforces or forwards; `PROFILE_MATCHED` is only "profile + observed snapshot met the
defined conditions", never VERIFIED / safe-to-forward / Fast-Path eligible / upstream-equivalent.
"""
import os
import sys
import unittest
from types import SimpleNamespace

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO_ROOT, "data_plane"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import canonical_adapter as adapter
import canonical_observer as obs_mod
import framing_evidence as fe


# ── builders ───────────────────────────────────────────────────────────────────
def profile(**over):
    """A tested FramingProfile unless a field is overridden."""
    base = dict(
        mitmproxy_version=fe.TESTED_MITMPROXY_VERSION,
        validate_inbound_headers=True,
        http2=False,
        stream_large_bodies=None,
        body_size_limit=None,
        mode=fe.TESTED_MODE,
        connection_strategy="lazy",
    )
    base.update(over)
    return fe.FramingProfile(**base)


def ok_accept(elapsed=1.5):
    return obs_mod.CanonicalObservation(obs_mod.OK, outcome="ACCEPT", size="UNCHECKED",
                                        target_form=adapter.FORM_ORIGIN, elapsed_ms=elapsed)


def ok_reject(code="R1"):
    return obs_mod.CanonicalObservation(obs_mod.OK, outcome="REJECT", reject=code,
                                        target_form=adapter.FORM_ORIGIN, elapsed_ms=1.0)


def ok_unsupported():
    return obs_mod.CanonicalObservation(obs_mod.OK, outcome="UNSUPPORTED",
                                        target_form=adapter.FORM_AUTHORITY, elapsed_ms=1.0)


def ev(prof=None, gc=1, gr=1, obs=None, form=adapter.FORM_ORIGIN, avail=True, version="HTTP/1.1"):
    return fe.evaluate(profile=profile() if prof is None else prof, gen_at_capture=gc,
                       gen_at_reply=gr, canonical_obs=ok_accept() if obs is None else obs,
                       form=form, canonical_available=avail, http_version=version)


# ── FramingProfile ──────────────────────────────────────────────────────────────
class TestFramingProfile(unittest.TestCase):
    def test_tested_profile_is_recognised(self):
        p = profile()
        self.assertTrue(p.is_tested_profile())
        self.assertFalse(p.has_unavailable_field())

    def test_each_off_field_makes_it_not_tested(self):
        for field_over in (
            dict(mitmproxy_version="12.2.2"),
            dict(validate_inbound_headers=False),
            dict(http2=True),                       # HTTP/2 enabled: not the tested lab profile
            dict(stream_large_bodies=1_000_000),
            dict(body_size_limit=5_000_000),
            dict(mode="regular"),
            dict(mode="reverse_proxy:other"),
            dict(connection_strategy="eager"),
        ):
            with self.subTest(field_over=field_over):
                self.assertFalse(profile(**field_over).is_tested_profile())

    def test_unavailable_field_is_flagged_and_not_tested(self):
        p = profile(http2=fe.UNAVAILABLE_FIELD)
        self.assertTrue(p.has_unavailable_field())
        self.assertFalse(p.is_tested_profile())      # an unavailable field is NEVER silently tested

    def test_fingerprint_changes_with_any_relevant_field(self):
        base = profile().relevant_fingerprint()
        self.assertEqual(base, profile().relevant_fingerprint())
        self.assertNotEqual(base, profile(connection_strategy="eager").relevant_fingerprint())
        self.assertNotEqual(base, profile(http2=True).relevant_fingerprint())
        # The fingerprint is hashable (used as a dict/set key for change detection).
        self.assertIsInstance(hash(base), int)


# ── sample_profile ───────────────────────────────────────────────────────────────
class TestSampleProfile(unittest.TestCase):
    def _opts(self, **over):
        base = dict(validate_inbound_headers=True, http2=False, stream_large_bodies=None,
                    body_size_limit=None, mode=["reverse:http://127.0.0.1:0"],
                    connection_strategy="lazy")
        base.update(over)
        return SimpleNamespace(**base)

    def test_reads_effective_tested_values(self):
        p = fe.sample_profile(self._opts(), fe.TESTED_MITMPROXY_VERSION)
        self.assertTrue(p.is_tested_profile())
        self.assertEqual(p.mode, fe.MODE_REVERSE_LOOPBACK)

    def test_missing_options_map_to_unavailable_not_tested(self):
        # An options object that simply lacks the attributes (getattr default path).
        p = fe.sample_profile(SimpleNamespace(), fe.TESTED_MITMPROXY_VERSION)
        self.assertTrue(p.has_unavailable_field())
        self.assertFalse(p.is_tested_profile())
        self.assertIs(p.validate_inbound_headers, fe.UNAVAILABLE_FIELD)
        self.assertIs(p.mode, fe.UNAVAILABLE_FIELD)   # a missing mode is unavailable, NOT the tested marker

    def test_unreadable_field_maps_to_unavailable(self):
        class Hostile:
            validate_inbound_headers = True
            http2 = False
            stream_large_bodies = None
            body_size_limit = None
            connection_strategy = "lazy"

            @property
            def mode(self):
                raise RuntimeError("cannot read mode")

        p = fe.sample_profile(Hostile(), fe.TESTED_MITMPROXY_VERSION)
        self.assertIs(p.mode, fe.UNAVAILABLE_FIELD)   # the raising field is unavailable, not tested
        self.assertFalse(p.is_tested_profile())

    def test_version_none_is_unavailable(self):
        p = fe.sample_profile(self._opts(), None)
        self.assertIs(p.mitmproxy_version, fe.UNAVAILABLE_FIELD)
        self.assertFalse(p.is_tested_profile())

    def test_mode_canonicalisation_validates_transport_and_address(self):
        tested = fe.MODE_REVERSE_LOOPBACK
        cases = {
            # the four required cases
            tuple(["reverse:http://127.0.0.1:8000"]): tested,                 # the lab, tested
            tuple(["reverse:http://127.synthetic.invalid:8000"]): "reverse_proxy:other",  # DNS name
            tuple(["reverse:https://127.0.0.1:8000"]): "reverse_proxy:other",  # wrong transport
            tuple(["reverse:http3://127.0.0.1:8000"]): "reverse_proxy:other",  # wrong transport
            # additional loopback literals / localhost over http: tested
            tuple(["reverse:http://localhost:0"]): tested,
            tuple(["reverse:http://[::1]:443"]): tested,
            tuple(["reverse:http://127.0.0.5:9"]): tested,
            # non-loopback / non-reverse
            tuple(["reverse:http://example.com:80"]): "reverse_proxy:other",
            tuple(["regular"]): "regular",
            tuple(["transparent"]): "transparent",
            tuple(["regular", "reverse:http://127.0.0.1:1"]): "multiple_modes",
        }
        for mode_value, expected in cases.items():
            with self.subTest(mode=mode_value):
                p = fe.sample_profile(self._opts(mode=list(mode_value)), fe.TESTED_MITMPROXY_VERSION)
                self.assertEqual(p.mode, expected)
                self.assertEqual(p.is_tested_profile(), expected == tested)

    def test_public_marker_hides_port_but_fingerprint_keeps_it(self):
        # Across-run dynamic ports share the tested CLASS (public marker), yet the INTERNAL
        # fingerprint differs by port so an in-run port change is observable.
        p1 = fe.sample_profile(self._opts(mode=["reverse:http://127.0.0.1:8000"]),
                               fe.TESTED_MITMPROXY_VERSION)
        p2 = fe.sample_profile(self._opts(mode=["reverse:http://127.0.0.1:9000"]),
                               fe.TESTED_MITMPROXY_VERSION)
        self.assertEqual(p1.mode, p2.mode)                 # same public class marker
        self.assertTrue(p1.is_tested_profile() and p2.is_tested_profile())
        self.assertNotEqual(p1.relevant_fingerprint(), p2.relevant_fingerprint())   # port kept internally
        self.assertNotIn("8000", p1.mode)                  # no port/destination in the public marker

    def test_sample_never_raises_on_hostile_options(self):
        class Boom:
            def __getattr__(self, name):
                raise RuntimeError("no attributes here")

        p = fe.sample_profile(Boom(), fe.TESTED_MITMPROXY_VERSION)  # must not raise
        self.assertTrue(p.has_unavailable_field())


# ── RelevantProfileGeneration ────────────────────────────────────────────────────
class TestRelevantProfileGeneration(unittest.TestCase):
    def test_first_observe_is_baseline_no_bump(self):
        g = fe.RelevantProfileGeneration()
        self.assertEqual(g.generation, 0)
        g.observe(profile())
        self.assertEqual(g.generation, 0)              # baseline established, no bump

    def test_single_change_bumps_once(self):
        g = fe.RelevantProfileGeneration()
        g.observe(profile())
        g.observe(profile())                           # identical fingerprint: no bump
        self.assertEqual(g.generation, 0)
        g.observe(profile(connection_strategy="eager"))
        self.assertEqual(g.generation, 1)

    def test_A_B_A_change_back_is_two_bumps(self):
        # Value equality against a single 'current' profile would see A==A and miss the round trip;
        # the monotonic counter must record BOTH transitions.
        g = fe.RelevantProfileGeneration()
        a, b = profile(), profile(http2=True)
        g.observe(a)                                   # baseline A, gen 0
        g.observe(b)                                   # A -> B, gen 1
        g.observe(a)                                   # B -> A (change back), gen 2
        self.assertEqual(g.generation, 2)

    def test_tested_to_untested_to_tested_drift(self):
        g = fe.RelevantProfileGeneration()
        g.observe(profile())                           # tested, baseline
        g.observe(profile(validate_inbound_headers=False))  # true -> false, bump
        g.observe(profile())                           # false -> true, bump
        self.assertEqual(g.generation, 2)

    def test_http_https_http_mode_drift_yields_generations_0_1_2(self):
        # Pure-unit SIMULATION of FirewallGateway.configure() being driven with a substituted options
        # object whose reverse transport flips http -> https -> http. The public class marker changes
        # AND the internal fingerprint changes, so the monotonic generation must be [0, 1, 2]
        # (NOT [0, 0, 0], which a public-marker-only or dict-equality check would produce).
        def opts(scheme):
            return SimpleNamespace(validate_inbound_headers=True, http2=False,
                                   stream_large_bodies=None, body_size_limit=None,
                                   mode=[f"reverse:{scheme}://127.0.0.1:8000"],
                                   connection_strategy="lazy")

        g = fe.RelevantProfileGeneration()
        seen = []
        for scheme in ("http", "https", "http"):
            seen.append(g.observe(fe.sample_profile(opts(scheme), fe.TESTED_MITMPROXY_VERSION)))
        self.assertEqual(seen, [0, 1, 2])

    def test_observe_never_raises_on_bad_profile(self):
        g = fe.RelevantProfileGeneration()

        class NoFingerprint:
            def relevant_fingerprint(self):
                raise RuntimeError("nope")

        self.assertEqual(g.observe(NoFingerprint()), 0)   # swallowed; counter unchanged


# ── evaluate ─────────────────────────────────────────────────────────────────────
class TestEvaluateProfileMatched(unittest.TestCase):
    def test_profile_matched_only_when_everything_holds(self):
        fo = ev()
        self.assertEqual(fo.status, fe.PROFILE_MATCHED)
        self.assertEqual(fo.reasons, ())
        self.assertEqual(fo.canonical_status, obs_mod.OK)
        self.assertEqual(fo.canonical_outcome, "ACCEPT")
        self.assertEqual(fo.target_form, adapter.FORM_ORIGIN)

    def test_asterisk_form_can_match(self):
        self.assertEqual(ev(form=adapter.FORM_ASTERISK).status, fe.PROFILE_MATCHED)

    def test_bare_lf_accept_may_reach_profile_matched_yet_is_not_wire_verified(self):
        # A bare-LF request is a WIRE fact canonical_request never sees, so canonicalize can ACCEPT
        # it. Under these limited semantics it MAY reach PROFILE_MATCHED — which asserts ONLY that the
        # profile and the observed snapshot met the defined conditions, NOT that the wire was verified.
        self.assertEqual(ev(obs=ok_accept()).status, fe.PROFILE_MATCHED)


class TestEvaluateUnattestable(unittest.TestCase):
    def test_generation_drift(self):
        fo = ev(gc=4, gr=5)
        self.assertEqual(fo.status, fe.UNATTESTABLE)
        self.assertIn(fe.GENERATION_DRIFT, fo.reasons)

    def test_profile_not_tested(self):
        fo = ev(prof=profile(connection_strategy="eager"))
        self.assertEqual(fo.status, fe.UNATTESTABLE)
        self.assertIn(fe.PROFILE_NOT_TESTED, fo.reasons)

    def test_validate_inbound_headers_off_adds_specific_reason(self):
        fo = ev(prof=profile(validate_inbound_headers=False))
        self.assertEqual(fo.status, fe.UNATTESTABLE)
        self.assertIn(fe.VALIDATE_INBOUND_HEADERS_OFF, fo.reasons)
        self.assertIn(fe.PROFILE_NOT_TESTED, fo.reasons)

    def test_canonical_reject_r1_is_residual_framing_failure(self):
        fo = ev(obs=ok_reject("R1"))
        self.assertEqual(fo.status, fe.UNATTESTABLE)
        self.assertEqual(fo.reasons, (fe.CANONICAL_REJECT_REASON,))
        self.assertEqual(fo.canonical_outcome, "REJECT")   # dimensions kept separate from the reason

    def test_canonical_reject_before_r1_is_still_unattestable(self):
        # An early reject (R4/R5/R6/R7) has NO R1 code, but the absence of an R1 code is NOT a pass:
        # a REJECT outcome is UNATTESTABLE, never PROFILE_MATCHED.
        for code in ("R4", "R5", "R6", "R7", "R8"):
            with self.subTest(code=code):
                fo = ev(obs=ok_reject(code))
                self.assertEqual(fo.status, fe.UNATTESTABLE)
                self.assertIn(fe.CANONICAL_REJECT_REASON, fo.reasons)
                self.assertNotEqual(fo.status, fe.PROFILE_MATCHED)

    def test_http_1_0_is_unattestable_even_when_accept(self):
        # HTTP/1.0 is in scope at the adapter and canonicalizes OK+ACCEPT, but it must NOT reach
        # PROFILE_MATCHED: only EXACTLY HTTP/1.1 may.
        fo = ev(version="HTTP/1.0")
        self.assertEqual(fo.status, fe.UNATTESTABLE)
        self.assertIn(fe.HTTP_VERSION_NOT_11, fo.reasons)
        self.assertNotEqual(fo.status, fe.PROFILE_MATCHED)

    def test_missing_or_odd_version_prevents_a_positive(self):
        for v in (None, "", "HTTP/1.2", "http/1.1"):
            with self.subTest(version=v):
                fo = ev(version=v)
                self.assertEqual(fo.status, fe.UNATTESTABLE)
                self.assertIn(fe.HTTP_VERSION_NOT_11, fo.reasons)

    def test_canonical_unsupported_is_unattestable(self):
        fo = ev(obs=ok_unsupported())
        self.assertEqual(fo.status, fe.UNATTESTABLE)
        self.assertIn(fe.CANONICAL_UNSUPPORTED_REASON, fo.reasons)

    def test_multiple_reasons_are_collected(self):
        fo = ev(prof=profile(connection_strategy="eager"), gc=1, gr=2, obs=ok_reject("R2"))
        self.assertEqual(fo.status, fe.UNATTESTABLE)
        self.assertIn(fe.GENERATION_DRIFT, fo.reasons)
        self.assertIn(fe.PROFILE_NOT_TESTED, fo.reasons)
        self.assertIn(fe.CANONICAL_REJECT_REASON, fo.reasons)


class TestEvaluateUnavailable(unittest.TestCase):
    def test_no_canonical_observer_when_unavailable_flag_false(self):
        fo = ev(avail=False)
        self.assertEqual(fo.status, fe.UNAVAILABLE)
        self.assertEqual(fo.reasons, (fe.NO_CANONICAL_OBSERVER,))

    def test_no_canonical_observer_when_obs_is_none(self):
        fo = fe.evaluate(profile=profile(), gen_at_capture=1, gen_at_reply=1, canonical_obs=None,
                         form=adapter.FORM_ORIGIN, canonical_available=True, http_version="HTTP/1.1")
        self.assertEqual(fo.status, fe.UNAVAILABLE)
        self.assertEqual(fo.reasons, (fe.NO_CANONICAL_OBSERVER,))

    def test_worker_infra_statuses_map_to_unavailable(self):
        cases = {
            obs_mod.UNAVAILABLE: fe.WORKER_UNAVAILABLE,
            obs_mod.BUSY: fe.WORKER_BUSY,
            obs_mod.TIMEOUT: fe.WORKER_TIMEOUT,
            obs_mod.DROP: fe.SNAPSHOT_DROPPED,
            obs_mod.ADAPTER_ERROR: fe.ADAPTER_ERROR,
        }
        for status, reason in cases.items():
            with self.subTest(status=status):
                obs = obs_mod.CanonicalObservation(status, detail="x", elapsed_ms=1.0)
                fo = ev(obs=obs)
                self.assertEqual(fo.status, fe.UNAVAILABLE)
                self.assertIn(reason, fo.reasons)

    def test_exception_id_mismatch_is_worker_unavailable_never_a_reject(self):
        # A late/cross-request reply is refused by the observer as EXCEPTION ipc_id_mismatch (the
        # correlation guard). The framing layer treats it as infrastructure UNAVAILABLE and can
        # NEVER attribute a PROFILE_MATCHED to such a desynchronised reply.
        obs = obs_mod.CanonicalObservation(obs_mod.EXCEPTION, detail="ipc_id_mismatch", elapsed_ms=1.0)
        fo = ev(obs=obs)
        self.assertEqual(fo.status, fe.UNAVAILABLE)
        self.assertIn(fe.WORKER_UNAVAILABLE, fo.reasons)
        self.assertNotEqual(fo.status, fe.PROFILE_MATCHED)

    def test_body_unavailable_maps_to_unavailable(self):
        # A missing/streamed body (None) is BODY_UNAVAILABLE at the observer; here it is UNAVAILABLE.
        # A PRESENT empty body (b"") instead reaches the worker and can ACCEPT -> PROFILE_MATCHED,
        # so the None-vs-b"" distinction (preserved by the adapter/observer) carries through here.
        obs = obs_mod.CanonicalObservation(obs_mod.BODY_UNAVAILABLE, detail="raw_content_none",
                                           target_form=adapter.FORM_ORIGIN, elapsed_ms=1.0)
        fo = ev(obs=obs)
        self.assertEqual(fo.status, fe.UNAVAILABLE)
        self.assertIn(fe.BODY_UNAVAILABLE, fo.reasons)

    def test_profile_field_unavailable_is_unavailable(self):
        fo = ev(prof=profile(mode=fe.UNAVAILABLE_FIELD))
        self.assertEqual(fo.status, fe.UNAVAILABLE)
        self.assertIn(fe.PROFILE_FIELD_UNAVAILABLE, fo.reasons)

    def test_out_of_scope_target_form(self):
        obs = obs_mod.CanonicalObservation(obs_mod.OUT_OF_SCOPE, detail=adapter.SCOPE_ABSOLUTE,
                                           target_form=adapter.FORM_ABSOLUTE, elapsed_ms=1.0)
        fo = ev(obs=obs, form=adapter.FORM_ABSOLUTE)
        self.assertEqual(fo.status, fe.UNAVAILABLE)
        self.assertIn(fe.TARGET_FORM_OUT_OF_SCOPE, fo.reasons)

    def test_out_of_scope_http_version(self):
        obs = obs_mod.CanonicalObservation(obs_mod.OUT_OF_SCOPE,
                                           detail=adapter.SCOPE_UNSUPPORTED_VERSION,
                                           target_form=adapter.FORM_ORIGIN, elapsed_ms=1.0)
        fo = ev(obs=obs, form=adapter.FORM_ORIGIN)
        self.assertEqual(fo.status, fe.UNAVAILABLE)
        self.assertIn(fe.HTTP_VERSION_OUT_OF_SCOPE, fo.reasons)

    def test_odd_form_with_accept_is_still_out_of_scope(self):
        # Defensive: even if an OK ACCEPT arrived, a non origin/asterisk form cannot be PROFILE_MATCHED.
        fo = ev(form=adapter.FORM_OTHER)
        self.assertEqual(fo.status, fe.UNAVAILABLE)
        self.assertIn(fe.TARGET_FORM_OUT_OF_SCOPE, fo.reasons)


# ── FramingObservation / format_record ────────────────────────────────────────────
class TestObservationAndRecord(unittest.TestCase):
    def test_status_and_reasons_are_closed(self):
        with self.assertRaises(ValueError):
            fe.FramingObservation(status="WHATEVER")
        with self.assertRaises(ValueError):
            fe.FramingObservation(status=fe.UNATTESTABLE, reasons=("NOT_A_REASON",))
        with self.assertRaises(ValueError):
            fe.FramingObservation(status=fe.PROFILE_MATCHED, reasons=(fe.GENERATION_DRIFT,))
        with self.assertRaises(ValueError):
            fe.FramingObservation(status=fe.UNATTESTABLE, reasons=())   # must carry a reason

    def test_format_record_is_closed_tokens_and_numbers_only(self):
        line = fe.format_record("tag01234", ev(obs=ok_reject("R1")))
        self.assertTrue(line.startswith("[tag01234] FRAMING OBS UNATTESTABLE"))
        self.assertIn("reasons=CANONICAL_REJECT", line)
        self.assertIn("canonical_status=OK", line)
        self.assertIn("canonical_outcome=REJECT", line)
        self.assertIn("target_form=origin", line)
        self.assertIn("gen=1", line)
        self.assertIn("elapsed=", line)

    def test_matched_line_has_no_reasons(self):
        line = fe.format_record("abc00001", ev())
        self.assertIn("FRAMING OBS PROFILE_MATCHED", line)
        self.assertNotIn("reasons=", line)


# ── end-to-end: early R4 reject WITH bad framing is never a pass ───────────────────
try:
    from mitmproxy import http
    from mitmproxy.test import tutils
    _HAVE_DATAPLANE = True
except ImportError:  # pragma: no cover
    _HAVE_DATAPLANE = False


@unittest.skipUnless(_HAVE_DATAPLANE, "needs the data plane environment (.venv-dataplane): mitmproxy")
class TestResidualFramingEndToEnd(unittest.IsolatedAsyncioTestCase):
    """Runs the real worker: a request rejected at canonical R4 (a NUL in a header value) WHILE ALSO
    carrying duplicate Content-Length (an R1 framing vector) must evaluate as UNATTESTABLE
    (CANONICAL_REJECT). Proves that 'no R1 code present' is never read as residual-framing success."""

    async def test_early_r4_with_duplicate_content_length_is_unattestable(self):
        o = obs_mod.build_process_observer(sys.executable, 5.0, 10.0, 0.0, 3)
        try:
            o.prewarm()
            if o._start_task is not None:
                await o._start_task
            r = tutils.treq(method=b"POST", path=b"/x", authority=b"", http_version=b"HTTP/1.1",
                            headers=http.Headers([(b"Host", b"h"), (b"X-Bad", b"a\x00b"),
                                                  (b"Content-Length", b"2"),
                                                  (b"Content-Length", b"2")]),
                            content=b"hi")
            cap = o.capture(r, profile=profile(), profile_generation=1)
            obs = await o.run_captured(cap)
            # The canonical observation itself: OK + REJECT + R4 (the early check wins over R1).
            self.assertEqual(obs.status, obs_mod.OK)
            self.assertEqual(obs.outcome, "REJECT")
            self.assertEqual(obs.reject, "R4")
            fo = fe.evaluate(profile=cap.profile, gen_at_capture=cap.profile_generation,
                             gen_at_reply=1, canonical_obs=obs, form=cap.form,
                             canonical_available=True, http_version=cap.http_version)
            self.assertEqual(fo.status, fe.UNATTESTABLE)
            self.assertIn(fe.CANONICAL_REJECT_REASON, fo.reasons)
            self.assertNotEqual(fo.status, fe.PROFILE_MATCHED)
        finally:
            await o.aclose()

    async def test_http_1_1_matches_but_http_1_0_does_not_through_the_real_path(self):
        # Real capture -> worker -> evaluate. A clean GET that canonicalizes OK+ACCEPT reaches
        # PROFILE_MATCHED on HTTP/1.1, but the SAME request on HTTP/1.0 is UNATTESTABLE
        # (HTTP_VERSION_NOT_11) — the version is carried from the one snapshot, not inferred.
        o = obs_mod.build_process_observer(sys.executable, 5.0, 10.0, 0.0, 3)
        try:
            o.prewarm()
            if o._start_task is not None:
                await o._start_task

            async def run(version):
                r = tutils.treq(method=b"GET", path=b"/health", authority=b"",
                                http_version=version, headers=http.Headers([(b"Host", b"h")]),
                                content=b"")
                cap = o.capture(r, profile=profile(), profile_generation=1)
                obs = await o.run_captured(cap)
                self.assertEqual(obs.status, obs_mod.OK)
                self.assertEqual(obs.outcome, "ACCEPT")
                return cap, fe.evaluate(profile=cap.profile, gen_at_capture=cap.profile_generation,
                                        gen_at_reply=1, canonical_obs=obs, form=cap.form,
                                        canonical_available=True, http_version=cap.http_version)

            cap11, fo11 = await run(b"HTTP/1.1")
            self.assertEqual(cap11.http_version, "HTTP/1.1")
            self.assertEqual(fo11.status, fe.PROFILE_MATCHED)

            cap10, fo10 = await run(b"HTTP/1.0")
            self.assertEqual(cap10.http_version, "HTTP/1.0")
            self.assertEqual(fo10.status, fe.UNATTESTABLE)
            self.assertIn(fe.HTTP_VERSION_NOT_11, fo10.reasons)
        finally:
            await o.aclose()


if __name__ == "__main__":
    unittest.main()
