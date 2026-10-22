"""
firewall-IA — tests for the wire-evidence harness (scripts/wire_evidence/harness.py), issue #68 §8.

Two layers:
  * Deterministic, no-network / loopback-only tests of the harness plumbing (vector catalogue,
    raw-socket client <-> upstream sink fidelity, outcome classification) and of the project-owned
    contract control via contract_level_residual().
  * One GUARDED live integration test that boots the real mitmdump lab profile and asserts that a
    valid request forwards while an R1 smuggling vector is rejected at the wire. It is SKIPPED when
    mitmdump is unavailable or cannot start, so the suite never hangs on a locked-down environment;
    the skip reason is explicit.

Run under the data-plane interpreter:
    .venv-dataplane/bin/python -I -m pytest tests/test_wire_evidence_harness.py
or  .venv-dataplane/bin/python -I -m unittest tests.test_wire_evidence_harness
"""
import os
import sys
import tempfile
import time
import unittest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "scripts", "wire_evidence"))

import harness as H  # noqa: E402


class TestVectorCatalogue(unittest.TestCase):
    def test_every_vector_has_exact_bytes_and_a_known_group(self):
        vectors = H.all_vectors()
        self.assertGreaterEqual(len(vectors), 20)
        for v in vectors:
            self.assertIsInstance(v.raw, bytes)
            self.assertTrue(v.raw, f"{v.vid} has empty bytes")
            self.assertIn(v.group, ("R1", "R2", "P4", "P9", "VALID", "DRIFT"))
            self.assertTrue(v.justification and v.description)

    def test_every_reject_vector_names_a_valid_counterpart_that_exists(self):
        by_id = {v.vid: v for v in H.all_vectors()}
        for v in H.all_vectors():
            if v.group in ("R1", "R2") and v.counterpart is not None:
                self.assertIn(v.counterpart, by_id, f"{v.vid} -> missing counterpart {v.counterpart}")
                self.assertEqual(by_id[v.counterpart].group, "VALID")

    def test_r1_and_r2_are_distinct_groups(self):
        groups = {v.vid: v.group for v in H.all_vectors()}
        self.assertEqual(groups["R2-TE-GZIP"], "R2")
        self.assertEqual(groups["R1-TECL"], "R1")

    def test_legal_ows_content_length_is_a_valid_vector_not_an_invalid_cl(self):
        v = {x.vid: x for x in H.all_vectors()}["VALID-CL-OWS"]
        self.assertEqual(v.group, "VALID")
        self.assertIn(b"Content-Length:  5 ", v.raw)   # legal OWS around the value

    def test_p9_bodies_are_real_gzip_with_matching_content_length(self):
        import re
        for v in H.all_vectors():
            if v.group == "P9":
                head, body = v.raw.split(b"\r\n\r\n", 1)
                m = re.search(rb"Content-Length: (\d+)", head)
                self.assertIsNotNone(m, v.vid)
                self.assertEqual(int(m.group(1)), len(body), v.vid)
                self.assertEqual(body[:2], b"\x1f\x8b", f"{v.vid} not gzip-framed")


class TestClassify(unittest.TestCase):
    def _cr(self, status=None, reset=False, timed_out=False, error=None):
        return H.ClientResult(10, b"", None, status, reset, timed_out, error, 1.0)

    def test_upstream_delivery_is_normalized_forward_not_r1_enforcement(self):
        self.assertEqual(H.classify(self._cr(status=200), True, True), H.OUT_NORMALIZED_FORWARD)

    def test_4xx_without_delivery_is_parser_reject(self):
        self.assertEqual(H.classify(self._cr(status=400), False, False), H.OUT_PARSER_REJECT)

    def test_403_is_addon_block_and_503_is_fail_closed(self):
        self.assertEqual(H.classify(self._cr(status=403), False, True), H.OUT_ADDON_BLOCK)
        self.assertEqual(H.classify(self._cr(status=503), False, True), H.OUT_FAIL_CLOSED)

    def test_reset_and_timeout_without_response(self):
        self.assertEqual(H.classify(self._cr(reset=True), False, False), H.OUT_CONN_RESET)
        self.assertEqual(H.classify(self._cr(timed_out=True), False, False), H.OUT_TIMEOUT)


class TestClientSinkFidelity(unittest.TestCase):
    """The raw client must deliver EXACT bytes and the sink must record what it actually received —
    including duplicate headers a convenience HTTP client would collapse."""

    def setUp(self):
        self.sink = H.UpstreamSink()
        self.sink.start()
        self.client = H.RawClient(H.LOOPBACK, self.sink.port, deadline_s=3.0)

    def tearDown(self):
        self.sink.stop()

    def test_sink_records_body_length_and_headers_in_order(self):
        self.client.send(b"POST /thing HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhello")
        time.sleep(0.3)
        recs = self.sink.drain()
        self.assertEqual(len(recs), 1)
        r = recs[0]
        self.assertEqual(r.request_line, "POST /thing HTTP/1.1")
        self.assertEqual(r.header_names, ["Host", "Content-Length"])
        self.assertEqual(r.body_len, 5)

    def test_sink_preserves_duplicate_content_length_headers(self):
        # A raw client can place two CL lines on the wire; a convenience client cannot. The sink must
        # SEE both, which is the whole point of observing divergence rather than trusting a library.
        self.client.send(b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello")
        time.sleep(0.3)
        recs = self.sink.drain()
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].header_names.count("Content-Length"), 2)

    def test_sink_dechunks_a_chunked_body_and_reports_payload_length(self):
        self.client.send(b"POST /x HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"
                         b"5\r\nhello\r\n0\r\n\r\n")
        time.sleep(0.3)
        recs = self.sink.drain()
        self.assertEqual(len(recs), 1)
        self.assertTrue(recs[0].chunked)
        self.assertEqual(recs[0].body_len, 5)


class TestByteIdentity(unittest.TestCase):
    """P9 preservation must be BYTE identity, not length. SHA-256 lives in the TEST harness only;
    the production observer never hashes request bytes."""

    def test_equal_length_different_bytes_fails_identity(self):
        # The whole point: 54==54 length is not identity. Four bytes vs four different bytes.
        self.assertFalse(H.bodies_identical(b"AAAA", H.body_sha256(b"BBBB")))
        self.assertTrue(H.bodies_identical(b"AAAA", H.body_sha256(b"AAAA")))

    def test_none_received_sha_is_not_identical(self):
        self.assertFalse(H.bodies_identical(b"AAAA", None))

    def test_sink_body_sha_matches_sent_bytes_over_loopback(self):
        sink = H.UpstreamSink()
        sink.start()
        try:
            client = H.RawClient(H.LOOPBACK, sink.port, deadline_s=3.0)
            import gzip
            body = gzip.compress(b"alpha=1") + gzip.compress(b"&beta=2")
            raw = (b"POST /x HTTP/1.1\r\nHost: h\r\nContent-Length: "
                   + str(len(body)).encode() + b"\r\n\r\n" + body)
            client.send(raw)
            time.sleep(0.3)
            recs = sink.drain()
            self.assertEqual(len(recs), 1)
            self.assertEqual(recs[0].body_len, len(body))
            self.assertTrue(H.bodies_identical(H.client_body(raw), recs[0].body_sha256))
            # And a different equal-length body would NOT match this received sha.
            other = gzip.compress(b"gamma=3")
            if len(other) == len(body):   # usually not; guard the assertion either way
                self.assertFalse(H.bodies_identical(other, recs[0].body_sha256))
        finally:
            sink.stop()


class TestContractLevelResidual(unittest.TestCase):
    """The project-owned canonical_request.canonicalize() control on parts that survive parsing.
    This is NOT wire evidence; it pins the residual-R1/R2/R4 outcomes the contract must give."""

    def setUp(self):
        self.by_case = {c["case"]: c for c in H.contract_level_residual()}

    def test_residual_r1_rejects(self):
        for case, reason in [("R1-TECL", "framing-te-and-cl"),
                             ("R1-DUPCL-EQ", "framing-duplicate-cl"),
                             ("R1-BADCL-HEX", "framing-invalid-cl"),
                             ("R1-MULTITE", "framing-multiple-te"),
                             ("R1-TE-EMPTY", "framing-te-empty"),
                             ("R1-TE10", "framing-te-on-http10"),
                             ("R1-CHUNK-NONFINAL", "framing-chunked-not-final")]:
            c = self.by_case[case]
            self.assertEqual((c["outcome"], c["reject"], c["reason"]), ("REJECT", "R1", reason), case)

    def test_r2_is_distinct_from_r1(self):
        c = self.by_case["R2-TE-GZIP"]
        self.assertEqual((c["outcome"], c["reject"]), ("REJECT", "R2"))

    def test_legal_ows_content_length_is_accepted_by_the_contract(self):
        self.assertEqual(self.by_case["R1-CL-OWS-VALID"]["outcome"], "ACCEPT")

    def test_r4_obstext_and_htab_accept_but_crlf_rejects(self):
        self.assertEqual(self.by_case["R4-OBSTEXT-VALID"]["outcome"], "ACCEPT")
        self.assertEqual(self.by_case["R4-HTAB-VALID"]["outcome"], "ACCEPT")
        c = self.by_case["R4-CRLF-REJECT"]
        self.assertEqual((c["outcome"], c["reject"]), ("REJECT", "R4"))


# ─────────────────────────── v2: framing observer (Track B) ───────────────────────────
#
# The v2 lab (run_wire_evidence_v2.py) adds the shadow FRAMING observer on top of the canonical
# observer and records five separate per-vector dimensions. The tests below cover, WITHOUT needing a
# live proxy: the LabProfile plumbing that turns framing on, the v2 runner's log parsing/attribution,
# and the framing_evidence.evaluate semantics (a conservative producer of PROFILE_MATCHED). Two items
# are UNIT SIMULATIONS, clearly labelled as such, because the live lab cannot interleave them
# deterministically: (a) generation DRIFT between a request's capture and its reply, and (b) a runtime
# configure()→generation BUMP. The live lab DOES establish the generation baseline for real.


def _import_framing():
    """framing_evidence + canonical_observer live under data_plane/ and need mitmproxy-free stdlib
    only; import lazily so the no-network suite still imports under any interpreter."""
    import importlib
    sys.path.insert(0, os.path.join(REPO, "data_plane"))
    return (importlib.import_module("framing_evidence"),
            importlib.import_module("canonical_observer"),
            importlib.import_module("canonical_adapter"))


class TestLabProfileFramingPlumbing(unittest.TestCase):
    """The framing switch must flow into the lab env as WIRE_LAB_FRAMING and must NOT alter the
    mitmdump argv (framing is a gateway/addon concern, read from the environment by lab_addon)."""

    def test_framing_flag_sets_env_and_defaults_off(self):
        # Same listen_port for both so the only possible argv difference would be framing itself.
        on = H.LabProfile(sink_url="http://127.0.0.1:1", classifier_url="http://127.0.0.1:2",
                          observer=True, framing=True, listen_port=55555)
        off = H.LabProfile(sink_url="http://127.0.0.1:1", classifier_url="http://127.0.0.1:2",
                           observer=True, listen_port=55555)
        self.assertEqual(on.env()["WIRE_LAB_FRAMING"], "1")
        self.assertEqual(off.env()["WIRE_LAB_FRAMING"], "0")   # default-off
        self.assertEqual(on.argv(), off.argv())                # framing never changes the proxy argv


class TestV2LogParsing(unittest.TestCase):
    """The v2 runner attributes CANONICAL/FRAMING lines to vectors by parsing the fully-flushed log
    into ordered flows. Pin the parser on a synthetic log slice (no proxy)."""

    def setUp(self):
        sys.path.insert(0, os.path.join(REPO, "scripts", "wire_evidence"))
        import importlib
        self.R = importlib.import_module("run_wire_evidence_v2")

    def test_parse_canonical_and_framing_fragments(self):
        c = self.R._parse_canonical(
            "CANONICAL OBS OK outcome=REJECT reject=R4 reason=field-value-cr-lf-nul target_form=origin")
        self.assertEqual((c["status"], c["outcome"], c["reject"]), ("OK", "REJECT", "R4"))
        f = self.R._parse_framing(
            "FRAMING OBS UNATTESTABLE reasons=CANONICAL_REJECT canonical_status=OK "
            "canonical_outcome=REJECT target_form=origin gen=0")
        self.assertEqual(f["status"], "UNATTESTABLE")
        self.assertEqual(f["reasons"], ["CANONICAL_REJECT"])
        self.assertEqual(f["canonical_outcome"], "REJECT")

    def test_flows_parsed_in_order_and_keyed_by_tag(self):
        log = (
            "[00:00:00.000] [aaaaaaaa] received GET 127.0.0.1:9/ok (body 0 bytes)\n"
            "[00:00:00.001] [aaaaaaaa] CANONICAL OBS OK outcome=ACCEPT target_form=origin\n"
            "[00:00:00.001] [aaaaaaaa] FRAMING OBS PROFILE_MATCHED canonical_status=OK "
            "canonical_outcome=ACCEPT target_form=origin gen=0\n"
            "[00:00:00.100] [bbbbbbbb] received OPTIONS 127.0.0.1:9* (body 0 bytes)\n"
            "[00:00:00.101] [bbbbbbbb] CANONICAL OBS OK outcome=ACCEPT target_form=asterisk\n"
            "[00:00:00.101] [bbbbbbbb] FRAMING OBS PROFILE_MATCHED canonical_status=OK "
            "canonical_outcome=ACCEPT target_form=asterisk gen=0\n")
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as fh:
            fh.write(log)
            path = fh.name
        try:
            flows = self.R._parse_flows(path)
            self.assertEqual([f["tag"] for f in flows], ["aaaaaaaa", "bbbbbbbb"])
            self.assertEqual(flows[0]["method"], "GET")
            self.assertEqual(flows[1]["method"], "OPTIONS")
            self.assertEqual(flows[1]["target"], "*")
            self.assertEqual(flows[0]["framing"]["status"], "PROFILE_MATCHED")
        finally:
            os.unlink(path)

    def test_attach_observations_skips_warmup_and_maps_in_order(self):
        # Two vectors reach the addon; the log has THREE flows (1 warm-up + 2). The warm-up is skipped
        # and the remaining flows map 1:1 in order; a method match is recorded.
        results = [
            {"vid": "V1", "dimensions": {"3_reachability": {"addon_reached": True},
                                         "4_canonical": None, "5_framing": None},
             "_expected_method": "GET"},
            {"vid": "V2", "dimensions": {"3_reachability": {"addon_reached": True},
                                         "4_canonical": None, "5_framing": None},
             "_expected_method": "OPTIONS"},
            {"vid": "REJ", "dimensions": {"3_reachability": {"addon_reached": False},
                                          "4_canonical": None, "5_framing": None},
             "_expected_method": "POST"},
        ]
        flows = [
            {"tag": "warm", "method": "GET", "target": "/ok", "canonical": None, "framing": None},
            {"tag": "t1", "method": "GET", "target": "/ok",
             "canonical": {"status": "OK", "outcome": "ACCEPT", "reject": None},
             "framing": {"status": "PROFILE_MATCHED", "reasons": []}},
            {"tag": "t2", "method": "OPTIONS", "target": "*",
             "canonical": {"status": "OK", "outcome": "ACCEPT", "reject": None},
             "framing": {"status": "PROFILE_MATCHED", "reasons": []}},
        ]
        rep = self.R.attach_observations(results, flows)
        self.assertEqual(rep["assumed_warmup_flows"], 1)
        self.assertFalse(rep["count_skew"])
        self.assertEqual(rep["method_mismatches"], [])
        self.assertEqual(results[0]["dimensions"]["5_framing"]["status"], "PROFILE_MATCHED")
        self.assertEqual(results[1]["correlation"]["flow_tag"], "t2")
        # The parser-rejected vector got no observation attached (addon never ran).
        self.assertIsNone(results[2]["dimensions"]["4_canonical"])


class TestFramingEvaluateSemantics(unittest.TestCase):
    """framing_evidence.evaluate is the ONLY producer of PROFILE_MATCHED and is conservative. These
    pin the honesty-critical conclusions the v2 lab relies on."""

    def setUp(self):
        self.fe, self.co, self.ad = _import_framing()
        self.tested = self.fe.FramingProfile(
            mitmproxy_version=self.fe.TESTED_MITMPROXY_VERSION, validate_inbound_headers=True,
            http2=False, stream_large_bodies=None, body_size_limit=None,
            mode=self.fe.MODE_REVERSE_LOOPBACK, connection_strategy="lazy")

    def _obs(self, **kw):
        return self.co.CanonicalObservation(**kw)

    def test_tested_profile_accept_origin_is_profile_matched(self):
        self.assertTrue(self.tested.is_tested_profile())
        r = self.fe.evaluate(profile=self.tested, gen_at_capture=0, gen_at_reply=0,
                             canonical_obs=self._obs(status=self.co.OK, outcome="ACCEPT",
                                                     target_form=self.ad.FORM_ORIGIN),
                             form=self.ad.FORM_ORIGIN, canonical_available=True,
                             http_version="HTTP/1.1")
        self.assertEqual((r.status, r.reasons), (self.fe.PROFILE_MATCHED, ()))

    def test_bare_lf_may_reach_profile_matched_wire_unverified(self):
        # bare-LF is a WIRE fact canonicalize never sees; it ACCEPTs the normalized parts, so framing
        # MAY be PROFILE_MATCHED under the limited semantics — yet wire verification is unavailable.
        r = self.fe.evaluate(profile=self.tested, gen_at_capture=0, gen_at_reply=0,
                             canonical_obs=self._obs(status=self.co.OK, outcome="ACCEPT",
                                                     target_form=self.ad.FORM_ORIGIN),
                             form=self.ad.FORM_ORIGIN, canonical_available=True,
                             http_version="HTTP/1.1")
        self.assertEqual(r.status, self.fe.PROFILE_MATCHED)   # documented, not a wire attestation

    def test_obsfold_r4_is_unattestable_canonical_reject_never_relabelled(self):
        r = self.fe.evaluate(profile=self.tested, gen_at_capture=0, gen_at_reply=0,
                             canonical_obs=self._obs(status=self.co.OK, outcome="REJECT", reject="R4",
                                                     target_form=self.ad.FORM_ORIGIN),
                             form=self.ad.FORM_ORIGIN, canonical_available=True,
                             http_version="HTTP/1.1")
        self.assertEqual(r.status, self.fe.UNATTESTABLE)
        self.assertIn(self.fe.CANONICAL_REJECT_REASON, r.reasons)

    def test_absolute_form_is_unavailable_out_of_scope_not_a_positive(self):
        r = self.fe.evaluate(profile=self.tested, gen_at_capture=0, gen_at_reply=0,
                             canonical_obs=self._obs(status=self.co.OUT_OF_SCOPE,
                                                     detail=self.ad.SCOPE_ABSOLUTE,
                                                     target_form=self.ad.FORM_ABSOLUTE),
                             form=self.ad.FORM_ABSOLUTE, canonical_available=True,
                             http_version="HTTP/1.1")
        self.assertEqual(r.status, self.fe.UNAVAILABLE)
        self.assertIn(self.fe.TARGET_FORM_OUT_OF_SCOPE, r.reasons)

    def test_no_canonical_observer_is_unavailable(self):
        r = self.fe.evaluate(profile=None, gen_at_capture=0, gen_at_reply=0, canonical_obs=None,
                             form=None, canonical_available=False, http_version=None)
        self.assertEqual(r.status, self.fe.UNAVAILABLE)
        self.assertIn(self.fe.NO_CANONICAL_OBSERVER, r.reasons)

    def test_generation_drift_capture_ne_reply_is_unattestable_UNIT_SIMULATION(self):
        # UNIT SIMULATION of the capture!=reply drift path. The live lab cannot deterministically
        # change an option in the sub-ms window between a request's capture and its worker reply, so
        # this conclusion is pinned here, separate from the real-lab runs.
        r = self.fe.evaluate(profile=self.tested, gen_at_capture=0, gen_at_reply=1,
                             canonical_obs=self._obs(status=self.co.OK, outcome="ACCEPT",
                                                     target_form=self.ad.FORM_ORIGIN),
                             form=self.ad.FORM_ORIGIN, canonical_available=True,
                             http_version="HTTP/1.1")
        self.assertEqual(r.status, self.fe.UNATTESTABLE)
        self.assertIn(self.fe.GENERATION_DRIFT, r.reasons)

    def test_vih_off_profile_is_unattestable_not_tested(self):
        off = self.fe.FramingProfile(
            mitmproxy_version=self.fe.TESTED_MITMPROXY_VERSION, validate_inbound_headers=False,
            http2=False, stream_large_bodies=None, body_size_limit=None,
            mode=self.fe.MODE_REVERSE_LOOPBACK, connection_strategy="lazy")
        r = self.fe.evaluate(profile=off, gen_at_capture=0, gen_at_reply=0,
                             canonical_obs=self._obs(status=self.co.OK, outcome="REJECT", reject="R1",
                                                     target_form=self.ad.FORM_ORIGIN),
                             form=self.ad.FORM_ORIGIN, canonical_available=True,
                             http_version="HTTP/1.1")
        self.assertEqual(r.status, self.fe.UNATTESTABLE)
        self.assertIn(self.fe.VALIDATE_INBOUND_HEADERS_OFF, r.reasons)
        self.assertIn(self.fe.PROFILE_NOT_TESTED, r.reasons)

    # ── D70 defect A: version boundary (PROFILE_MATCHED requires EXACTLY HTTP/1.1) ──
    def test_http10_in_scope_accept_is_unattestable_version_not_11(self):
        # HTTP/1.0 is IN adapter scope and canonicalizes OK+ACCEPT, but the corrected evaluator must
        # refuse the positive: UNATTESTABLE / HTTP_VERSION_NOT_11 (NOT the OUT_OF_SCOPE path, which is
        # reserved for HTTP/2+). This is the unit counterpart of the live VALID-HTTP10 vector.
        r = self.fe.evaluate(profile=self.tested, gen_at_capture=0, gen_at_reply=0,
                             canonical_obs=self._obs(status=self.co.OK, outcome="ACCEPT",
                                                     target_form=self.ad.FORM_ORIGIN),
                             form=self.ad.FORM_ORIGIN, canonical_available=True,
                             http_version="HTTP/1.0")
        self.assertEqual(r.status, self.fe.UNATTESTABLE)
        self.assertIn(self.fe.HTTP_VERSION_NOT_11, r.reasons)
        self.assertNotIn(self.fe.HTTP_VERSION_OUT_OF_SCOPE, r.reasons)

    def test_http11_positive_is_unchanged_by_the_version_fix(self):
        r = self.fe.evaluate(profile=self.tested, gen_at_capture=0, gen_at_reply=0,
                             canonical_obs=self._obs(status=self.co.OK, outcome="ACCEPT",
                                                     target_form=self.ad.FORM_ORIGIN),
                             form=self.ad.FORM_ORIGIN, canonical_available=True,
                             http_version="HTTP/1.1")
        self.assertEqual((r.status, r.reasons), (self.fe.PROFILE_MATCHED, ()))

    def test_http2_unsupported_version_stays_on_out_of_scope_path(self):
        # An adapter-out-of-scope version (canonical OUT_OF_SCOPE/unsupported_http_version) stays
        # UNAVAILABLE/HTTP_VERSION_OUT_OF_SCOPE — distinct from the in-scope HTTP/1.0 case above.
        r = self.fe.evaluate(profile=self.tested, gen_at_capture=0, gen_at_reply=0,
                             canonical_obs=self._obs(status=self.co.OUT_OF_SCOPE,
                                                     detail=self.ad.SCOPE_UNSUPPORTED_VERSION,
                                                     target_form=self.ad.FORM_ORIGIN),
                             form=self.ad.FORM_ORIGIN, canonical_available=True,
                             http_version="HTTP/2")
        self.assertEqual(r.status, self.fe.UNAVAILABLE)
        self.assertIn(self.fe.HTTP_VERSION_OUT_OF_SCOPE, r.reasons)

    # ── D70 defect B: mode validation is transport+address (confirm the lab profile stays tested) ──
    def test_lab_reverse_http_loopback_mode_is_still_the_tested_profile(self):
        class _Opts:
            validate_inbound_headers = True
            http2 = False
            stream_large_bodies = None
            body_size_limit = None
            mode = ["reverse:http://127.0.0.1:0"]   # the lab's transport+address
            connection_strategy = "lazy"
        p = self.fe.sample_profile(_Opts(), self.fe.TESTED_MITMPROXY_VERSION)
        self.assertTrue(p.is_tested_profile())   # lab profile still matches tested after defect B

    def test_https_and_nonloopback_reverse_modes_are_not_the_tested_profile(self):
        def prof(mode):
            class _Opts:
                validate_inbound_headers = True
                http2 = False
                stream_large_bodies = None
                body_size_limit = None
                connection_strategy = "lazy"
            _Opts.mode = [mode]
            return self.fe.sample_profile(_Opts(), self.fe.TESTED_MITMPROXY_VERSION)
        # https transport, http3, and a non-loopback address must NOT be the tested profile.
        self.assertFalse(prof("reverse:https://127.0.0.1:0").is_tested_profile())
        self.assertFalse(prof("reverse:http://10.0.0.1:0").is_tested_profile())


class TestGatewayConfigureGenerationBump(unittest.TestCase):
    """UNIT SIMULATION of the integrated gateway's configure()→generation path. This drives the REAL
    FirewallGateway.configure() hook (not RelevantProfileGeneration in isolation) with a changing
    mitmproxy options object and asserts the relevant-profile generation bumps — including A→B→A as
    TWO bumps. The live lab establishes the generation BASELINE for real at startup; it cannot be made
    to change an option deterministically mid-request, so the bump is exercised here."""

    def _gateway_and_ctx(self):
        try:
            sys.path.insert(0, os.path.join(REPO, "data_plane"))
            import importlib
            dp = importlib.import_module("data_plane")
        except Exception as exc:  # noqa: BLE001 — needs the data-plane venv (mitmproxy/httpx)
            self.skipTest(f"data_plane import unavailable: {type(exc).__name__}: {exc}")
        return dp

    def test_configure_bumps_generation_on_real_option_change_including_A_B_A(self):
        dp = self._gateway_and_ctx()

        class _Opts:
            def __init__(self, vih):
                self.validate_inbound_headers = vih
                self.http2 = False
                self.stream_large_bodies = None
                self.body_size_limit = None
                self.mode = ["reverse:http://127.0.0.1:0"]
                self.connection_strategy = "lazy"

        class _Ctx:
            options = _Opts(True)

        gw = dp.FirewallGateway("http://127.0.0.1:1", 1.0, framing_observer=True)
        saved = dp.ctx
        dp.ctx = _Ctx()
        try:
            dp.ctx.options = _Opts(True)
            gw.configure(None)                               # baseline (A), no bump
            base = gw._relevant_profile_generation.generation
            dp.ctx.options = _Opts(False)
            gw.configure(None)                               # A -> B : one bump
            dp.ctx.options = _Opts(True)
            gw.configure(None)                               # B -> A : a second bump (change-back)
            self.assertEqual(gw._relevant_profile_generation.generation, base + 2)
        finally:
            dp.ctx = saved

    def test_configure_is_a_noop_when_framing_off(self):
        dp = self._gateway_and_ctx()
        gw = dp.FirewallGateway("http://127.0.0.1:1", 1.0, framing_observer=False)
        before = gw._relevant_profile_generation.generation
        gw.configure(None)   # framing off: nothing sampled, never raises
        self.assertEqual(gw._relevant_profile_generation.generation, before)


def _mitmdump_available() -> bool:
    return os.path.exists(H.MITMDUMP)


@unittest.skipUnless(_mitmdump_available(), "mitmdump not present in .venv-dataplane")
class TestLiveLabProfile(unittest.TestCase):
    """GUARDED live integration: boots the real reverse-proxy lab and checks that a valid request
    forwards while an R1 smuggling vector is rejected at the wire. Skipped (not failed) if mitmdump
    cannot start, so a locked-down sandbox never turns this into a false negative."""

    def setUp(self):
        self.stub = H.ClassifierStub()
        self.sink = H.UpstreamSink()
        self.stub.start()
        self.sink.start()
        self.prof = H.LabProfile(sink_url=self.sink.url, classifier_url=self.stub.url,
                                 validate_inbound_headers=True, observer=False)
        self._tmp = tempfile.NamedTemporaryFile(suffix=".log", delete=False)
        self._tmp.close()
        try:
            self.prof.start(self._tmp.name, startup_deadline_s=20.0)
        except Exception as exc:  # noqa: BLE001
            self.stub.stop(); self.sink.stop()
            self.skipTest(f"mitmdump lab did not start: {type(exc).__name__}: {exc}")

    def tearDown(self):
        self.prof.stop()
        self.stub.stop()
        self.sink.stop()
        try:
            os.unlink(self._tmp.name)
        except OSError:
            pass

    def _send(self, raw):
        client = H.RawClient(H.LOOPBACK, self.prof.listen_port, deadline_s=3.0)
        self.sink.drain()
        r = client.send(raw)
        time.sleep(0.4)
        return r, self.sink.drain()

    def test_valid_request_is_forwarded_to_upstream(self):
        r, recs = self._send(b"GET /ok HTTP/1.1\r\nHost: sink.test\r\n\r\n")
        self.assertEqual(H.classify(r, bool(recs), True), H.OUT_NORMALIZED_FORWARD)
        self.assertEqual(len(recs), 1)

    def test_te_cl_smuggling_vector_is_rejected_at_the_wire(self):
        raw = (b"POST /x HTTP/1.1\r\nHost: s\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n"
               b"5\r\nhello\r\n0\r\n\r\n")
        r, recs = self._send(raw)
        # The parser must NOT forward a TE+CL request under validate_inbound_headers=true.
        self.assertEqual(len(recs), 0, "TE+CL smuggling vector was forwarded upstream")
        self.assertIn(H.classify(r, False, False), (H.OUT_PARSER_REJECT, H.OUT_CONN_RESET))


@unittest.skipUnless(_mitmdump_available(), "mitmdump not present in .venv-dataplane")
class TestLiveFramingObserver(unittest.TestCase):
    """GUARDED live integration for Track B: boots the lab with BOTH observers on and asserts the
    FRAMING OBS lines that the v2 report relies on actually appear in the proxy log:
      * a valid in-scope request -> FRAMING OBS PROFILE_MATCHED
      * an absolute-form request  -> FRAMING OBS UNAVAILABLE (TARGET_FORM_OUT_OF_SCOPE)
    Skipped (not failed) when mitmdump cannot start, so a locked-down sandbox is a disclosed missing
    test, not a false pass."""

    def setUp(self):
        self.stub = H.ClassifierStub()
        self.sink = H.UpstreamSink()
        self.stub.start()
        self.sink.start()
        self.prof = H.LabProfile(sink_url=self.sink.url, classifier_url=self.stub.url,
                                 validate_inbound_headers=True, observer=True, framing=True)
        self._tmp = tempfile.NamedTemporaryFile(suffix=".log", delete=False)
        self._tmp.close()
        try:
            self.prof.start(self._tmp.name, startup_deadline_s=20.0)
        except Exception as exc:  # noqa: BLE001
            self.stub.stop(); self.sink.stop()
            self.skipTest(f"mitmdump lab did not start: {type(exc).__name__}: {exc}")

    def tearDown(self):
        self.prof.stop()
        self.stub.stop()
        self.sink.stop()
        try:
            os.unlink(self._tmp.name)
        except OSError:
            pass

    def _send(self, raw, settle=1.0):
        client = H.RawClient(H.LOOPBACK, self.prof.listen_port, deadline_s=3.0)
        self.sink.drain()
        client.send(raw)
        time.sleep(settle)

    def test_framing_lines_appear_for_valid_and_absolute_form(self):
        # mitmdump BLOCK-BUFFERS its log, so it is read only AFTER the proxy is stopped (same as the
        # v2 runner). One proxy lifetime covers both assertions. Warm the worker first.
        self._send(b"GET /ok HTTP/1.1\r\nHost: sink.test\r\n\r\n")                 # warm
        self._send(b"GET /ok HTTP/1.1\r\nHost: sink.test\r\n\r\n")                 # in-scope valid
        self._send(b"GET http://sink.test/abs-target HTTP/1.1\r\nHost: sink.test\r\n\r\n")  # absform
        self.prof.stop()   # flush the buffered log; tearDown's second stop() is a safe no-op
        with open(self._tmp.name, "r", encoding="utf-8", errors="replace") as f:
            log = f.read()
        # A valid in-scope request -> PROFILE_MATCHED; absolute-form -> UNAVAILABLE / out-of-scope.
        self.assertIn("FRAMING OBS PROFILE_MATCHED", log)
        self.assertIn("FRAMING OBS UNAVAILABLE", log)
        self.assertIn("TARGET_FORM_OUT_OF_SCOPE", log)
        # Honesty: the parser-rejected / fail-closed paths are covered by the runner; here we only
        # assert the two framing lines the report relies on actually come out of the live gateway.


if __name__ == "__main__":
    unittest.main()
