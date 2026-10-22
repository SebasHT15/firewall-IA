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


if __name__ == "__main__":
    unittest.main()
