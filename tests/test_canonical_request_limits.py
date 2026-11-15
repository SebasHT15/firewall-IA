"""Resource-bound tests for the content decoders of `data_plane/canonical_request.py` (D63).

Local, bounded cases only: no network, no gateway. Every cap is a TEST VALUE; the production
`MAX_DECODED_BODY` is PENDING (integration). What is asserted:
  * output bound per coding: gzip/deflate <= cap + 1, br <= cap + 32,752, zstd <= cap + 17 x 128 KiB
    (measured at every cap check by wrapping `_check_cap`);
  * linear time on bodies made of many tiny gzip members / zstd frames (was quadratic);
  * a zstd frame declaring a 128 MiB window is still bounded by the cap (no window reject);
  * peak RSS of a decompression bomb, in a fresh subprocess, stays far below the bomb size.

    .venv-dataplane/bin/python -m unittest tests.test_canonical_request_limits -v
"""

import gzip
import os
import subprocess
import sys
import time
import unittest
import zlib
from unittest import mock

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PLANE_DIR = os.path.join(REPO, "data_plane")
sys.path.insert(0, DATA_PLANE_DIR)

import canonical_request as cr  # noqa: E402

try:
    import brotli
except ImportError:
    brotli = None
try:
    import zstandard
except ImportError:
    zstandard = None

CAP = 1 << 20  # TEST VALUE
BOMB = 64 << 20  # 64 MiB of zeros, compressed to a few KiB
BOUNDS = {"gzip": 1, "deflate": 1, "br": 32752, "zstd": 17 * 128 * 1024}


def _encode(coding, raw):
    if coding == "gzip":
        return gzip.compress(raw)
    if coding == "deflate":
        return zlib.compress(raw)
    if coding == "br":
        return brotli.compress(raw, quality=5)
    return zstandard.ZstdCompressor().compress(raw)


def _canon(body, coding, cap=CAP):
    parts = cr.RequestParts(b"POST", b"/x", "HTTP/1.1",
                            ((b"Content-Type", b"text/plain"), (b"Content-Encoding", coding.encode())), body)
    return cr.canonicalize(parts, cr.Limits(max_decoded_body=cap))


def _available(coding):
    return {"br": brotli, "zstd": zstandard}.get(coding, True) is not None


class OutputBound(unittest.TestCase):
    def test_bomb_output_never_exceeds_documented_bound(self):
        for coding, slack in BOUNDS.items():
            if not _available(coding):
                continue
            body = _encode(coding, b"\x00" * BOMB)
            seen = []
            real = cr._check_cap

            def spy(out, cap):
                seen.append(len(out))
                real(out, cap)

            with mock.patch.object(cr, "_check_cap", spy):
                r = _canon(body, coding)
            self.assertEqual((r.reject, r.reason), ("R8", "decoded-body-over-cap"), coding)
            self.assertLessEqual(max(seen), CAP + slack, coding)

    def test_exact_cap_passes_and_cap_plus_one_rejected(self):
        for coding in BOUNDS:
            if not _available(coding):
                continue
            ok = _canon(_encode(coding, b"a" * CAP), coding)
            self.assertEqual(ok.outcome, cr.ACCEPT, coding)
            self.assertEqual(ok.audit["decoded_body_bytes"], CAP)
            self.assertEqual(_canon(_encode(coding, b"a" * (CAP + 1)), coding).reject, "R8", coding)


class LinearTime(unittest.TestCase):
    def _ratio(self, unit, coding):
        times = []
        for n in (20_000, 80_000):
            t = time.perf_counter()
            r = _canon(unit * n, coding, cap=1 << 24)
            times.append(time.perf_counter() - t)
            self.assertEqual(r.outcome, cr.ACCEPT)
        return times

    def test_many_gzip_members_linear(self):
        small, large = self._ratio(gzip.compress(b""), "gzip")
        self.assertLess(large, 2.0)
        self.assertLess(large / max(small, 1e-3), 8)  # 4x input: linear ~4x, quadratic ~16x

    @unittest.skipIf(zstandard is None, "zstandard not installed")
    def test_many_zstd_frames_linear(self):
        small, large = self._ratio(zstandard.ZstdCompressor().compress(b""), "zstd")
        self.assertLess(large, 2.0)
        self.assertLess(large / max(small, 1e-3), 8)

    @unittest.skipIf(brotli is None, "brotli not installed")
    def test_large_brotli_body_linear(self):
        # Regression (decoder review, D63): feeding the whole body to Brotli at once made every
        # one-block drain step re-scan the buffered input (64 MB took 15 s). Now sliced input.
        raw = os.urandom(32 << 20)
        body = brotli.compress(raw, quality=0)
        t = time.perf_counter()
        r = _canon(body, "br", cap=64 << 20)
        self.assertLess(time.perf_counter() - t, 3.0)
        self.assertEqual(r.audit["decoded_body_bytes"], len(raw))

    def test_gzip_nul_padding_run_linear(self):
        body = gzip.compress(b"k=v") + b"\x00" * (8 << 20)
        t = time.perf_counter()
        self.assertEqual(_canon(body, "gzip").outcome, cr.ACCEPT)
        self.assertLess(time.perf_counter() - t, 1.0)


@unittest.skipIf(zstandard is None, "zstandard not installed")
class ZstdLargeWindow(unittest.TestCase):
    """A frame declaring a 128 MiB window (beyond RFC 9659's 8 MB for HTTP) is not rejected by
    the contract; its cost must still be bounded by the cap (D63: no invented reject)."""

    def test_large_window_frame_bounded_by_cap(self):
        p = zstandard.ZstdCompressionParameters.from_level(1, window_log=27, write_content_size=False)
        co = zstandard.ZstdCompressor(compression_params=p).compressobj()
        frame = b"".join(co.compress(bytes([i % 251]) * (1 << 20)) for i in range(8)) + co.flush()
        self.assertEqual(zstandard.get_frame_parameters(frame).window_size, 128 << 20)
        self.assertEqual(_canon(frame, "zstd").reject, "R8")
        self.assertEqual(_canon(frame, "zstd", cap=8 << 20).outcome, cr.ACCEPT)


@unittest.skipUnless(os.path.exists("/proc/self/status"), "Linux /proc required")
class PeakMemory(unittest.TestCase):
    """Peak RSS growth while rejecting a 64 MiB bomb with a 1 MiB cap (fresh process each)."""
    SCRIPT = r"""
import sys
sys.path.insert(0, sys.argv[1])
import canonical_request as cr
body = sys.stdin.buffer.read()  # the bomb is built by the parent; this process only decodes
coding = sys.argv[2]
p = cr.RequestParts(b"POST", b"/x", "HTTP/1.1", ((b"Content-Encoding", coding.encode()),), body)
def hwm():  # VmHWM: this process's peak RSS in KiB (ru_maxrss would inherit the parent's peak)
    with open("/proc/self/status") as f:
        return next(int(l.split()[1]) for l in f if l.startswith("VmHWM:"))
before = hwm()
r = cr.canonicalize(p, cr.Limits(max_decoded_body=1 << 20))
after = hwm()
print(r.reject, after - before, before)
"""

    def test_bomb_peak_rss_growth_bounded(self):
        # VmHWM is a high-water mark. The child only reads the compressed bomb and decodes
        # it, so the growth during the call is the decoding cost (cap + decoder state). Bound
        # asserted: 32 MiB for a 64 MiB bomb; measured values are in the stage report.
        for coding in BOUNDS:
            if not _available(coding):
                continue
            body = _encode(coding, b"\x00" * BOMB)
            out = subprocess.run([sys.executable, "-c", self.SCRIPT, DATA_PLANE_DIR, coding], input=body,
                                 capture_output=True, check=True, timeout=120).stdout.decode().split()
            self.assertEqual(out[0], "R8", coding)
            self.assertLess(int(out[1]), 32 * 1024, coding)  # KiB on Linux

if __name__ == "__main__":
    unittest.main()
