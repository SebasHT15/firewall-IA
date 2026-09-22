"""External Test v1 — generator image pin consistency.

Static text checks over docker/generator/. No Docker daemon, no network, no image.

These exist because of a real failure: the first generator image pinned
`playwright==1.49.1` on the ROLLING `python:3.12-slim` base, whose Debian release moved
underneath the pin. Playwright's hardcoded per-distro dependency table had no entry for
it, fell back to an Ubuntu package list, and apt failed on `ttf-ubuntu-font-family` and
`ttf-unifont`. The fix pins the vendor image, which ties the Playwright version, Chromium
and the OS together — and that only holds while the tag and the requirement pin agree.
"""

import os
import re
import unittest

GEN_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "docker", "generator")


def read(name):
    with open(os.path.join(GEN_DIR, name), encoding="utf-8") as f:
        return f.read()


def instructions(dockerfile: str) -> str:
    """Only the build instructions, with comments stripped.

    The Dockerfile explains the failure it exists to avoid, so it legitimately mentions
    `--with-deps` and `PLAYWRIGHT_BROWSERS_PATH` in prose. Assertions below are about what
    the build DOES, so they must not read the commentary.
    """
    return "\n".join(line for line in dockerfile.splitlines()
                     if line.strip() and not line.lstrip().startswith("#"))


class TestGeneratorImagePins(unittest.TestCase):
    def setUp(self):
        self.dockerfile = read("Dockerfile")
        self.build = instructions(self.dockerfile)
        self.requirements = read("requirements.txt")
        self.verify = read("verify_image.py")

    def image_tag_version(self):
        m = re.search(r"^FROM mcr\.microsoft\.com/playwright/python:v([0-9.]+)-",
                      self.dockerfile, re.M)
        self.assertIsNotNone(m, "expected an official Playwright python base image")
        return m.group(1)

    def requirement_version(self):
        m = re.search(r"^playwright==([0-9.]+)\s*$", self.requirements, re.M)
        self.assertIsNotNone(m, "expected a pinned playwright requirement")
        return m.group(1)

    def test_base_image_version_matches_the_requirement_pin(self):
        self.assertEqual(
            self.image_tag_version(), self.requirement_version(),
            "the Playwright base image tag and the requirements.txt pin must name the "
            "same version, or pip would replace the version the browsers were built for")

    def test_build_time_check_asserts_the_same_version(self):
        m = re.search(r'EXPECTED_PLAYWRIGHT = "([0-9.]+)"', self.verify)
        self.assertIsNotNone(m)
        self.assertEqual(m.group(1), self.requirement_version())

    def test_does_not_install_browsers_with_apt_dependency_resolution(self):
        # `playwright install --with-deps` is the exact step that failed. The vendor image
        # ships the browsers and their system libraries already.
        self.assertNotIn("--with-deps", self.build)
        self.assertNotIn("playwright install", self.build)

    def test_does_not_override_the_browsers_path(self):
        # The base image installs browsers under /ms-playwright and sets the variable.
        # Overriding it would make Chromium unfindable at runtime.
        self.assertNotIn("PLAYWRIGHT_BROWSERS_PATH", self.build)

    def test_base_image_is_pinned_not_rolling(self):
        self.assertNotRegex(self.build, r"(?m)^FROM .*:latest\s*$")
        self.assertNotRegex(self.build, r"(?m)^FROM python:3\.12-slim\s*$")

    def test_build_verifies_the_image_before_it_is_tagged(self):
        self.assertIn("verify_image.py", self.build)


class TestChromiumContainerFlags(unittest.TestCase):
    """Chromium as root in Docker needs two flags; neither alters emitted HTTP."""

    def setUp(self):
        path = os.path.join(os.path.dirname(GEN_DIR), "..", "scripts", "external",
                            "drive_traffic.py")
        with open(os.path.abspath(path), encoding="utf-8") as f:
            self.source = f.read()

    def test_launch_passes_no_sandbox_and_dev_shm_flags(self):
        self.assertIn("--no-sandbox", self.source)
        self.assertIn("--disable-dev-shm-usage", self.source)

    def test_browser_flow_still_uses_real_chromium(self):
        # Guard against anyone "fixing" a browser problem by swapping in an HTTP client.
        self.assertIn("sync_playwright", self.source)
        self.assertIn("p.chromium.launch", self.source)


if __name__ == "__main__":
    unittest.main()
