"""Docker Lab demo — static checks over docker/demo.sh.

No Docker daemon, no network, no model. The runtime behaviour of the demo is verified by
running it (docker/README.md, "Demo"); these tests pin the properties that make that run
trustworthy and keep it from drifting:

- it adds no fixtures or assertions of its own: every request goes through the validated
  smoke client (docker/client/smoke_test.py);
- the fail-closed stage keeps the two guards the first Docker Lab validation proved
  necessary: `--no-deps`, and the control plane asserted stopped before AND after the
  request (reports/lab/docker-lab-v1/);
- the clean step removes containers and network only, and covers both profiles, because
  a plain `docker compose down` leaves lab-app running and the network in use;
- it never touches External Test v1, and the smoke destination it drives is not a host
  any frozen External v1 case targets.
"""

import json
import os
import re
import subprocess
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEMO = os.path.join(ROOT, "docker", "demo.sh")
FROZEN_CASES = os.path.join(ROOT, "datasets", "external_v1", "cases.jsonl")


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def instructions(script: str) -> str:
    """Only the executable lines, comments stripped: the header explains in prose what
    the script must never do, and assertions are about what it DOES."""
    return "\n".join(line for line in script.splitlines()
                     if line.strip() and not line.lstrip().startswith("#"))


class TestDemoScript(unittest.TestCase):
    def setUp(self):
        self.script = read(DEMO)
        self.code = instructions(self.script)

    def test_is_valid_bash(self):
        result = subprocess.run(["bash", "-n", DEMO], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_is_executable(self):
        self.assertTrue(os.access(DEMO, os.X_OK), "docker/demo.sh must be executable")

    def test_stages_in_order_and_final_verdict(self):
        positions = [self.code.find(f"stage {i}/5 ") for i in range(1, 6)]
        self.assertNotIn(-1, positions, "every [n/5] stage must be present")
        self.assertEqual(positions, sorted(positions), "stages must run in order 1..5")
        self.assertIn("DEMO PASS", self.code)
        self.assertIn("DEMO FAIL", self.code)
        self.assertIn("exit 1", self.code, "a failed stage must exit non-zero")

    def test_every_request_goes_through_the_smoke_client(self):
        phases = re.findall(r"^client_phase \S+ (\w+)", self.code, re.M)
        self.assertEqual(phases, ["allow", "block", "failclosed", "allow"])
        self.assertIn("$COMPOSE run --rm", self.code)
        self.assertRegex(self.code, r'run --rm "\$@" client "\$phase"')

    def test_defines_no_fixtures_of_its_own(self):
        for fixture_marker in ("app.fwlab.test", "products.html", "index.html", "?id=",
                               "curl ", "urllib.request.urlopen('http://data-plane"):
            self.assertNotIn(fixture_marker, self.code,
                             f"demo must reuse the smoke fixtures, found {fixture_marker!r}")

    def test_fail_closed_uses_no_deps_and_only_there(self):
        self.assertRegex(self.code, r"(?m)^client_phase 4/5 failclosed --no-deps$")
        no_deps_lines = [l for l in self.code.splitlines() if "--no-deps" in l]
        self.assertEqual(len(no_deps_lines), 1, no_deps_lines)

    def test_fail_closed_asserts_control_plane_stopped_before_and_after(self):
        stage4 = self.code.split("stage 4/5 ", 1)[1].split("stage 5/5 ", 1)[0]
        before, _, after = stage4.partition("client_phase 4/5 failclosed")
        self.assertIn("$COMPOSE stop control-plane", before)
        self.assertRegex(before, r"state=\$\(service_state control-plane\)")
        self.assertRegex(before, r'\[ "\$state" != running \] \|\| die')
        self.assertRegex(after, r"state=\$\(service_state control-plane\)")
        self.assertRegex(after, r'\[ "\$state" != running \] \|\| die')

    def test_clean_step_covers_both_profiles_and_is_non_destructive(self):
        self.assertIn("--profile smoke --profile extv1 down --remove-orphans", self.code)
        for destructive in (" -v", "--volumes", "--rmi", "rm -rf", "prune", "git "):
            self.assertNotIn(destructive, self.code, f"found {destructive!r}")

    def test_never_touches_external_v1_or_reports(self):
        for path in ("datasets/", "external_v1", "reports/", "scripts/external"):
            self.assertNotIn(path, self.code, f"demo must not reference {path!r}")

    def test_restores_the_control_plane_it_stopped(self):
        self.assertIn("trap restore_control_plane EXIT", self.code)
        self.assertRegex(self.code, r"STOPPED_CONTROL_PLANE=1\n\$COMPOSE stop control-plane")


class TestDemoTrafficIsNotExternalV1(unittest.TestCase):
    """The demo drives the smoke destination. No frozen External v1 case is addressed to
    it, so the live demo can never be a replay of a frozen case. Read-only."""

    def test_no_frozen_case_targets_the_smoke_destination(self):
        with open(FROZEN_CASES, encoding="utf-8") as f:
            cases = [json.loads(line) for line in f if line.strip()]
        self.assertEqual(len(cases), 400)
        for case in cases:
            host_line = case["request_text"].split("\n")[1]
            self.assertNotEqual(case["host"], "app.fwlab.test", case["case_id"])
            self.assertFalse(host_line.lower().startswith("host: app.fwlab.test"),
                             case["case_id"])


if __name__ == "__main__":
    unittest.main()
