"""Build-time self-check for the External Test v1 generator image.

Run as the last step of the image build so a broken generator fails at `docker compose
build` rather than halfway through a traffic run — the previous image failed at build for
a distro dependency mismatch, and the class of problem is worth catching early.

Checks:
  1. the installed playwright version equals the pin (which must equal the base image tag);
  2. Chromium is actually present at the path Playwright resolves;
  3. httpx and curl, used by the API and query flows, are available.

Chromium is NOT launched here: launching adds sandbox/shared-memory variables that belong
to run time, not build time, and would make the build fail for reasons unrelated to the
image contents.
"""

import importlib.metadata
import os
import shutil
import sys

EXPECTED_PLAYWRIGHT = "1.49.1"


def main() -> int:
    problems = []

    version = importlib.metadata.version("playwright")
    if version != EXPECTED_PLAYWRIGHT:
        problems.append(
            f"playwright {version} installed, expected {EXPECTED_PLAYWRIGHT}. The base "
            f"image tag and docker/generator/requirements.txt must name the same version.")

    from playwright.sync_api import sync_playwright
    pw = sync_playwright().start()
    try:
        chromium_path = pw.chromium.executable_path
    finally:
        pw.stop()
    if not os.path.exists(chromium_path):
        problems.append(f"chromium not found at {chromium_path}")

    try:
        importlib.metadata.version("httpx")
    except importlib.metadata.PackageNotFoundError:
        problems.append("httpx is not installed")

    if shutil.which("curl") is None:
        problems.append("curl is not on PATH")

    if problems:
        print("generator image verification FAILED:")
        for p in problems:
            print(f"  - {p}")
        return 1

    print(f"generator image OK: playwright {version}, chromium at {chromium_path}, "
          f"httpx and curl present")
    return 0


if __name__ == "__main__":
    sys.exit(main())
