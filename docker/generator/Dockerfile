# firewall-IA — Docker Lab `generator`: External Test v1 traffic generation.
#
# Build context: docker/generator (needs nothing from the repository root).
# The scripts themselves are BIND-MOUNTED from scripts/external/ so they can be iterated
# during DRAFT without a rebuild; the image provides only the runtime.
#
# Behind the `extv1` compose profile: `docker compose up` and ./docker/smoke_test.sh are
# unaffected by its existence.
#
# WHY THE OFFICIAL PLAYWRIGHT IMAGE, AND NOT python:*-slim + `playwright install --with-deps`
#   The first attempt built on python:3.12-slim and ran `playwright install --with-deps
#   chromium`. apt failed on `ttf-ubuntu-font-family` and `ttf-unifont` — UBUNTU package
#   names, on a DEBIAN base, where they are `fonts-ubuntu` and `fonts-unifont`. Playwright
#   carries a hardcoded per-distro dependency table; 1.49.1 predates the Debian release
#   that the rolling `python:3.12-slim` tag now resolves to, found no matching entry and
#   fell back to an Ubuntu list.
#
#   Pinning a Debian release would paper over it. This image removes the failure mode
#   instead: the vendor ships Chromium AND its system libraries already installed and
#   version-matched to the Playwright release, so no distro dependency resolution happens
#   at build time at all. The tag also pins the OS, which `python:3.12-slim` does not —
#   that rolling base is what let the distro change underneath a pinned Playwright.
#
#   The tag version MUST equal the pin in requirements.txt. tests/test_generator_image.py
#   asserts that, and the build re-asserts it below.
#
# Ubuntu 24.04 (noble) ships Python 3.12, matching the project's interpreter convention.
FROM mcr.microsoft.com/playwright/python:v1.49.1-noble

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# PLAYWRIGHT_BROWSERS_PATH is deliberately NOT set. The base image installs the browsers
# under /ms-playwright and points the variable there; overriding it would make Chromium
# unfindable at runtime.

# curl is used by the query-parameter traffic flow. It is normally already present in this
# image; installing it explicitly keeps the flow from depending on that.
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# playwright is already installed here at the pinned version, so pip reports it satisfied
# and the line acts as a version assertion. httpx is the addition.
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

# Fail the BUILD, not the traffic run, if the browser or the version pin is wrong.
COPY verify_image.py /srv/verify_image.py
RUN python3 /srv/verify_image.py

WORKDIR /opt/external
CMD ["python3", "-c", "print('generator image ready; run a script from /opt/external')"]
