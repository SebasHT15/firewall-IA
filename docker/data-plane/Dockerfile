# firewall-IA — Data Plane image (mitmproxy addon, data_plane.py).
#
# Build context: the repository ROOT (see .dockerignore).
#     docker compose build data-plane
#
# Deliberately SEPARATE from the control-plane image (D33): mitmproxy 12.2.3 pins
# typing-extensions<=4.14 on Python 3.12, while the control plane's pydantic 2.13.4
# needs >=4.14.1. Two images keep both stacks at their verified versions; merging
# them would downgrade a dependency of the validated control plane.
#
# This image contains NO model and NO ML stack. The data plane only speaks HTTP to
# the control plane.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

COPY requirements-data-plane.txt /tmp/requirements-data-plane.txt
RUN pip install --no-cache-dir -r /tmp/requirements-data-plane.txt

WORKDIR /app
COPY data_plane/ /app/data_plane/

# data_plane.py resolves CONFIG_PATH as <parent of data_plane/>/config.yaml, i.e.
# /app/config.yaml. Compose bind-mounts docker/config.docker.yaml there read-only.
# It is NOT copied in: the file is mounted so the lab's classifier URL is visible
# and editable without rebuilding, and so this image carries no stale copy.

EXPOSE 8080

# 0.0.0.0 so client containers on the Docker network can use this as their explicit
# HTTP proxy. mitmdump exits with code 1 if the addon or config.yaml fails to load,
# so a misconfigured gateway never serves traffic (verified on mitmproxy 12.2.3).
CMD ["mitmdump", "-s", "data_plane/data_plane.py", "--listen-host", "0.0.0.0", "-p", "8080"]
