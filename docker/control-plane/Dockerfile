# firewall-IA — Control Plane image (FastAPI + inference_core + TinyLlama V4).
#
# Build context: the repository ROOT (see .dockerignore).
#     docker compose build control-plane
#
# WHAT IS AND IS NOT IN THIS IMAGE
#   IN : the control plane source and the ML/inference stack from requirements.txt.
#   OUT: the V4 adapter and the HuggingFace cache. Both are large and gitignored;
#        compose bind-mounts them read-only at runtime. Baking the adapter into an
#        image would copy a gitignored artifact into a distributable layer.
#   OUT: mitmproxy. It conflicts with pydantic on Python 3.12 (D33) and lives in
#        the separate data-plane image.
#
# Ubuntu 24.04 ships Python 3.12, matching the verified environment (Python 3.12.13,
# CONTEXT.md section 2). torch comes from the cu124 index because requirements.txt
# records the verified build as 2.6.0+cu124; the plain PyPI wheel is CPU-only and
# would NOT reproduce the measured GPU behaviour.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# build-essential and python3-dev are a RUNTIME requirement here, not a build
# convenience. bitsandbytes imports Triton, and Triton's NVIDIA backend compiles a
# small CPython extension on first import, at model load time. On a bare
# ubuntu:24.04 there is no toolchain, so loading V4 failed with
#   RuntimeError: Failed to find C compiler. Please specify via CC environment variable.
# FastAPI still started and /health stayed model_loaded: false, so the healthcheck
# correctly never went healthy. This never appeared locally because the host already
# has a toolchain. Nothing outside this image changes: no production code, no
# requirements.txt, no package version, no model or inference configuration.
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3.12 \
        python3-pip \
        python3-dev \
        build-essential \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# `--break-system-packages` is the same mechanism the project documents for the
# host (CONTEXT.md section 2). In a single-purpose container there is no system
# Python to protect, so no virtualenv is added on top.
# torch first, from the CUDA 12.4 index. `torch==2.6.0` in requirements.txt is then
# already satisfied by 2.6.0+cu124 (PEP 440 ignores the local version segment), so
# the second command does not pull the CPU wheel over it.
RUN python3 -m pip install --break-system-packages \
        --index-url https://download.pytorch.org/whl/cu124 \
        torch==2.6.0

COPY requirements.txt /tmp/requirements.txt
RUN python3 -m pip install --break-system-packages -r /tmp/requirements.txt \
    && python3 -c "import torch; assert torch.__version__.startswith('2.6.0'), torch.__version__; print('torch', torch.__version__)"

WORKDIR /app
COPY control_plane/ /app/control_plane/

# The V4 adapter is mounted here read-only by compose. inference_core reads this
# variable (control_plane/inference_core.py, DEFAULT_ADAPTER_DIR); without it the
# default would be /app/model-output-v4-clean, which is deliberately not in the image.
ENV FIREWALL_ADAPTER_DIR=/opt/firewall-ia/adapter

# Consumed by the NVIDIA Container Toolkit when the container is started with GPU
# access. Harmless when it is absent — the container simply has no GPU, and
# inference_core.resolve_device() then reports CPU (a DIFFERENT execution
# environment from the CUDA baseline; see docker/README.md).
ENV NVIDIA_VISIBLE_DEVICES=all \
    NVIDIA_DRIVER_CAPABILITIES=compute,utility

EXPOSE 8000

# 0.0.0.0 is required for the data-plane container to reach this service over the
# Docker network. The port is NOT published to the host by compose.
# One worker: one GPU, one model, loaded once at startup (same as the documented
# local command).
CMD ["python3", "-m", "uvicorn", "--app-dir", "control_plane", "classifier_api:app", \
     "--host", "0.0.0.0", "--port", "8000"]
