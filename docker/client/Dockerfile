# firewall-IA — Docker Lab smoke-test client.
#
# Build context: docker/client (it needs nothing from the repository root).
#
# A one-shot client, not a service: it sends a handful of requests through the
# gateway and exits with the result. Standard library only, so the traffic it
# generates carries no third-party HTTP client's header fingerprint beyond
# urllib's own defaults.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1

COPY smoke_test.py /srv/smoke_test.py

ENTRYPOINT ["python3", "/srv/smoke_test.py"]
CMD ["all"]
