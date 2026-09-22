# firewall-IA — Docker Lab `lab-app`: the External Test v1 destination application.
#
# Build context: docker/lab-app (needs nothing from the repository root).
#
# Separate from the smoke-test `destination` service, which is deliberately left untouched
# so ./docker/smoke_test.sh keeps passing exactly as verified in reports/lab/docker-lab-v1.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    ACCESS_LOG=/logs/lab-app-access.jsonl \
    PORT=9100

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt

COPY app.py /srv/app.py

EXPOSE 9100
CMD ["python3", "/srv/app.py"]
