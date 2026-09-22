# firewall-IA — Docker Lab destination application.
#
# Build context: docker/destination (it needs nothing from the repository root).
#
# The protected origin server. Standard library only, no dependencies. Its purpose
# is to make "did the request reach the destination?" answerable from evidence:
# every request that arrives is appended to a JSONL receipt log, which the smoke
# client reads through a shared volume.
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    ACCESS_LOG=/logs/destination-access.jsonl \
    WWW_ROOT=/srv/www \
    PORT=9000

COPY www/ /srv/www/
COPY serve.py /srv/serve.py

EXPOSE 9000

CMD ["python3", "/srv/serve.py"]
