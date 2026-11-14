# Adapter image for sec-challenges/Web/ObC00ki3s (ships no Dockerfile).
# Build context MUST be the ObC00ki3s/ directory. The application source is copied in UNMODIFIED;
# this file only installs the application's own pinned requirements and runs its unmodified entry file.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

COPY requirements.txt ./
RUN python -m pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Unmodified application tree (server.py, templates/, static/js, static/img, ...).
COPY . .

# server.py calls app.run(host='0.0.0.0') with no port → Flask default 5000.
EXPOSE 5000
CMD ["python", "server.py"]
