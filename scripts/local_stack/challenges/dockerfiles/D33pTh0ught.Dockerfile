# Adapter image for sec-challenges/Web/D33pTh0ught (ships no Dockerfile).
# Build context MUST be the D33pTh0ught/ directory. The application source is copied in UNMODIFIED;
# this file only installs the application's own pinned requirements and runs its unmodified entry file.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

COPY requirements.txt ./
RUN python -m pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Unmodified application tree (D33p.py, templates/, static/, ...).
COPY . .

EXPOSE 3030
CMD ["python", "D33p.py"]
