# Adapter image for sec-challenges/Web/ag3ncy (ships no Dockerfile).
# Build context MUST be the ag3ncy/ directory. The application source is copied in UNMODIFIED;
# this file only installs the application's own pinned requirements and runs its unmodified entry file.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

COPY requirements.txt ./
RUN python -m pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Unmodified application tree (agency.py, templates/, static/, ...).
COPY . .

EXPOSE 5000
CMD ["python", "agency.py"]
