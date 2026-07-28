FROM python:3.12-slim

WORKDIR /app

# System deps for bcrypt/cryptography wheels
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
COPY scripts/ ./scripts/

RUN mkdir -p /app/data

ENV PYTHONUNBUFFERED=1

EXPOSE 8000

# Seed demo data on first boot if the DB doesn't exist yet, then start the API.
CMD ["sh", "-c", "python -m scripts.seed_data && uvicorn app.main:app --host 0.0.0.0 --port 8000"]
