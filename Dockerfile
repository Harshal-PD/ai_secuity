FROM python:3.11-slim

# System deps: git, build tools, and the docker CLI (worker spawns the
# exploit-verification sandbox on the host daemon via the mounted docker.sock).
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    gcc \
    g++ \
    docker.io \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first for better Docker layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY hackersec/ hackersec/
COPY eval_run.py .
COPY test_vuln.py .

# Copy pre-built data files (FAISS index, ML model, KB metadata)
COPY data/ data/

# Ensure upload directory exists
RUN mkdir -p workspace data/uploads

# Default: run FastAPI (override in docker-compose for worker)
CMD ["uvicorn", "hackersec.main:app", "--host", "0.0.0.0", "--port", "8000"]
