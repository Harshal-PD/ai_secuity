FROM python:3.11-slim

# System dependencies for git, semgrep native, and building Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first for better Docker layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY hackersec/ hackersec/
COPY eval_run.py .
COPY test_vuln.py .

# Create workspace and data directories
RUN mkdir -p workspace data

# Default: run FastAPI (override in docker-compose for worker)
CMD ["uvicorn", "hackersec.main:app", "--host", "0.0.0.0", "--port", "8000"]
