FROM python:3.11-slim

# System dependencies for git, semgrep native, and building Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    gcc \
    g++ \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Optional CodeQL CLI bundle installation (pass --build-arg INSTALL_CODEQL=1
# or mount a host bundle at /opt/codeql).
ARG INSTALL_CODEQL=0
RUN if [ "$INSTALL_CODEQL" = "1" ]; then \
      mkdir -p /opt && \
      curl -fsSL https://github.com/github/codeql-action/releases/latest/download/codeql-bundle-linux64.tar.gz \
        | tar -xz -C /opt; \
    fi
ENV PATH="/opt/codeql:${PATH}"

WORKDIR /app

# Install Python deps first for better Docker layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Separate layer: changing eval deps must not reinstall torch & co.
COPY requirements-eval.txt .
RUN pip install --no-cache-dir -r requirements-eval.txt

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
