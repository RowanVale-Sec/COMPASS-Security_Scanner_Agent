FROM python:3.11-slim

WORKDIR /app

# Install system dependencies and security scanning tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Install Semgrep and Bandit
RUN pip install --no-cache-dir semgrep bandit

# Copy shared libraries
COPY shared/ /app/shared/

# Copy agent code
COPY agents/scanner/ /app/agents/scanner/

# Install Python dependencies
COPY agents/scanner/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Pre-pull the local embeddings model so the deduplicator doesn't pay the
# ~80MB download cost on its first run in a fresh container.
RUN python -c "from sentence_transformers import SentenceTransformer; SentenceTransformer('sentence-transformers/all-MiniLM-L6-v2')"

# Create scan directory
RUN mkdir -p /scan

ENV PYTHONUNBUFFERED=1
ENV COMPASS_MODE=server
ENV SCANNER_PORT=8090

EXPOSE 8090

CMD ["python", "-m", "agents.scanner.scanner_agent"]
