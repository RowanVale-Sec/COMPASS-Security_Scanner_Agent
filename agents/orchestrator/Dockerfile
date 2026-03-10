FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy shared libraries
COPY shared/ /app/shared/

# Copy agent code
COPY agents/orchestrator/ /app/agents/orchestrator/

# Install Python dependencies
COPY agents/orchestrator/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

ENV PYTHONUNBUFFERED=1
ENV COMPASS_MODE=server
ENV ORCHESTRATOR_PORT=8093

EXPOSE 8093

CMD ["python", "-m", "agents.orchestrator.orchestrator_agent"]
