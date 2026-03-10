FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy shared libraries
COPY shared/ /app/shared/

# Copy agent code
COPY agents/threat_model/ /app/agents/threat_model/

# Install Python dependencies
COPY agents/threat_model/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

ENV PYTHONUNBUFFERED=1
ENV COMPASS_MODE=server
ENV THREAT_MODEL_PORT=8092

EXPOSE 8092

CMD ["python", "-m", "agents.threat_model.threat_model_agent"]
