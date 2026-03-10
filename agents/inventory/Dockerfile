FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy shared libraries
COPY shared/ /app/shared/

# Copy agent code
COPY agents/inventory/ /app/agents/inventory/

# Install Python dependencies
COPY agents/inventory/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Create scan directory
RUN mkdir -p /scan

ENV PYTHONUNBUFFERED=1
ENV COMPASS_MODE=server
ENV INVENTORY_PORT=8091

EXPOSE 8091

CMD ["python", "-m", "agents.inventory.inventory_agent"]
