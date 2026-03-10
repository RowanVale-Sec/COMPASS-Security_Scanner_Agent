FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy shared libraries
COPY shared/ /app/shared/

# Copy MCP server code
COPY mcp_servers/syft/syft_mcp_server.py .

# Install Python dependencies
RUN pip install --no-cache-dir flask gunicorn

# Download Syft binary
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /app

# Create workspace directory
RUN mkdir -p /workspace

EXPOSE 8080

CMD ["python", "syft_mcp_server.py"]
