# ==============================================================================
# MITRE ATT&CK MCP Server - Production Dockerfile
# 
# This Dockerfile clones the open-source mitre-mcp repository and builds
# a minimal production image with only necessary runtime artifacts.
# ==============================================================================

# ------------------------------------------------------------------------------
# CONFIGURATION SECTION - Customize these variables for your needs
# ------------------------------------------------------------------------------
# GitHub repository URL - Change this to point to your fork or different repo
ARG REPO_URL=https://github.com/Montimage/mitre-mcp.git

# Release tag or branch - Update this to use a specific version
# Examples: "main", "v1.0.0", "v1.2.3", or a specific commit hash
ARG REPO_VERSION=main

# Python version - Adjust based on upstream compatibility requirements
ARG PYTHON_VERSION=3.10
# ------------------------------------------------------------------------------

# ==============================================================================
# Stage 1: Builder - Clone repository and build artifacts
# ==============================================================================
FROM python:${PYTHON_VERSION}-slim AS builder

# Install git and other build dependencies
# NOTE: Add additional build tools here if the upstream repo requires them
# (e.g., gcc, g++, make, etc. - check upstream repo's documentation)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        git \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Clone the repository at the specified version
ARG REPO_URL
ARG REPO_VERSION
RUN git clone --depth 1 --branch ${REPO_VERSION} ${REPO_URL} mitre-mcp

WORKDIR /build/mitre-mcp

# Install Python dependencies
# NOTE: If the upstream repo has different installation steps (e.g., setup.py install,
# poetry, pipenv, etc.), modify these commands accordingly. Refer to the upstream
# repo's README.md or installation documentation for the correct procedure.
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Install the package and collect artifacts
# This creates the necessary Python package structure
RUN pip install --no-cache-dir .

# Pre-download MITRE ATT&CK data (cached in the build stage)
# This reduces startup time for the final image
RUN mkdir -p /build/data && \
    python -c "from mitre_mcp.mitre_mcp_server import download_and_save_attack_data; download_and_save_attack_data('/build/data')" || \
    echo "Warning: Could not pre-download MITRE ATT&CK data"

# ==============================================================================
# Stage 2: Runtime - Minimal production image
# ==============================================================================
FROM python:${PYTHON_VERSION}-slim

# Add metadata labels
LABEL maintainer="Your Team <your-email@example.com>"
LABEL description="MITRE ATT&CK MCP Server - Production Image"
LABEL org.opencontainers.image.source="https://github.com/Montimage/mitre-mcp"

# Create non-root user for security
RUN useradd -m -u 1000 -s /bin/bash mcp && \
    mkdir -p /app /app/data && \
    chown -R mcp:mcp /app

WORKDIR /app

# Copy only runtime Python dependencies from builder
# This significantly reduces the final image size
# Note: Using wildcard to match the full Python version (e.g., 3.10.x)
COPY --from=builder /usr/local/lib/python3.*/site-packages /usr/local/lib/python3.10/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy the mitre-mcp package source
COPY --from=builder /build/mitre-mcp/mitre_mcp /app/mitre_mcp

# Copy pre-downloaded MITRE ATT&CK data
COPY --from=builder /build/data /app/data

# Copy LICENSE file from the cloned repository (license compliance)
# IMPORTANT: This ensures proper attribution to the upstream open-source project
COPY --from=builder /build/mitre-mcp/LICENSE /app/LICENSE

# Copy additional documentation files (optional but recommended)
COPY --from=builder /build/mitre-mcp/README.md /app/README.md

# Patch FastMCP constructor to bind to 0.0.0.0 for Docker networking.
# FastMCP.run() does NOT accept host/port kwargs — set them on the constructor instead.
# FastMCP also reads FASTMCP_HOST / FASTMCP_PORT env vars as a reliable fallback.
RUN sed -i 's|lifespan=attack_lifespan)|lifespan=attack_lifespan, host="0.0.0.0", port=8000)|' \
        /app/mitre_mcp/mitre_mcp_server.py && \
    grep -q 'host="0.0.0.0"' /app/mitre_mcp/mitre_mcp_server.py && \
    echo "Patch verified OK" || echo "WARNING: patch may not have matched"

ENV FASTMCP_HOST=0.0.0.0
ENV FASTMCP_PORT=8000

# Set ownership for non-root user
RUN chown -R mcp:mcp /app

# Switch to non-root user
USER mcp

# Expose the service port
EXPOSE 8000

# Run MCP server in HTTP mode
CMD ["python", "-m", "mitre_mcp.mitre_mcp_server", "--http", "--host", "0.0.0.0"]

# ==============================================================================
# BUILD INSTRUCTIONS
# ==============================================================================
# Build with default settings:
#   docker build -t mitre-mcp:latest .
#
# Build with a specific version/tag:
#   docker build --build-arg REPO_VERSION=v1.0.0 -t mitre-mcp:v1.0.0 .
#
# Build with a different repository URL (e.g., your fork):
#   docker build --build-arg REPO_URL=https://github.com/yourname/mitre-mcp.git -t mitre-mcp:latest .
#
# Build with a specific Python version:
#   docker build --build-arg PYTHON_VERSION=3.11 -t mitre-mcp:latest .
#
# Run the container:
#   docker run -p 8000:8000 mitre-mcp:latest
# ==============================================================================
