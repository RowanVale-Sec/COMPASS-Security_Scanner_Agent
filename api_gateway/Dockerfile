FROM python:3.12-slim

# git is needed for repo clones; openssh-client for SSH-aware remotes even
# though we only accept HTTPS URLs (belt and braces — if the URL validator
# misses something, we still want a safe SSH runtime).
RUN apt-get update \
 && apt-get install -y --no-install-recommends git openssh-client ca-certificates \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY api_gateway/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY api_gateway/app /app/app

EXPOSE 8094

# NOTE: runs as root so it can create per-job directories inside the shared
# `compass-workspace` Docker named volume (Docker creates named-volume mount
# points owned by root:root). Other agents mount the same volume read-only
# so they happily read what we write. For the cloud migration we swap the
# volume out for GCS + FUSE, and drop privileges there.

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8094", "--no-server-header"]
