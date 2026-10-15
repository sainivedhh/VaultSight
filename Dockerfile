# Multi-stage hardened Dockerfile for VaultSight DSPM
# Base image: minimal python 3.11 slim
FROM python:3.11-slim AS builder

WORKDIR /app

# Install build essentials if needed for wheels
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# Final runtime image
FROM python:3.11-slim AS runtime

# Security: Create non-root user and group
RUN groupadd -r vaultsight && useradd -r -g vaultsight -u 10001 vaultsight

WORKDIR /app

# Copy installed dependencies from builder
COPY --from=builder /root/.local /home/vaultsight/.local

# Copy application source code
COPY --chown=vaultsight:vaultsight vaultsight/ ./vaultsight/
COPY --chown=vaultsight:vaultsight pytest.ini .

# Set environment
ENV PATH=/home/vaultsight/.local/bin:$PATH \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Drop privileges to non-root user
USER vaultsight

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/docs')" || exit 1

CMD ["uvicorn", "vaultsight.api.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000"]
