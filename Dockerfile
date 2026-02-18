# ══════════════════════════════════════════════════════════
# PhishGuard AI — Multi-Stage Production Dockerfile
# ══════════════════════════════════════════════════════════

# ── Stage 1: Builder ──────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends gcc && \
    rm -rf /var/lib/apt/lists/*

# Copy requirements first for layer caching
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Stage 2: Runtime ──────────────────────────────────────
FROM python:3.11-slim AS runtime

LABEL maintainer="PhishGuard AI Team"
LABEL description="Explainable Phishing Email Detection API"
LABEL version="2.0.0"

WORKDIR /app

# Create non-root user for security
RUN groupadd -r appuser && \
    useradd -r -g appuser -d /app -s /sbin/nologin appuser

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY app/ ./app/
COPY data/ ./data/
COPY frontend/ ./frontend/

# Create persistent data directories
RUN mkdir -p /app/chroma_data && \
    chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" || exit 1

# Run the application with production settings
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2", "--access-log"]
