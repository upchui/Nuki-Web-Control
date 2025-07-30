# Stage 1: Build dependencies
FROM python:3.11-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    gcc \
    musl-dev \
    libffi-dev \
    openssl-dev

# Set working directory
WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .

# Create optimized requirements with uvloop for performance
RUN echo 'fastapi' > requirements_optimized.txt && \
    echo 'uvicorn[standard]' >> requirements_optimized.txt && \
    echo 'uvloop' >> requirements_optimized.txt && \
    echo 'paho-mqtt' >> requirements_optimized.txt && \
    echo 'sqlalchemy' >> requirements_optimized.txt && \
    echo 'pydantic' >> requirements_optimized.txt && \
    echo 'python-multipart' >> requirements_optimized.txt

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements_optimized.txt

# Compile dependencies bytecode in build stage for better optimization
RUN python -m compileall -b /usr/local/lib/python3.11/site-packages && \
    find /usr/local/lib/python3.11/site-packages -name "*.py" -delete

# Copy and compile application code in build stage
COPY . /tmp/app
RUN python -m compileall -b /tmp/app && \
    find /tmp/app -name "*.py" -delete && \
    find /tmp/app -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true

# Stage 2: Ultra-minimal runtime image
FROM alpine:3.18 AS runtime

# Install ONLY minimal runtime dependencies (no dev tools!)
RUN apk add --no-cache \
    python3 \
    libffi \
    openssl \
    && ln -sf python3 /usr/bin/python

# Create non-root user for security
RUN addgroup -g 1000 appuser && \
    adduser -D -s /bin/sh -u 1000 -G appuser appuser

# Copy pre-compiled Python packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Set Python path to include both locations
ENV PYTHONPATH="/usr/lib/python3.11/site-packages:/usr/local/lib/python3.11/site-packages"

# Set working directory
WORKDIR /app

# Copy pre-compiled application code
COPY --from=builder --chown=appuser:appuser /tmp/app .

# Create data directory for persistent database storage
RUN mkdir -p /app/data && chown -R appuser:appuser /app/data

# Set environment variables for optimization
ENV PYTHONOPTIMIZE=2 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8001

# Optimized uvicorn command with uvloop
CMD ["uvicorn", "main:app", \
     "--host", "0.0.0.0", \
     "--port", "8001", \
     "--loop", "uvloop", \
     "--workers", "1", \
     "--log-level", "info", \
     "--no-access-log"]
