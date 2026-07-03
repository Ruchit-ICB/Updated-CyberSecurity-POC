# ==================== Builder ====================
FROM python:3.11-slim AS builder

WORKDIR /app

# Install build dependencies (if any)
RUN apt-get update && apt-get install -y --no-install-recommends build-essential && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ==================== Runtime ====================
FROM python:3.11-slim

# Create a non‑root user
RUN useradd -m appuser
WORKDIR /app

# Copy installed packages from builder stage
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application source code
COPY . .

# Create upload directory and expose as a volume
RUN mkdir -p /uploads && chown appuser:appuser /uploads
VOLUME /uploads

# Switch to non‑root user
USER appuser

# Expose the FastAPI port
EXPOSE 8000

# Run the server
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
