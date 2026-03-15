FROM python:3.11-slim

WORKDIR /app

# Build + runtime deps in one stage (simpler, avoids --user path issues)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    gcc \
    libgomp1 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies into system site-packages (accessible to all users)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ src/
COPY templates/ templates/
COPY main.py .

# Create data/logs dirs; create non-root user with ownership
RUN mkdir -p /app/data /app/logs \
    && useradd -m -u 1000 phishing \
    && chown -R phishing:phishing /app

USER phishing

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    LOG_LEVEL=INFO \
    DASHBOARD_PORT=8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -sf http://localhost:8000/api/health || exit 1

EXPOSE 8000

CMD ["python", "main.py", "serve", "--host", "0.0.0.0", "--port", "8000"]
