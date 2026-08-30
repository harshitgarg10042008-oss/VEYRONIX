FROM python:3.11-slim

# Create a non-root user
RUN groupadd -r veyronix && useradd -r -g veyronix veyronix

WORKDIR /app

# Install system dependencies if any
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy pyproject.toml and source code
COPY pyproject.toml README.md ./
COPY src/ ./src/
COPY examples/ ./examples/
# Copy the config pack or other required files if they exist in a data folder
# COPY tests/fixtures /app/tests/fixtures

# Install python dependencies securely
RUN pip install --no-cache-dir -e .[api]

# Change ownership
RUN chown -R veyronix:veyronix /app

# Switch to non-root user
USER veyronix

# Expose backend port
EXPOSE 5000

# Environment variables
ENV VEYRONIX_API_HOST=0.0.0.0
ENV VEYRONIX_API_PORT=5000
ENV PYTHONPATH=/app/src

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://127.0.0.1:5000/api/health || exit 1

CMD ["python", "examples/api_server.py"]
