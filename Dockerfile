# CloakAI Enterprise Gateway Dockerfile
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
RUN python -m spacy download en_core_web_sm

# Copy project files
COPY . .

# Expose internal gateway port
EXPOSE 8080

# Run with Gunicorn or direct python
CMD ["python", "gateway.py"]