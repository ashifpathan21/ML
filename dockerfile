FROM python:3.11-slim

# Install system deps for androguard & cryptography
RUN apt-get update && apt-get install -y \
    openjdk-17-jre-headless \
    build-essential \
    libssl-dev \
    libffi-dev \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy code
COPY . .

# Install requirements
RUN pip install --no-cache-dir -r requirements.txt

# Expose port
EXPOSE 5000

# Run Flask
CMD ["python", "app.py"]
