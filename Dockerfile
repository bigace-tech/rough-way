FROM python:3.9-slim-bullseye

WORKDIR /app

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=8080 \
    FLASK_APP=app.py \
    FLASK_ENV=production

# Copy all files first
COPY . .

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Ensure script has execute permissions
RUN chmod +x start.sh

EXPOSE $PORT

CMD ["./start.sh"]