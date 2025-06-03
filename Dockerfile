# Use official Python runtime as a parent image
FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    netcat-openbsd gcc postgresql-client \
 && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt

# Copy the rest of the application code
COPY . .

# Collect static files (if needed)
RUN python manage.py collectstatic --noinput

# Expose the port
EXPOSE 8080

# Start the Gunicorn server
CMD ["gunicorn", "userform.wsgi:application", "--bind", ":8080", "--workers", "3"]
