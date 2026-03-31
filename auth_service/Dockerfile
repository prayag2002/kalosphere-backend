FROM python:3.11-slim

WORKDIR /app

# System dependencies for psycopg2
RUN apt-get update && \
    apt-get install -y --no-install-recommends libpq-dev gcc && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Collect static files for admin
RUN python manage.py collectstatic --noinput 2>/dev/null || true

EXPOSE 8000

# Run migrations and start server with gunicorn
CMD ["sh", "-c", "python manage.py migrate --noinput && gunicorn auth_service.wsgi:application --bind 0.0.0.0:8000 --workers 3 --timeout 120"]
