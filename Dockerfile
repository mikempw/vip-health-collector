FROM python:3.9-slim

# Install dependencies
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user for security
RUN useradd -m appuser && chown -R appuser:appuser /app
USER appuser

# Expose API port
EXPOSE 8080

# Run the collector
CMD ["python", "vip_health_collector.py"]
