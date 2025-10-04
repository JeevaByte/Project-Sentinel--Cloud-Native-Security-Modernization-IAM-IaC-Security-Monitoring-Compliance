FROM python:3.9-slim

# INTENTIONAL VULNERABILITIES FOR DEMONSTRATION PURPOSES

# VULNERABILITY: Running as root user
# Should use: RUN adduser --disabled-password --gecos '' appuser
# USER appuser

WORKDIR /app

# VULNERABILITY: Using latest tag for base dependencies
# Should pin specific versions
COPY requirements.txt .

# VULNERABILITY: No verification of package integrity
RUN pip install --no-cache-dir -r requirements.txt

# VULNERABILITY: Copying entire context instead of specific files
COPY . .

# VULNERABILITY: Exposing internal port without documentation
EXPOSE 5000

# VULNERABILITY: No health check defined
# Should include: HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
#   CMD curl -f http://localhost:5000/health || exit 1

# VULNERABILITY: Using curl in production container
RUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*

# VULNERABILITY: Hardcoded secrets in environment variables
ENV SECRET_KEY=supersecretkey123
ENV DB_PASSWORD=password
ENV API_KEY=ak_1234567890abcdef

# VULNERABILITY: Debug mode enabled
ENV FLASK_ENV=development
ENV FLASK_DEBUG=1

# VULNERABILITY: Running application as root
CMD ["python", "app.py"]

# VULNERABILITY: No security labels or metadata
# Should include security scanning labels and build info