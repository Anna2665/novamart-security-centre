# NovaMart API (FastAPI) - used by Render. The web pages are built and hosted separately (Netlify).
FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOST=0.0.0.0 \
    FORWARDED_ALLOW_IPS=*

WORKDIR /app

# Runtime dependencies only (the test tools in requirements.txt are not needed in production).
COPY backend/requirements.txt /tmp/requirements.txt
RUN grep -vE '^(pytest|httpx|aiosmtpd|#)' /tmp/requirements.txt > /tmp/prod-requirements.txt \
 && pip install --no-cache-dir -r /tmp/prod-requirements.txt

COPY backend ./backend
COPY run.py ./run.py

RUN useradd --create-home app && mkdir -p /app/data && chown -R app:app /app
USER app

# Render passes the port in $PORT (run.py reads it).
EXPOSE 10000
CMD ["python", "run.py"]
