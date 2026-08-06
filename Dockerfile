FROM python:3.12-slim

# git is not a convenience here: the engine audits repositories it clones.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY alembic.ini secaudit.py ./
COPY migrations/ ./migrations/
COPY web/ ./web/
COPY docker-entrypoint.sh /usr/local/bin/

RUN useradd --create-home --uid 10001 secaudit \
    && chmod +x /usr/local/bin/docker-entrypoint.sh
USER secaudit

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SECAUDIT_BACKEND=anthropic-api

EXPOSE 8000
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["uvicorn", "web.main:app", "--host", "0.0.0.0", "--port", "8000"]
