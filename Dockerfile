FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TDM_HOST=0.0.0.0 \
    TDM_PORT=4300

WORKDIR /app

RUN groupadd --gid 10001 appgroup \
    && useradd --uid 10001 --gid appgroup --shell /usr/sbin/nologin --create-home appuser

COPY pyproject.toml README.md LICENSE SECURITY.md ./
COPY policies ./policies
COPY deploy ./deploy
COPY src ./src

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir . \
    && chown -R appuser:appgroup /app

USER appuser

EXPOSE 4300

HEALTHCHECK --interval=20s --timeout=4s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:4300/healthz', timeout=3)"

CMD ["tdm-guard", "serve", "--host", "0.0.0.0", "--port", "4300"]

