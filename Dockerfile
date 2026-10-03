FROM python:3.12-slim

RUN useradd --create-home --uid 10001 soar \
    && mkdir -p /var/lib/soar \
    && chown soar:soar /var/lib/soar

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir .
COPY config ./config
COPY data/ioc ./data/ioc

USER soar
ENV SOAR_DATA_DIR=/var/lib/soar \
    SOAR_POLICY_FILE=/app/config/lab-policy.json \
    SOAR_IOC_PATHS=/app/data/ioc/local_iocs.seed.jsonl \
    PYTHONUNBUFFERED=1
EXPOSE 8088
HEALTHCHECK --interval=30s --timeout=5s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8088/healthz', timeout=3)"
CMD ["phishing-soar", "serve", "--host", "0.0.0.0", "--port", "8088"]
