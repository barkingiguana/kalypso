FROM python:3.12-slim AS base

LABEL org.opencontainers.image.title="Kalypso"
LABEL org.opencontainers.image.description="Local dev SSL certificate authority"
LABEL org.opencontainers.image.source="https://github.com/kalypso-dev/kalypso"
LABEL kalypso.self="true"

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src/ src/

RUN pip install --no-cache-dir . && \
    rm -rf /root/.cache

RUN adduser --system --no-create-home kalypso
USER kalypso

VOLUME /data
EXPOSE 8200

HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8200/health')"

ENTRYPOINT ["kalypso"]
CMD ["--data-dir", "/data", "serve"]
