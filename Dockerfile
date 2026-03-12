FROM python:3.12-slim AS base

LABEL org.opencontainers.image.title="Kalypso"
LABEL org.opencontainers.image.description="Local dev SSL certificate authority"
LABEL org.opencontainers.image.source="https://github.com/kalypso-dev/kalypso"

# Install mkcert for trust store management
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl libnss3-tools && \
    ARCH=$(dpkg --print-architecture) && \
    curl -fsSL "https://dl.filippo.io/mkcert/latest?for=linux/${ARCH}" -o /usr/local/bin/mkcert && \
    chmod +x /usr/local/bin/mkcert && \
    apt-get purge -y curl && \
    apt-get autoremove -y && \
    rm -rf /var/lib/apt/lists/*

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
