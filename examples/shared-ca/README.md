# Shared Kalypso CA — One Instance, Many Projects

Run Kalypso once. Every project on the machine gets trusted HTTPS from the same CA.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  "kalypso" network                   │
│                                                     │
│  ┌──────────┐    ┌──────────┐    ┌──────────┐      │
│  │ Kalypso  │    │ frontend │    │ backend  │      │
│  │ CA       │◄───│ sidecar  │    │ sidecar  │      │
│  │ :8200    │    └────┬─────┘    └────┬─────┘      │
│  └──────────┘         │               │             │
│                       ▼               ▼             │
│                 ┌──────────┐   ┌──────────┐        │
│                 │  nginx   │   │  nginx   │        │
│                 │  :443    │   │  :8443   │        │
│                 └──────────┘   └──────────┘        │
└─────────────────────────────────────────────────────┘
```

## Setup

### 1. Start the shared Kalypso (once)

```bash
cd examples/shared-ca
docker compose up -d
```

### 2. Trust the CA on your host (once)

```bash
curl http://localhost:8200/ca.pem > /tmp/kalypso-ca.pem

# macOS
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain /tmp/kalypso-ca.pem

# Ubuntu/Debian
sudo cp /tmp/kalypso-ca.pem /usr/local/share/ca-certificates/kalypso.crt
sudo update-ca-certificates
```

### 3. Start any project

```bash
# In one terminal
cd frontend/
docker compose up -d

# In another terminal
cd backend/
docker compose up -d
```

### 4. Add to /etc/hosts

```
127.0.0.1 frontend.local api.local
```

### 5. Visit

- https://frontend.local — green lock
- https://api.local:8443 — green lock
- Both signed by the same CA

## How It Works

The key is a **named Docker network** called `kalypso`:

- The shared `docker-compose.yml` creates it: `networks: kalypso: name: kalypso`
- Each project joins it: `networks: kalypso: external: true`
- The sidecar in each project can reach `http://kalypso:8200` over this network
- Each project gets its own certs volume — no conflicts

## Adding a New Project

Three things in your project's `docker-compose.yml`:

```yaml
services:
  # 1. Add a sidecar that talks to the shared Kalypso
  certs:
    image: kalypso/kalypso:latest
    command: ["sidecar"]
    environment:
      KALYPSO_DOMAINS: "myproject.local"
      KALYPSO_SERVER: "http://kalypso:8200"
    volumes:
      - certs:/certs
    networks:
      - kalypso           # join the shared network

  # 2. Mount certs into your service
  web:
    image: nginx:alpine
    volumes:
      - certs:/etc/nginx/certs:ro

volumes:
  certs:

# 3. Reference the external network
networks:
  kalypso:
    external: true
```

That's it. The sidecar handles issuance, renewal, and writes cert/key/ca/fullchain to `/certs`.

## Importing a Corporate CA

If your company already has a trusted CA:

```bash
# On the shared Kalypso setup
docker compose down
docker compose run --rm kalypso import-ca \
  --cert /data/corp-ca.pem --key /data/corp-ca-key.pem
docker compose up -d
```

Or mount the CA files directly:

```yaml
# In the shared docker-compose.yml
services:
  kalypso:
    image: kalypso/kalypso:latest
    volumes:
      - ./corp-ca.pem:/data/ca-cert.pem:ro
      - ./corp-ca-key.pem:/data/ca-key.pem:ro
```

Now every project gets certs signed by the corporate CA — no per-project trust needed.
