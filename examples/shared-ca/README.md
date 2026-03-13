# Shared Kalypso CA — One Instance, Many Projects

Run Kalypso once. Every project on the machine gets trusted HTTPS from the same CA.

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  Host machine                        │
│                                                     │
│  ┌──────────┐                                       │
│  │ Kalypso  │──── Docker socket ──── watches ALL    │
│  │ :8200    │     /var/run/docker.sock  containers  │
│  └────┬─────┘                                       │
│       │ writes certs to ~/.kalypso/certs/           │
│       │                                             │
│       ├── frontend/  ◄── mounted by frontend stack  │
│       └── backend/   ◄── mounted by backend stack   │
│                                                     │
│  ┌──────────┐   ┌──────────┐                        │
│  │  nginx   │   │  nginx   │   (separate compose    │
│  │  :443    │   │  :8443   │    stacks, no sidecar) │
│  └──────────┘   └──────────┘                        │
└─────────────────────────────────────────────────────┘
```

## How It Works

Kalypso watches the **Docker socket** — it sees every container on the host, regardless of which Compose stack it belongs to. No sidecars, no shared networks.

1. Kalypso runs once with the Docker socket mounted
2. It watches for any container with a `kalypso.domains` label
3. When it sees one, it issues a cert and writes it to `/certs/{cert_dir}/`
4. The host bind mount (`~/.kalypso/certs`) makes certs available to all stacks
5. Kalypso auto-detects nginx/apache/haproxy and sends a reload signal

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

Kalypso sees the new containers start, issues certs, writes them, and reloads nginx — automatically.

### 4. Add to /etc/hosts

```
127.0.0.1 frontend.local api.local
```

### 5. Visit

- https://frontend.local — green lock
- https://api.local:8443 — green lock
- Both signed by the same CA

## Adding a New Project

Two things in your project's `docker-compose.yml`:

```yaml
services:
  web:
    image: nginx:alpine
    labels:
      # 1. Tell Kalypso what domains you want
      kalypso.domains: "myproject.local"
      kalypso.cert_dir: "myproject"
    volumes:
      # 2. Mount the cert subdirectory
      - ~/.kalypso/certs/myproject:/etc/nginx/certs:ro
      - ./nginx.conf:/etc/nginx/conf.d/default.conf:ro
    ports:
      - "9443:443"
```

That's it. No sidecar container. No shared Docker network. Kalypso watches the socket, issues certs, writes them to the host bind mount, and reloads your server.

## Custom Certs Directory

By default, certs are written to `~/.kalypso/certs`. Override with:

```bash
KALYPSO_CERTS_DIR=/opt/certs docker compose up -d
```

## Importing a Corporate CA

If your company already has a trusted CA:

```bash
# On the shared Kalypso setup
docker compose down
docker compose run --rm kalypso import-ca \
  --cert /data/corp-ca.pem --key /data/corp-ca-key.pem
docker compose up -d
```

Now every project gets certs signed by the corporate CA — no per-project trust needed.
