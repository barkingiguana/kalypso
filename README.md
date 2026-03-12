# Kalypso

**Local dev SSL certificate authority — like Let's Encrypt for localhost.**

Zero dependencies. No third-party tools. Just `pip install kalypso`.

Kalypso makes HTTPS in local development effortless. Create one root CA,
trust it once, then let Kalypso vend short-lived SSL certificates to every
service in your stack.

## Quick Start

```bash
# Install
pip install kalypso

# Create your root CA (do this once)
kalypso init

# Trust it (auto-detects your OS — macOS, Linux, or Windows)
sudo kalypso trust

# Issue a certificate (valid for 24 hours by default)
kalypso issue myapp.local "*.myapp.local"

# Or run the API server for Docker Compose integration
kalypso serve
```

## Why Kalypso?

| Feature | Kalypso | Self-signed certs | mkcert |
|---|---|---|---|
| Short-lived certs (24h default) | Yes | No | No |
| REST API for containers | Yes | No | No |
| Docker Compose sidecar | Yes | No | No |
| Auto-renewal | Yes | No | No |
| Native trust store install | Yes (no deps) | No | Yes |
| SDKs (Python, Ruby, Go, curl) | Yes | No | No |
| ECDSA P-384 | Yes | No | No |
| File permission hardening | Yes | No | No |
| Certificate fingerprints | Yes | No | No |
| Zero external dependencies | Yes | N/A | No (Go binary) |

## How It Works

1. **`kalypso init`** — generates an ECDSA P-384 root CA (key saved with 0600 perms)
2. **`kalypso trust`** — natively installs into OS trust stores (no third-party tools)
3. **Issue certs** — via CLI, API, or SDK. Certs are short-lived (24h default, 7 day max)
4. **Auto-refresh** — the Docker sidecar renews certs before they expire

```
┌─────────────────────────────────────┐
│  Your Browser / curl / httpie       │
│  (trusts Kalypso root CA)           │
└────────────┬────────────────────────┘
             │ HTTPS
             ▼
┌─────────────────────────────────────┐
│  nginx / your app                   │
│  (uses Kalypso-issued cert)         │
└────────────┬────────────────────────┘
             │ requests cert
             ▼
┌─────────────────────────────────────┐
│  Kalypso CA (API server / CLI)      │
│  (signs with trusted root CA)       │
└─────────────────────────────────────┘
```

## Docker Compose

Add Kalypso as a service and let your apps request certs automatically:

```yaml
services:
  kalypso:
    image: kalypso/kalypso:latest
    volumes:
      - kalypso-data:/data
      - certs:/certs
    ports:
      - "8200:8200"

  web:
    image: nginx:alpine
    volumes:
      - certs:/etc/nginx/certs:ro
    depends_on:
      - kalypso

volumes:
  kalypso-data:
  certs:
```

See [examples/](examples/) for complete working setups.

## API

### `GET /health`
Health check and stats.

### `GET /ca.pem`
Download the root CA certificate.

### `POST /certificates`
Issue a new certificate.

```json
{
  "domains": ["myapp.local", "*.myapp.local"],
  "hours": 24,
  "ip_addresses": ["127.0.0.1"]
}
```

## SDKs

- **Python**: `pip install kalypso-sdk`
- **Ruby**: `gem install kalypso`
- **Go**: `go get github.com/kalypso-dev/kalypso-go`
- **curl**: See [docs/curl.md](docs/curl.md)

## Security

- **ECDSA P-384 keys** — 192-bit security (stronger than mkcert's P-256)
- **SHA-384 signatures** — matched to curve strength
- Root CA is constrained (`pathLength=0`, `keyUsage=keyCertSign`)
- Leaf certs are short-lived (24h default, 7 day max)
- Leaf certs have `extKeyUsage=serverAuth` only
- Each cert gets a unique serial number and key pair
- **Private keys written with 0600 permissions** (owner-only)
- **SHA-256 certificate fingerprints** for audit trail
- Native trust store management — no third-party binaries
- `kalypso status` — verify key security and CA fingerprint

## License

MIT
