# Kalypso

**Local dev SSL certificate authority — like Let's Encrypt for localhost.**

Kalypso makes HTTPS in local development effortless. Create one root CA,
trust it once, then let Kalypso vend short-lived SSL certificates to every
service in your stack.

## Quick Start

```bash
# Install
pip install kalypso

# Create your root CA (do this once)
kalypso init

# Trust it — auto via mkcert, or manually:
kalypso trust          # uses mkcert if installed (brew install mkcert)
# Or manually:
# macOS:  sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain ~/.kalypso/ca-cert.pem
# Ubuntu: sudo cp ~/.kalypso/ca-cert.pem /usr/local/share/ca-certificates/kalypso.crt && sudo update-ca-certificates

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
| Zero config | Yes | No | Yes |
| SDKs (Python, Ruby, Go, curl) | Yes | No | No |

## How It Works

1. **`kalypso init`** — generates an ECDSA P-256 root CA certificate
2. **`kalypso trust`** — uses [mkcert](https://github.com/FiloSottile/mkcert) to install into system/browser trust stores (or shows manual instructions)
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

- ECDSA P-256 keys (fast, secure, small)
- Root CA is constrained (`pathLength=0`, `keyUsage=keyCertSign`)
- Leaf certs are short-lived (24h default, 7 day max)
- Leaf certs have `extKeyUsage=serverAuth` only
- Each cert gets a unique serial number and key pair
- No wildcard root — you choose exactly which domains to cover

## License

MIT
